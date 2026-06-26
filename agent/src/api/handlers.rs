//! API handler 与 Bearer 鉴权抽取器。

use super::error::{internal, ApiResult, AppError};
use super::AppState;
use crate::auth::{challenge, keys, pairing, token};
use crate::reconcile;
use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::Json;
use chrono::{Duration, Utc};
use ipgate_proto::{
    validate_ports, AddForwardRequest, AllowRequest, Allowlist, AuthChallengeRequest,
    AuthChallengeResponse, AuthVerifyRequest, AuthVerifyResponse, Device, DeviceId, Diff, Entry,
    ErrorCode, ForwardCaps, ForwardId, ForwardOrigin, ForwardRule, ForwardView, InterfaceInfo,
    PairRequest, PairResponse, RevokeRequest, SessionToken, UnifiedForwardList, UnifiedForwardView,
    WhoamiResponse, SESSION_TOKEN_TTL_SECS,
};
use std::net::SocketAddr;

/// 已鉴权设备：从 `Authorization: Bearer <token>` 验出。
pub struct AuthDevice(pub DeviceId);

impl FromRequestParts<AppState> for AuthDevice {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::new(ErrorCode::Unauthorized, "缺少 Authorization"))?;
        let raw = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::new(ErrorCode::Unauthorized, "需要 Bearer 令牌"))?;
        let device = token::verify(
            &SessionToken::from(raw),
            Utc::now(),
            &state.auth.token_secret,
        )
        .ok_or_else(|| AppError::new(ErrorCode::Unauthorized, "令牌无效或过期"))?;
        Ok(AuthDevice(device))
    }
}

pub async fn healthz() -> &'static str {
    "ok"
}

// ---- 预鉴权 ----

pub async fn pair(
    State(st): State<AppState>,
    Json(req): Json<PairRequest>,
) -> ApiResult<Json<PairResponse>> {
    let now = Utc::now();
    // 先验签（对配对码的签名 → 证明持有私钥），再消费配对码。
    if !keys::verify(
        &req.device_pubkey,
        &pairing::pair_message(&req.pairing_code),
        &req.signature,
    ) {
        return Err(AppError::new(ErrorCode::PairingInvalid, "签名无效"));
    }
    if !pairing::consume(&st.cfg.data_dir, &req.pairing_code, now).map_err(internal)? {
        return Err(AppError::new(ErrorCode::PairingInvalid, "配对码无效/过期/已用"));
    }

    let device = Device {
        id: DeviceId::new(),
        name: req.device_name,
        pubkey: req.device_pubkey,
        created_at: now,
        last_seen: None,
    };
    let device_id = device.id;
    {
        let mut store = st.store.lock().unwrap();
        store.add_device(device);
        store.save().map_err(internal)?;
    }
    Ok(Json(PairResponse { device_id }))
}

pub async fn auth_challenge(
    State(st): State<AppState>,
    Json(req): Json<AuthChallengeRequest>,
) -> ApiResult<Json<AuthChallengeResponse>> {
    if st.store.lock().unwrap().get_device(req.device_id).is_none() {
        return Err(AppError::new(ErrorCode::DeviceUnknown, "设备未授权"));
    }
    let (nonce, expires_at) = st.auth.challenges.issue(req.device_id, Utc::now());
    Ok(Json(AuthChallengeResponse { nonce, expires_at }))
}

pub async fn auth_verify(
    State(st): State<AppState>,
    Json(req): Json<AuthVerifyRequest>,
) -> ApiResult<Json<AuthVerifyResponse>> {
    let now = Utc::now();
    let pubkey = st
        .store
        .lock()
        .unwrap()
        .get_device(req.device_id)
        .map(|d| d.pubkey.clone())
        .ok_or_else(|| AppError::new(ErrorCode::DeviceUnknown, "设备未授权"))?;

    let nonce = st
        .auth
        .challenges
        .take_valid(req.device_id, now)
        .ok_or_else(|| AppError::new(ErrorCode::ChallengeInvalid, "挑战不存在或已过期"))?;

    let message = challenge::auth_message(&nonce, &st.fingerprint);
    if !keys::verify(&pubkey, &message, &req.signature) {
        return Err(AppError::new(ErrorCode::ChallengeInvalid, "签名不符"));
    }

    let expires_at = now + Duration::seconds(SESSION_TOKEN_TTL_SECS as i64);
    let tok = token::issue(req.device_id, expires_at, &st.auth.token_secret);
    {
        let mut store = st.store.lock().unwrap();
        store.touch_device(req.device_id, now);
        let _ = store.save();
    }
    Ok(Json(AuthVerifyResponse {
        token: tok,
        expires_at,
    }))
}

// ---- 需鉴权 ----

pub async fn list_allowlist(
    State(st): State<AppState>,
    _auth: AuthDevice,
) -> ApiResult<Json<Allowlist>> {
    let store = st.store.lock().unwrap();
    Ok(Json(Allowlist {
        entries: store.entries().to_vec(),
        revision: store.revision(),
    }))
}

pub async fn allow(
    State(st): State<AppState>,
    auth: AuthDevice,
    Json(req): Json<AllowRequest>,
) -> ApiResult<Json<Entry>> {
    let now = Utc::now();
    // 存储为期望态权威：先持久化，再落内核（落内核失败也会被对账循环补上）。
    let entry = {
        let mut store = st.store.lock().unwrap();
        let entry = store.allow(req, auth.0, now);
        store.save().map_err(internal)?;
        entry
    };
    st.backend
        .add(&entry)
        .map_err(|e| AppError::new(ErrorCode::NftFailure, e.to_string()))?;
    Ok(Json(entry))
}

pub async fn revoke(
    State(st): State<AppState>,
    _auth: AuthDevice,
    Json(req): Json<RevokeRequest>,
) -> ApiResult<StatusCode> {
    let target = {
        let mut store = st.store.lock().unwrap();
        let target = match req {
            RevokeRequest::Target(t) => t,
            RevokeRequest::Id(id) => store
                .find_by_id(id)
                .map(|e| e.target)
                .ok_or_else(|| AppError::new(ErrorCode::NotFound, "条目不存在"))?,
        };
        if !store.revoke_by_target(&target) {
            return Err(AppError::new(ErrorCode::NotFound, "条目不存在"));
        }
        store.save().map_err(internal)?;
        target
    };
    st.backend
        .remove(&target)
        .map_err(|e| AppError::new(ErrorCode::NftFailure, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// 回报 agent 在本条 TLS 连接上观测到的客户端来源 IP（即 nftables 会匹配的地址）。
/// agent 直接 bind_rustls 监听、无反代，对端地址即客户端外部 IP。
pub async fn whoami(
    _auth: AuthDevice,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> ApiResult<Json<WhoamiResponse>> {
    Ok(Json(WhoamiResponse { ip: peer.ip() }))
}

pub async fn sync(State(st): State<AppState>, _auth: AuthDevice) -> ApiResult<Json<Diff>> {
    let now = Utc::now();
    let kernel = st
        .backend
        .list()
        .map_err(|e| AppError::new(ErrorCode::NftFailure, e.to_string()))?;
    let store = st.store.lock().unwrap();
    Ok(Json(reconcile::diff(store.entries(), &kernel, now)))
}

// ---- 端口转发（独立 `ip ipgate_nat` 表）----

/// 构造单条转发的客户端视图：附上当前解析 IP 与是否生效。
fn forward_view(store: &crate::store::Store, rule: ipgate_proto::ForwardRule) -> ForwardView {
    let resolved_ip = store.resolved_ip(rule.id);
    ForwardView {
        rule,
        resolved_ip,
        // 有解析到 IP 即视作已落地（apply 失败不回写缓存，故缓存有值=上次落地成功含本条）。
        active: resolved_ip.is_some(),
    }
}

/// 规则的有效网卡：显式 `iface`，否则默认路由网卡（与 native 落地口径一致）。
fn effective_iface(iface: &Option<String>) -> Option<String> {
    iface.clone().or_else(crate::netinfo::default_route_iface)
}

/// native 规则 → 统一视图（origin=ipgate，全增删改）。
fn native_unified(store: &crate::store::Store, rule: ForwardRule) -> UnifiedForwardView {
    let resolved_ip = store.resolved_ip(rule.id);
    UnifiedForwardView {
        origin: ForwardOrigin::Ipgate,
        proto: rule.proto,
        listen: rule.listen,
        dest_port: rule.dest_port,
        source: rule.source,
        resolved_ip,
        active: resolved_ip.is_some(),
        caps: ForwardCaps { can_edit: true, can_delete: true, can_migrate: false },
        conflict: false,
        id: Some(rule.id),
        dnat_key: None,
        iface: rule.iface,
        dest_host: rule.dest_host,
        note: rule.note,
    }
}

/// 统一转发列表：native（`ip ipgate_nat`）+ dnat（`dnat_utils`，启用时），跨来源标冲突。
pub async fn list_forwards(
    State(st): State<AppState>,
    _auth: AuthDevice,
) -> ApiResult<Json<UnifiedForwardList>> {
    let (mut forwards, revision) = {
        let store = st.store.lock().unwrap();
        let native: Vec<UnifiedForwardView> = store
            .forwards()
            .iter()
            .cloned()
            .map(|r| native_unified(&store, r))
            .collect();
        (native, store.forward_revision())
    };

    let mut dnat_views: Vec<UnifiedForwardView> =
        if st.dnat.present() { st.dnat.list() } else { Vec::new() };

    // 跨来源回填 conflict：同（有效网卡, 端口区间重叠）即过渡期碰撞。
    if !dnat_views.is_empty() {
        let default_iface = crate::netinfo::default_route_iface();
        let eff = |v: &UnifiedForwardView| v.iface.clone().or_else(|| default_iface.clone());
        for n in forwards.iter_mut() {
            let (ni, nl) = (eff(n), n.listen);
            // ni.is_some() 守卫：网卡无法确定时不臆断为冲突（评审 None 比较坑）。
            if ni.is_some()
                && dnat_views
                    .iter()
                    .any(|d| eff(d) == ni && nl.overlaps(&d.listen))
            {
                n.conflict = true;
            }
        }
        for d in dnat_views.iter_mut() {
            let (di, dl) = (eff(d), d.listen);
            if di.is_some()
                && forwards
                    .iter()
                    .any(|n| eff(n) == di && dl.overlaps(&n.listen))
            {
                d.conflict = true;
            }
        }
    }

    forwards.append(&mut dnat_views);
    Ok(Json(UnifiedForwardList { forwards, revision }))
}

pub async fn add_forward(
    State(st): State<AppState>,
    auth: AuthDevice,
    Json(req): Json<AddForwardRequest>,
) -> ApiResult<Json<ForwardView>> {
    validate_ports(&req.listen, &req.dest_port)
        .map_err(|e| AppError::new(ErrorCode::BadRequest, e))?;
    if req.dest_host.trim().is_empty() {
        return Err(AppError::new(ErrorCode::BadRequest, "目标主机为空"));
    }

    // 碰撞检测（ADR 0006 排空模型）：监听端口被本机 dnat 规则占用则拒，引导先迁移。
    // eff_iface 为 None（无显式 iface 且默认路由不可知）时跳过——此种规则落地期
    // resolve 本就会失败被跳过，不会进内核，无真实碰撞（评审 None 比较坑）。
    if st.dnat.present() {
        if let Some(eff_iface) = effective_iface(&req.iface) {
            let clash = st.dnat.rules().into_iter().any(|d| {
                d.iface == eff_iface && req.listen.overlaps(&d.listen)
            });
            if clash {
                return Err(AppError::new(
                    ErrorCode::Conflict,
                    "监听端口已被本机 dnat 规则占用，请先迁移该 dnat 规则或改用其它端口",
                ));
            }
        }
    }

    let now = Utc::now();
    let rule = {
        let mut store = st.store.lock().unwrap();
        let rule = store.add_forward(req, auth.0, now);
        store.save().map_err(internal)?;
        rule
    };
    let id = rule.id;

    // 立即解析 + 落地（best-effort：解析失败的条目会被跳过、留待周期循环重试）。
    // 落地真失败（nft 报错）才回报 NftFailure——但规则已持久化，对账/重解析会补。
    crate::forward::apply_now(&st.store, &st.nat)
        .map_err(|e| AppError::new(ErrorCode::NftFailure, e.to_string()))?;

    let store = st.store.lock().unwrap();
    Ok(Json(forward_view(&store, rule_by_id(&store, id).unwrap_or(rule))))
}

/// 落地后重新取一遍规则（拿到最新 resolved 状态）。
fn rule_by_id(store: &crate::store::Store, id: ForwardId) -> Option<ipgate_proto::ForwardRule> {
    store.find_forward(id).cloned()
}

pub async fn remove_forward(
    State(st): State<AppState>,
    _auth: AuthDevice,
    Path(id): Path<ForwardId>,
) -> ApiResult<StatusCode> {
    {
        let mut store = st.store.lock().unwrap();
        if !store.remove_forward(id) {
            return Err(AppError::new(ErrorCode::NotFound, "转发规则不存在"));
        }
        store.save().map_err(internal)?;
    }
    crate::forward::apply_now(&st.store, &st.nat)
        .map_err(|e| AppError::new(ErrorCode::NftFailure, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- dnat 适配（ADR 0006 排空模型）：删除 / 迁移 dnat 规则 ----

/// 解码 dnat key（base64url 的 PrefixKey），并确认本机启用了 dnat 适配。
fn dnat_prefix_from_key(st: &AppState, key: &str) -> Result<String, AppError> {
    if !st.dnat.present() {
        return Err(AppError::new(ErrorCode::NotFound, "本机未启用 dnat 适配"));
    }
    crate::dnat::decode_key(key).ok_or_else(|| AppError::new(ErrorCode::BadRequest, "非法 dnat 键"))
}

/// 删除一条 dnat 规则（改 dnat conf + 触发 `dnat apply`，不动 native）。
pub async fn remove_dnat_forward(
    State(st): State<AppState>,
    _auth: AuthDevice,
    Path(key): Path<String>,
) -> ApiResult<StatusCode> {
    let prefix = dnat_prefix_from_key(&st, &key)?;
    let removed = st
        .dnat
        .remove_prefix(&prefix)
        .map_err(|e| AppError::new(ErrorCode::NftFailure, e.to_string()))?;
    if !removed {
        return Err(AppError::new(ErrorCode::NotFound, "dnat 规则不存在"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// 迁移一条 dnat 规则到 native（`ip ipgate_nat`）。
///
/// 顺序（ADR 0006 零瞬断）：先建 native(`-90`)（此刻 dnat(`-100`) 仍先匹配→零抖动）→
/// native 生效后再撤 dnat（包落到 native，无瞬断）。撤 dnat 失败不回滚：native 已接管。
pub async fn migrate_dnat_forward(
    State(st): State<AppState>,
    auth: AuthDevice,
    Path(key): Path<String>,
) -> ApiResult<Json<ForwardView>> {
    let prefix = dnat_prefix_from_key(&st, &key)?;
    let rule = st
        .dnat
        .find_rule_by_prefix(&prefix)
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "dnat 规则不存在"))?;
    let req = crate::dnat::dnat_rule_to_add_request(&rule);

    // dnat 允许、但 native 表达不了的映射（如单监听→目标区间）不能迁移（评审）。
    validate_ports(&req.listen, &req.dest_port).map_err(|e| {
        AppError::new(
            ErrorCode::BadRequest,
            format!("该 dnat 规则的端口映射 native 不支持，无法迁移：{e}"),
        )
    })?;

    // 目标 (网卡,端口) 已有 native 转发则拒——否则 store.add_forward 会按 (iface,listen)
    // 静默覆盖掉那条无关 native 规则（评审）。dnat 规则的 iface 必为具体名。
    {
        let store = st.store.lock().unwrap();
        let clobbers = store.forwards().iter().any(|f| {
            effective_iface(&f.iface).as_deref() == Some(rule.iface.as_str())
                && f.listen.overlaps(&rule.listen)
        });
        if clobbers {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "目标 (网卡,端口) 已有 native 转发，迁移会覆盖它；请先处理后再迁移",
            ));
        }
    }

    // 顺序（ADR 0006 零瞬断）：先建 native(-90)（dnat(-100) 仍先匹配→零抖动）。
    let now = Utc::now();
    let new_rule = {
        let mut store = st.store.lock().unwrap();
        let r = store.add_forward(req, auth.0, now);
        store.save().map_err(internal)?;
        r
    };
    let id = new_rule.id;
    crate::forward::apply_now(&st.store, &st.nat)
        .map_err(|e| AppError::new(ErrorCode::NftFailure, e.to_string()))?;

    // 确认 native 真生效（解析成功＝已进内核）。apply_now 对解析失败的条目只是跳过、仍返回
    // Ok，所以必须显式核对，否则会在 native 没生效时就撤 dnat → 转发全黑（违反零瞬断，评审）。
    let live = st.store.lock().unwrap().resolved_ip(id).is_some();
    if !live {
        // native 没生效：回滚这条僵尸规则，**保留 dnat**，让调用方稍后重试。
        {
            let mut store = st.store.lock().unwrap();
            store.remove_forward(id);
            let _ = store.save();
        }
        let _ = crate::forward::apply_now(&st.store, &st.nat);
        return Err(AppError::new(
            ErrorCode::NftFailure,
            "native 规则未能解析/生效（如目标域名暂时解析失败），已保留原 dnat 规则，请稍后重试迁移",
        ));
    }

    // native 已生效，再撤原 dnat。撤失败不回滚：native（-90）已就绪，dnat（-100）仍在则继续
    // 服务同一目标，无中断；重试迁移幂等（add_forward 去重 + remove 再试）。
    if let Err(e) = st.dnat.remove_prefix(&prefix) {
        return Err(AppError::new(
            ErrorCode::NftFailure,
            format!("native 已建好并生效，但移除原 dnat 规则失败（dnat 仍在服务，可重试迁移或手动 dnat-rm）：{e}"),
        ));
    }

    let store = st.store.lock().unwrap();
    Ok(Json(forward_view(
        &store,
        rule_by_id(&store, id).unwrap_or(new_rule),
    )))
}

/// 列主机网卡（客户端做下拉 + 源 IP 提示）。
pub async fn list_interfaces(_auth: AuthDevice) -> ApiResult<Json<Vec<InterfaceInfo>>> {
    Ok(Json(crate::netinfo::interfaces()))
}

pub async fn list_devices(
    State(st): State<AppState>,
    _auth: AuthDevice,
) -> ApiResult<Json<Vec<Device>>> {
    let store = st.store.lock().unwrap();
    Ok(Json(store.devices().to_vec()))
}

pub async fn revoke_device(
    State(st): State<AppState>,
    _auth: AuthDevice,
    Path(id): Path<DeviceId>,
) -> ApiResult<StatusCode> {
    let mut store = st.store.lock().unwrap();
    if !store.remove_device(id) {
        return Err(AppError::new(ErrorCode::NotFound, "设备不存在"));
    }
    store.save().map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}
