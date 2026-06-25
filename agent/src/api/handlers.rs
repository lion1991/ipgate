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
    ErrorCode, ForwardId, ForwardList, ForwardView, InterfaceInfo, PairRequest, PairResponse,
    RevokeRequest, SessionToken, WhoamiResponse, SESSION_TOKEN_TTL_SECS,
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

pub async fn list_forwards(
    State(st): State<AppState>,
    _auth: AuthDevice,
) -> ApiResult<Json<ForwardList>> {
    let store = st.store.lock().unwrap();
    let forwards = store
        .forwards()
        .iter()
        .cloned()
        .map(|r| forward_view(&store, r))
        .collect();
    Ok(Json(ForwardList {
        forwards,
        revision: store.forward_revision(),
    }))
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
