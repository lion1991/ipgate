//! 业务 handler：纯同步函数，由 `api::dispatch` 按 RPC op 调用（ADR 0007）。
//!
//! 逻辑沿用 0003 版（放行 / 转发 / dnat 适配），只是脱掉了 axum 的 `State`/`Json`/
//! 抽取器外壳——鉴权已由 Noise 握手在连接层完成，这里直接拿 `&AppState` + 已认证
//! 的 `DeviceId`。返回 proto `ApiError`（无 HTTP 状态码）。

use super::error::{internal, ApiResult};
use super::AppState;
use crate::reconcile;
use chrono::Utc;
use ipgate_proto::{
    validate_ports, AddForwardRequest, AgentSettings, AllowRequest, Allowlist, ApiError, Device,
    DeviceId, Diff, Entry, ErrorCode, ForwardCaps, ForwardId, ForwardOrigin, ForwardRule,
    ForwardView, InterfaceInfo, RevokeRequest, UnifiedForwardList, UnifiedForwardView,
    WhoamiResponse,
};
use std::net::IpAddr;

// ---- 放行名单 ----

pub fn list_allowlist(st: &AppState) -> ApiResult<Allowlist> {
    let store = st.store.lock().unwrap();
    Ok(Allowlist {
        entries: store.entries().to_vec(),
        revision: store.revision(),
    })
}

pub fn allow(st: &AppState, by: DeviceId, req: AllowRequest) -> ApiResult<Entry> {
    let now = Utc::now();
    // 存储为期望态权威：先持久化，再落内核（落内核失败也会被对账循环补上）。
    let entry = {
        let mut store = st.store.lock().unwrap();
        let entry = store.allow(req, by, now);
        store.save().map_err(internal)?;
        entry
    };
    st.backend
        .add(&entry)
        .map_err(|e| ApiError::new(ErrorCode::NftFailure, e.to_string()))?;
    Ok(entry)
}

pub fn revoke(st: &AppState, req: RevokeRequest) -> ApiResult<()> {
    let target = {
        let mut store = st.store.lock().unwrap();
        let target = match req {
            RevokeRequest::Target(t) => t,
            RevokeRequest::Id(id) => store
                .find_by_id(id)
                .map(|e| e.target)
                .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "条目不存在"))?,
        };
        if !store.revoke_by_target(&target) {
            return Err(ApiError::new(ErrorCode::NotFound, "条目不存在"));
        }
        store.save().map_err(internal)?;
        target
    };
    st.backend
        .remove(&target)
        .map_err(|e| ApiError::new(ErrorCode::NftFailure, e.to_string()))?;
    Ok(())
}

/// 回报 agent 在本连接上观测到的对端 IP。
///
/// TODO(ADR0007)：SSH 隧道模式下对端恒为 loopback——客户端真实外网 IP 需经 SSH 层
/// 获取（如握手时由客户端经 exec 通道读 `$SSH_CONNECTION`，见 Phase 3）。直连模式下
/// 此值即客户端外部 IP。
pub fn whoami(peer_ip: IpAddr) -> WhoamiResponse {
    WhoamiResponse { ip: peer_ip }
}

pub fn sync(st: &AppState) -> ApiResult<Diff> {
    let now = Utc::now();
    let kernel = st
        .backend
        .list()
        .map_err(|e| ApiError::new(ErrorCode::NftFailure, e.to_string()))?;
    let store = st.store.lock().unwrap();
    Ok(reconcile::diff(store.entries(), &kernel, now))
}

// ---- agent 设置（SSH 端口暴露模式）----

/// 组装 [`AgentSettings`]：运行期 SSH 暴露态 + 静态端口 + best-effort 的 sshd 认证态势。
/// `sshd -T` 探测失败（无 root/无 sshd）时各认证项为 `None`，不影响其余字段。
fn build_settings(st: &AppState, ssh_allowlist_only: bool) -> AgentSettings {
    let auth = crate::sshd::probe();
    AgentSettings {
        ssh_allowlist_only,
        ssh_port: st.cfg.ssh_port,
        ssh_password_auth: auth.password,
        ssh_kbd_interactive_auth: auth.kbd_interactive,
        ssh_permit_root_login: auth.permit_root,
    }
}

pub fn get_settings(st: &AppState) -> AgentSettings {
    let allowlist_only = st.store.lock().unwrap().ssh_allowlist_only();
    build_settings(st, allowlist_only)
}

/// 切换 SSH 端口暴露模式并整表重建 ruleset。
///
/// 开启「仅名单」前的自锁防护：名单为空必然把所有人（含发起方自己）挡在 SSH 外（连管理
/// 隧道也走 SSH），直接拒绝。名单非空时仍可能漏掉发起方的真实出口 IP——那一层由可信客户端
/// 在调用前核对「当前外网 IP ∈ 名单」兜底（agent 经隧道只见 loopback，无法自证）。
pub fn set_ssh_exposure(st: &AppState, allowlist_only: bool) -> ApiResult<AgentSettings> {
    let now = Utc::now();
    let entries = {
        let mut store = st.store.lock().unwrap();
        if allowlist_only {
            let live = store.entries().iter().filter(|e| !e.is_expired(now)).count();
            if live == 0 {
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    "放行名单为空：开启「SSH 仅名单可连」会把所有人（含你自己）挡在外。请先放行你的 IP 再开启。",
                ));
            }
        }
        store.set_ssh_allowlist_only(allowlist_only);
        store.save().map_err(internal)?;
        store.entries().to_vec()
    };
    // SSH 暴露是 input 链结构变更（非 set 元素）：必须整表原子重建。对账循环只增删 set 元素、
    // 不重渲染链，故此变更落地后不会被它 revert（仅 list() 失败时的兜底重建会读 store 同步本值）。
    st.backend
        .apply(&st.cfg.ruleset_with(allowlist_only), &entries)
        .map_err(|e| ApiError::new(ErrorCode::NftFailure, e.to_string()))?;
    Ok(build_settings(st, allowlist_only))
}

/// 开/关系统 sshd 的密码登录（改 sshd_config + reload），返回刷新后的设置。
/// `{e:#}` 带出完整 anyhow 因果链（含底层 io 错误，如 “Operation not permitted”），便于排障。
pub fn set_ssh_password_auth(st: &AppState, enabled: bool) -> ApiResult<AgentSettings> {
    crate::sshd::set_password_auth(enabled)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("{e:#}")))?;
    let allowlist_only = st.store.lock().unwrap().ssh_allowlist_only();
    Ok(build_settings(st, allowlist_only))
}

/// 重置 root 密码。明文经 Noise 隧道送达，此处不落盘、不记日志，直接交 chpasswd。
pub fn reset_root_password(password: String) -> ApiResult<()> {
    if password.chars().count() < 8 {
        return Err(ApiError::new(ErrorCode::BadRequest, "密码至少 8 位"));
    }
    crate::sshd::reset_root_password(&password)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("{e:#}")))?;
    Ok(())
}

// ---- 端口转发（独立 `ip ipgate_nat` 表）----

/// 构造单条转发的客户端视图：附上当前解析 IP 与是否生效。
fn forward_view(store: &crate::store::Store, rule: ForwardRule) -> ForwardView {
    let resolved_ip = store.resolved_ip(rule.id);
    ForwardView {
        rule,
        resolved_ip,
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
pub fn list_forwards(st: &AppState) -> ApiResult<UnifiedForwardList> {
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
    Ok(UnifiedForwardList { forwards, revision })
}

pub fn add_forward(st: &AppState, by: DeviceId, req: AddForwardRequest) -> ApiResult<ForwardView> {
    validate_ports(&req.listen, &req.dest_port)
        .map_err(|e| ApiError::new(ErrorCode::BadRequest, e))?;
    if req.dest_host.trim().is_empty() {
        return Err(ApiError::new(ErrorCode::BadRequest, "目标主机为空"));
    }

    // 碰撞检测（ADR 0006 排空模型）：监听端口被本机 dnat 规则占用则拒，引导先迁移。
    if st.dnat.present() {
        if let Some(eff_iface) = effective_iface(&req.iface) {
            let clash = st
                .dnat
                .rules()
                .into_iter()
                .any(|d| d.iface == eff_iface && req.listen.overlaps(&d.listen));
            if clash {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "监听端口已被本机 dnat 规则占用，请先迁移该 dnat 规则或改用其它端口",
                ));
            }
        }
    }

    let now = Utc::now();
    let rule = {
        let mut store = st.store.lock().unwrap();
        let rule = store.add_forward(req, by, now);
        store.save().map_err(internal)?;
        rule
    };
    let id = rule.id;

    // 立即解析 + 落地（best-effort：解析失败的条目会被跳过、留待周期循环重试）。
    crate::forward::apply_now(&st.store, &st.nat)
        .map_err(|e| ApiError::new(ErrorCode::NftFailure, e.to_string()))?;

    let store = st.store.lock().unwrap();
    Ok(forward_view(&store, rule_by_id(&store, id).unwrap_or(rule)))
}

/// 落地后重新取一遍规则（拿到最新 resolved 状态）。
fn rule_by_id(store: &crate::store::Store, id: ForwardId) -> Option<ForwardRule> {
    store.find_forward(id).cloned()
}

pub fn remove_forward(st: &AppState, id: ForwardId) -> ApiResult<()> {
    {
        let mut store = st.store.lock().unwrap();
        if !store.remove_forward(id) {
            return Err(ApiError::new(ErrorCode::NotFound, "转发规则不存在"));
        }
        store.save().map_err(internal)?;
    }
    crate::forward::apply_now(&st.store, &st.nat)
        .map_err(|e| ApiError::new(ErrorCode::NftFailure, e.to_string()))?;
    Ok(())
}

// ---- dnat 适配（ADR 0006 排空模型）：删除 / 迁移 dnat 规则 ----

/// 解码 dnat key（base64url 的 PrefixKey），并确认本机启用了 dnat 适配。
fn dnat_prefix_from_key(st: &AppState, key: &str) -> Result<String, ApiError> {
    if !st.dnat.present() {
        return Err(ApiError::new(ErrorCode::NotFound, "本机未启用 dnat 适配"));
    }
    crate::dnat::decode_key(key).ok_or_else(|| ApiError::new(ErrorCode::BadRequest, "非法 dnat 键"))
}

/// 删除一条 dnat 规则（改 dnat conf + 触发 `dnat apply`，不动 native）。
pub fn remove_dnat_forward(st: &AppState, key: &str) -> ApiResult<()> {
    let prefix = dnat_prefix_from_key(st, key)?;
    let removed = st
        .dnat
        .remove_prefix(&prefix)
        .map_err(|e| ApiError::new(ErrorCode::NftFailure, e.to_string()))?;
    if !removed {
        return Err(ApiError::new(ErrorCode::NotFound, "dnat 规则不存在"));
    }
    Ok(())
}

/// 迁移一条 dnat 规则到 native（先建 native(-90) 再撤 dnat(-100)，零瞬断，ADR 0006）。
pub fn migrate_dnat_forward(st: &AppState, by: DeviceId, key: &str) -> ApiResult<ForwardView> {
    let prefix = dnat_prefix_from_key(st, key)?;
    let rule = st
        .dnat
        .find_rule_by_prefix(&prefix)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "dnat 规则不存在"))?;
    let req = crate::dnat::dnat_rule_to_add_request(&rule);

    // dnat 允许、但 native 表达不了的映射（如单监听→目标区间）不能迁移。
    validate_ports(&req.listen, &req.dest_port).map_err(|e| {
        ApiError::new(
            ErrorCode::BadRequest,
            format!("该 dnat 规则的端口映射 native 不支持，无法迁移：{e}"),
        )
    })?;

    // 目标 (网卡,端口) 已有 native 转发则拒——否则 store.add_forward 会静默覆盖它。
    {
        let store = st.store.lock().unwrap();
        let clobbers = store.forwards().iter().any(|f| {
            effective_iface(&f.iface).as_deref() == Some(rule.iface.as_str())
                && f.listen.overlaps(&rule.listen)
        });
        if clobbers {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "目标 (网卡,端口) 已有 native 转发，迁移会覆盖它；请先处理后再迁移",
            ));
        }
    }

    // 先建 native(-90)（dnat(-100) 仍先匹配→零抖动）。
    let now = Utc::now();
    let new_rule = {
        let mut store = st.store.lock().unwrap();
        let r = store.add_forward(req, by, now);
        store.save().map_err(internal)?;
        r
    };
    let id = new_rule.id;
    crate::forward::apply_now(&st.store, &st.nat)
        .map_err(|e| ApiError::new(ErrorCode::NftFailure, e.to_string()))?;

    // 确认 native 真生效（解析成功＝已进内核）；否则回滚僵尸规则、保留 dnat。
    let live = st.store.lock().unwrap().resolved_ip(id).is_some();
    if !live {
        {
            let mut store = st.store.lock().unwrap();
            store.remove_forward(id);
            let _ = store.save();
        }
        let _ = crate::forward::apply_now(&st.store, &st.nat);
        return Err(ApiError::new(
            ErrorCode::NftFailure,
            "native 规则未能解析/生效（如目标域名暂时解析失败），已保留原 dnat 规则，请稍后重试迁移",
        ));
    }

    // native 已生效，再撤原 dnat。撤失败不回滚：native 已接管。
    if let Err(e) = st.dnat.remove_prefix(&prefix) {
        return Err(ApiError::new(
            ErrorCode::NftFailure,
            format!("native 已建好并生效，但移除原 dnat 规则失败（dnat 仍在服务，可重试迁移或手动 dnat-rm）：{e}"),
        ));
    }

    let store = st.store.lock().unwrap();
    Ok(forward_view(&store, rule_by_id(&store, id).unwrap_or(new_rule)))
}

// ---- 杂项 ----

/// 列主机网卡（客户端做下拉 + 源 IP 提示）。
pub fn list_interfaces() -> Vec<InterfaceInfo> {
    crate::netinfo::interfaces()
}

pub fn list_devices(st: &AppState) -> Vec<Device> {
    st.store.lock().unwrap().devices().to_vec()
}

pub fn revoke_device(st: &AppState, id: DeviceId) -> ApiResult<()> {
    let mut store = st.store.lock().unwrap();
    if !store.remove_device(id) {
        return Err(ApiError::new(ErrorCode::NotFound, "设备不存在"));
    }
    store.save().map_err(internal)?;
    Ok(())
}
