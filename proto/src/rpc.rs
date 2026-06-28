//! Noise 隧道内的应用层 RPC 信封与握手载荷（ADR 0007）。
//!
//! ADR 0007 用 `Noise_IKpsk0` + SSH 载体取代了 0003 的 TLS/REST/Bearer。隧道建立
//! 后，客户端与 agent 不再走 HTTP，而是用下面的 [`RpcRequest`] / [`RpcResponse`]
//! 信封做请求-响应。每个 op 对应原 REST 路由的语义（注释里标了旧路由）。

use crate::{
    AddForwardRequest, AllowRequest, ApiError, DeviceId, ForwardId, PairingCode, RevokeRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Noise 握手套件（ADR 0007）。
///
/// `IKpsk0`：PSK 在 msg1 之前混入链密钥 → 不持 PSK 者连合法 msg1 都造不出，响应方
/// 直接静默拒绝、不回包，达成「隧道内也不可探测」。PSK = agent 的 128-bit access
/// key（不再做 HTTP 门，转生为 Noise PSK）。
pub const NOISE_PATTERN: &str = "Noise_IKpsk0_25519_ChaChaPoly_BLAKE2s";

/// Noise prologue：把协议版本绑进握手哈希，防降级 / 跨协议复用。
pub const NOISE_PROLOGUE: &[u8] = b"ipgate-noise-v1";

/// 单帧最大**明文**长度。Noise 单消息上限 65535（含 16B AEAD tag），留余量。
pub const NOISE_MAX_FRAME: usize = 65_519;

/// 客户端在 Noise 握手首消息（msg1）里携带的载荷（加密）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HandshakeHello {
    /// 仅首次配对携带：用它授权本设备的静态公钥（握手中已传给 agent）。
    /// 已配对设备留空——其静态公钥本就在授权列表里。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<PairingCode>,
    /// 首次配对时的设备显示名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

/// agent 在握手次消息（msg2）里回给客户端的载荷（加密）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeAck {
    /// 本设备的 ID（agent 据静态公钥映射；首次配对时新分配）。
    pub device_id: DeviceId,
    /// 本次握手是否完成了一次新配对（true=刚配对，false=老设备直连）。
    pub paired: bool,
}

/// 隧道内的 RPC 请求——取代 0003 的 REST 路由。
///
/// 邻接标签编码：`{"op":"allow","body":{...}}`；无参 op 形如 `{"op":"sync"}`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", content = "body", rename_all = "snake_case")]
pub enum RpcRequest {
    /// `GET /v1/allowlist`
    ListAllowlist,
    /// `POST /v1/allowlist`
    Allow(AllowRequest),
    /// `DELETE /v1/allowlist`
    Revoke(RevokeRequest),
    /// `GET /v1/whoami`
    Whoami,
    /// `POST /v1/sync`
    Sync,
    /// `GET /v1/forwards`
    ListForwards,
    /// `POST /v1/forwards`
    AddForward(AddForwardRequest),
    /// `DELETE /v1/forwards/{id}`
    RemoveForward(ForwardId),
    /// `DELETE /v1/forwards/dnat/{key}`
    RemoveDnat { key: String },
    /// `POST /v1/forwards/dnat/{key}/migrate`
    MigrateDnat { key: String },
    /// `GET /v1/interfaces`
    ListInterfaces,
    /// `GET /v1/devices`
    ListDevices,
    /// `DELETE /v1/devices/{id}`
    RevokeDevice(DeviceId),
    /// 读取 agent 设置（当前 SSH 暴露模式等）→ [`AgentSettings`]。
    GetSettings,
    /// 切换 SSH 端口暴露：true=仅放行名单，false=对所有人开放。返回 [`AgentSettings`]。
    SetSshExposure { allowlist_only: bool },
}

/// agent 可由客户端查看/调节的运行期设置（ADR 0007）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSettings {
    /// SSH 端口当前是否仅对放行名单开放（见 [`crate::RulesetConfig::ssh_allowlist_only`]）。
    pub ssh_allowlist_only: bool,
    /// 当前 SSH 管理端口（展示用，便于客户端文案标明是「端口 N」）。
    pub ssh_port: u16,
    /// 系统 sshd 是否开着密码登录（best-effort 读 `sshd -T`）。
    /// `None` = agent 探测不到（无 root/无 sshd）或旧版 agent 未上报（`serde(default)`）。
    #[serde(default)]
    pub ssh_password_auth: Option<bool>,
    /// `KbdInteractive`（旧 `ChallengeResponse`）认证是否开着——开着 + PAM 可变相密码登录，
    /// 故与 `ssh_password_auth` 一并构成「密码登录面」。`None` 同上。
    #[serde(default)]
    pub ssh_kbd_interactive_auth: Option<bool>,
    /// `PermitRootLogin` 原值（展示用：yes / no / prohibit-password / forced-commands-only）。`None` 同上。
    #[serde(default)]
    pub ssh_permit_root_login: Option<String>,
}

/// 隧道内的 RPC 响应。成功负载按对应 op 的类型编码（客户端据 op 反序列化）；
/// 无返回值的 op（撤销 / 删除，旧 204）用 `Ok(Value::Null)`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcResponse {
    Ok(Value),
    Err(ApiError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_request_tagged_roundtrip() {
        let r = RpcRequest::RemoveDnat { key: "abc".into() };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""op":"remove_dnat""#), "got {s}");
        let back: RpcRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn rpc_request_unit_variant_is_bare_op() {
        assert_eq!(serde_json::to_string(&RpcRequest::Sync).unwrap(), r#"{"op":"sync"}"#);
    }

    #[test]
    fn rpc_response_err_roundtrip() {
        use crate::ErrorCode;
        let r = RpcResponse::Err(ApiError::new(ErrorCode::NotFound, "x"));
        let s = serde_json::to_string(&r).unwrap();
        let back: RpcResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }
}
