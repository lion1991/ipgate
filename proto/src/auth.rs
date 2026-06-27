//! 鉴权与设备类型（ADR 0003：TOFU + Ed25519 设备密钥 + 配对码 + 会话令牌）。

use crate::crypto::{NoisePublicKey, Nonce, PairingCode, PublicKey, SessionToken, Signature};
use crate::ids::DeviceId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 已授权设备（agent `authorized_keys` 的一员）。
///
/// ADR 0007 起 `pubkey` 是设备的 **Noise 静态公钥（X25519）**——握手即设备鉴权。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub name: String,
    pub pubkey: NoisePublicKey,
    pub created_at: DateTime<Utc>,
    /// 最近一次成功鉴权时间。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
}

/// 配对（入网）请求：携带设备公钥 + 对配对码的签名，证明持有私钥。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequest {
    pub pairing_code: PairingCode,
    pub device_name: String,
    pub device_pubkey: PublicKey,
    /// 用设备私钥对 `pairing_code` 的签名。
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairResponse {
    pub device_id: DeviceId,
}

/// 取登录挑战。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallengeRequest {
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallengeResponse {
    pub nonce: Nonce,
    pub expires_at: DateTime<Utc>,
}

/// 验签换令牌。
///
/// 签名覆盖：`nonce ‖ timestamp ‖ 服务端 SPKI 指纹`，绑定信道以防重放到别处。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerifyRequest {
    pub device_id: DeviceId,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerifyResponse {
    pub token: SessionToken,
    pub expires_at: DateTime<Utc>,
}
