//! 鉴权：配对码 + 管理访问密钥。
//!
//! ADR 0007：Noise_IKpsk0 握手取代了 0003 的令牌 / 登录挑战 / 设备 Ed25519 验签——
//! 握手本身完成双向认证与前向保密。这里只剩两样：
//! - [`pairing`]：一次性配对码（授权新设备的静态公钥）。
//! - [`access`]：管理访问密钥——经 `noise::derive_psk` 变成握手 PSK（psk0）。

pub mod access;
pub mod pairing;

use anyhow::Result;
use std::path::Path;

/// 运行期鉴权状态（ADR 0007 后只剩访问密钥）。
pub struct AuthState {
    /// 管理访问密钥（预共享）；派生 Noise PSK。见 [`access`]。
    pub access_key: String,
}

impl AuthState {
    pub fn load_or_generate(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            access_key: access::load_or_generate(data_dir)?,
        })
    }
}
