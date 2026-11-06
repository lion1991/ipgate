//! 鉴权：配对码 + 管理访问密钥。
//!
//! ADR 0007：Noise_IKpsk0 握手取代了 0003 的令牌 / 登录挑战 / 设备 Ed25519 验签——
//! 握手本身完成双向认证与前向保密。这里只剩两样：
//! - [`pairing`]：一次性配对码（授权新设备的静态公钥）。
//! - [`access`]：管理访问密钥——经 `noise::derive_psk` 变成握手 PSK（psk0）。

pub mod access;
pub mod pairing;

use anyhow::Result;
use ipgate_proto::{SshKnock, KNOCK_PORT_BASE, KNOCK_PORT_SPAN};
use sha2::{Digest, Sha256};
use std::path::Path;

/// 由 access key 派生 SSH 敲门口令与端口（ADR 0012 决策 3）。客户端 core 有同一算法，
/// 两边用同一组测试向量钉住。
pub fn derive_knock(access_key: &str) -> SshKnock {
    let mut h = Sha256::new();
    h.update(b"ipgate-knock-v1");
    h.update(access_key.as_bytes());
    let h = h.finalize();
    let mut token = [0u8; 16];
    token.copy_from_slice(&h[..16]);
    let port = KNOCK_PORT_BASE + u16::from_be_bytes([h[16], h[17]]) % KNOCK_PORT_SPAN;
    SshKnock { port, token }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knock_derivation_matches_shared_vector() {
        // 与客户端 core 的同名测试共用这组向量：改算法两边必须一起改。
        let k = derive_knock("test-access-key");
        assert_eq!(crate::util::to_hex(&k.token), "6569fb0f9d1b8fd78d4a0f07b0123eac");
        assert_eq!(k.port, 44707);
    }
}
