//! 鉴权：设备密钥验签、会话令牌、登录挑战、配对码（ADR 0003）。

pub mod challenge;
pub mod keys;
pub mod pairing;
pub mod token;

use crate::util::{random_bytes, write_private};
use anyhow::{anyhow, Result};
use challenge::ChallengeStore;
use std::path::Path;

/// 运行期鉴权状态：令牌 HMAC 密钥（持久化）+ 内存挑战表。
pub struct AuthState {
    pub token_secret: [u8; 32],
    pub challenges: ChallengeStore,
}

impl AuthState {
    /// 加载令牌密钥；不存在则生成并持久化（0600）。
    pub fn load_or_generate(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("secret.bin");
        let token_secret: [u8; 32] = if path.exists() {
            std::fs::read(&path)?
                .try_into()
                .map_err(|_| anyhow!("secret.bin 长度异常"))?
        } else {
            let secret = random_bytes::<32>();
            std::fs::create_dir_all(data_dir)?;
            write_private(&path, &secret)?;
            secret
        };
        Ok(Self {
            token_secret,
            challenges: ChallengeStore::new(),
        })
    }
}
