//! 管理访问密钥（128-bit）：ADR 0007 起它被 `noise::derive_psk` 派生成 Noise 握手的
//! PSK（psk0）——不持此密钥者连合法 msg1 都造不出、本方静默拒绝（端口「变暗」）。
//!
//! 不变量：本地 `ipgate-agent` CLI 直接读写磁盘、SSH(22) 走系统认证，都不经此密钥；
//! 丢了：SSH 进去 `ipgate-agent access-key --reset` 重置，再重新配对各设备。

use crate::util::{random_bytes, to_hex, write_private};
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

fn file(data_dir: &Path) -> PathBuf {
    data_dir.join("access.key")
}

/// 生成一个新访问密钥（128-bit hex）并落盘（0600）。
fn generate(data_dir: &Path) -> Result<String> {
    let key = to_hex(&random_bytes::<16>());
    std::fs::create_dir_all(data_dir)?;
    write_private(&file(data_dir), key.as_bytes())?;
    Ok(key)
}

/// 加载访问密钥；不存在则生成。即便当前没启用门禁也照常生成，
/// 这样 `access-key` 子命令随时可印、用户一开 `require_access_key` 就能用。
pub fn load_or_generate(data_dir: &Path) -> Result<String> {
    let p = file(data_dir);
    if p.exists() {
        let s = std::fs::read_to_string(&p)?.trim().to_string();
        if s.is_empty() {
            return Err(anyhow!("access.key 为空（已损坏）；用 access-key --reset 重置"));
        }
        Ok(s)
    } else {
        generate(data_dir)
    }
}

/// 强制重置访问密钥，返回新值（旧客户端需重新填入新密钥/重配对）。
pub fn reset(data_dir: &Path) -> Result<String> {
    generate(data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{random_bytes, to_hex};

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("ipgate-ak-{}", to_hex(&random_bytes::<8>())))
    }

    #[test]
    fn generate_is_stable_then_reset_changes() {
        let dir = tmp();
        let a = load_or_generate(&dir).unwrap();
        let b = load_or_generate(&dir).unwrap();
        assert_eq!(a, b, "二次加载应拿到同一密钥");
        assert_eq!(a.len(), 32, "128-bit = 32 hex 字符");
        let c = reset(&dir).unwrap();
        assert_ne!(a, c, "reset 应换新");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
