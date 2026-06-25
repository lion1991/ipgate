//! 管理 API 访问密钥（预共享口令）：让管理端口对**无密钥者「变暗」**。
//!
//! 不变量背书（与 ADR 0003 不冲突）：访问密钥是**应用层**前置门，只挡 19186 的 HTTP；
//! 本地 `ipgate-agent` CLI 直接读写磁盘、SSH(22) 受名单管，二者都不经此门 —— 所以它
//! **永远不会**新增一条把人锁到 VNC 的路径。丢了密钥：SSH 进去 `ipgate-agent access-key --reset`。

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

/// 常数时间比较（定长密钥，长度本身非秘密）。挡时序侧信道。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
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

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab")); // 长度不同
        assert!(!ct_eq(b"", b"x"));
    }
}
