//! 配对码：`ipgate-agent pair` 生成、限时、单次；以文件跨进程共享给运行中的 server。
//!
//! 文件里只存配对码的 SHA-256（不存明文）。ADR 0007 起，「持有设备私钥」由 Noise
//! 握手证明（客户端静态公钥随握手送达），这里只管配对码的限时 + 单次消费。

use crate::util::{random_bytes, to_hex, write_private};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use ipgate_proto::PairingCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn code_hash(code: &PairingCode) -> String {
    to_hex(&Sha256::digest(code.as_str().as_bytes()))
}

#[derive(Default, Serialize, Deserialize)]
struct Pending {
    codes: Vec<PendingCode>,
}

#[derive(Serialize, Deserialize)]
struct PendingCode {
    hash: String,
    expires_at: DateTime<Utc>,
}

fn file(data_dir: &Path) -> PathBuf {
    data_dir.join("pairing.json")
}

fn load(data_dir: &Path) -> Result<Pending> {
    let p = file(data_dir);
    if p.exists() {
        Ok(serde_json::from_str(&std::fs::read_to_string(&p)?).context("解析 pairing.json 失败")?)
    } else {
        Ok(Pending::default())
    }
}

fn save(data_dir: &Path, p: &Pending) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let path = file(data_dir);
    let tmp = path.with_extension("json.tmp");
    write_private(&tmp, &serde_json::to_vec_pretty(p)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// 生成一个新的配对码（明文仅此一次返回，用于打印），其哈希入文件。
pub fn create(data_dir: &Path, ttl_secs: u64, now: DateTime<Utc>) -> Result<PairingCode> {
    let code = PairingCode::from(to_hex(&random_bytes::<8>())); // 16 个十六进制字符
    let mut pending = load(data_dir)?;
    pending.codes.retain(|c| c.expires_at > now); // 顺手清过期
    pending.codes.push(PendingCode {
        hash: code_hash(&code),
        expires_at: now + Duration::seconds(ttl_secs as i64),
    });
    save(data_dir, &pending)?;
    Ok(code)
}

/// 校验并消费一个配对码：命中且未过期返回 `true`（单次）。
pub fn consume(data_dir: &Path, code: &PairingCode, now: DateTime<Utc>) -> Result<bool> {
    let mut pending = load(data_dir)?;
    let before = pending.codes.len();
    pending.codes.retain(|c| c.expires_at > now); // 丢弃过期
    let hash = code_hash(code);
    let hit = pending.codes.iter().position(|c| c.hash == hash);
    let ok = if let Some(i) = hit {
        pending.codes.remove(i);
        true
    } else {
        false
    };
    if ok || pending.codes.len() != before {
        save(data_dir, &pending)?;
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("ipgate-pair-{}", to_hex(&random_bytes::<8>())))
    }

    #[test]
    fn create_then_consume_is_single_use() {
        let dir = tmp_dir();
        let now = Utc::now();
        let code = create(&dir, 600, now).unwrap();
        assert!(consume(&dir, &code, now).unwrap());
        assert!(!consume(&dir, &code, now).unwrap()); // 第二次失败
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_and_expired_codes_rejected() {
        let dir = tmp_dir();
        let now = Utc::now();
        let code = create(&dir, 600, now).unwrap();
        assert!(!consume(&dir, &PairingCode::from("deadbeef"), now).unwrap());
        let later = now + Duration::seconds(601);
        assert!(!consume(&dir, &code, later).unwrap()); // 已过期
        let _ = std::fs::remove_dir_all(&dir);
    }
}
