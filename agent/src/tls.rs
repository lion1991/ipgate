//! 服务端 TLS 身份：自签证书 + SPKI 指纹（ADR 0003，TOFU）。
//!
//! 固定对象是 **SPKI 的 SHA-256**（而非整张证书），故证书续签、只要密钥不变，
//! 客户端无需重新固定指纹。

use crate::util::{random_bytes, to_hex_colon};
use anyhow::{Context, Result};
use ipgate_proto::SpkiFingerprint;
use rcgen::{generate_simple_self_signed, KeyPair, PublicKeyData};
use sha2::{Digest, Sha256};
use std::path::Path;

/// 服务端身份：证书/私钥 PEM + SPKI 指纹。
#[derive(Clone)]
pub struct ServerIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: SpkiFingerprint,
}

/// 计算 KeyPair 的 SPKI SHA-256 指纹（冒号分隔大写十六进制）。
fn spki_fingerprint(kp: &KeyPair) -> SpkiFingerprint {
    let spki = kp.subject_public_key_info();
    let digest = Sha256::digest(&spki);
    SpkiFingerprint::from(to_hex_colon(&digest))
}

/// 加载已有证书；不存在则生成自签证书并持久化（私钥 0600）。
pub fn load_or_generate(data_dir: &Path) -> Result<ServerIdentity> {
    let cert_path = data_dir.join("cert.pem");
    let key_path = data_dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        let kp = KeyPair::from_pem(&key_pem).context("解析已有私钥失败")?;
        let fingerprint = spki_fingerprint(&kp);
        return Ok(ServerIdentity {
            cert_pem,
            key_pem,
            fingerprint,
        });
    }

    // 用一个随机 SAN，避免多台主机证书完全相同（指纹仍来自密钥）。
    let san = format!("ipgate-{}", crate::util::to_hex(&random_bytes::<6>()));
    let certified = generate_simple_self_signed(vec![san]).context("生成自签证书失败")?;
    let cert_pem = certified.cert.pem();
    let key_pem = certified.signing_key.serialize_pem();
    let fingerprint = spki_fingerprint(&certified.signing_key);

    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("创建数据目录失败: {}", data_dir.display()))?;
    std::fs::write(&cert_path, &cert_pem)?;
    crate::util::write_private(&key_path, key_pem.as_bytes())?;

    Ok(ServerIdentity {
        cert_pem,
        key_pem,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reloads_stable_fingerprint() {
        let dir = std::env::temp_dir().join(format!(
            "ipgate-tls-{}",
            crate::util::to_hex(&random_bytes::<8>())
        ));
        let a = load_or_generate(&dir).unwrap();
        let b = load_or_generate(&dir).unwrap(); // 第二次走加载分支
        assert_eq!(a.fingerprint, b.fingerprint, "重载后指纹应稳定");
        assert!(a.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(a.fingerprint.as_str().contains(':'));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
