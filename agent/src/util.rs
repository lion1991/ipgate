//! 小工具：CSPRNG 随机字节、十六进制编码、OpenSSH 私钥种子抽取。

use anyhow::{bail, Context, Result};

/// 用操作系统 CSPRNG 填充 `N` 字节。
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("操作系统 CSPRNG 不可用");
    b
}

/// 小写十六进制。
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 写文件并在 unix 上设 0600（私钥/密钥用）。
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// 从 OpenSSH 格式（未加密）的 ed25519 私钥 PEM 中抽出 32 字节种子。
///
/// 仅支持我们自己用 `ssh-keygen -t ed25519 -N ""` 生成的隧道密钥：cipher/kdf 均为 `none`、
/// 单密钥。配对二维码只带这 32 字节（而非整段 ~400 字符 PEM），客户端再用 `from_seed` 重建
/// 同一把 SSH 私钥（公钥由种子确定性派生，与服务器 authorized_keys 一致）——QR 体积砍掉一大半。
pub fn extract_ed25519_seed(pem: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    // 1) 剥离 PEM 头尾、拼接 base64 主体后解码。
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----") && !l.is_empty())
        .collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .context("隧道密钥 PEM base64 解码失败")?;

    // 2) 顶层结构：magic + cipher/kdf/kdfopts + numkeys + pub blob + priv 区。
    let mut r = SshReader::new(&raw);
    if r.take(15)? != b"openssh-key-v1\0" {
        bail!("非 openssh-key-v1 私钥");
    }
    let cipher = r.string()?;
    let kdf = r.string()?;
    let _kdfopts = r.string()?;
    if cipher != b"none" || kdf != b"none" {
        bail!("隧道密钥被加密（cipher/kdf 非 none），不支持");
    }
    let nkeys = r.u32()?;
    if nkeys != 1 {
        bail!("隧道密钥含 {nkeys} 把密钥（应为 1），不支持");
    }
    let _pub_blob = r.string()?;
    let priv_section = r.string()?;

    // 3) priv 区（cipher=none 故为明文）：双校验字 + keytype + pub32 + priv64(seed||pub)。
    let mut p = SshReader::new(priv_section);
    if p.u32()? != p.u32()? {
        bail!("隧道密钥校验字不匹配（损坏或加密）");
    }
    if p.string()? != b"ssh-ed25519" {
        bail!("隧道密钥非 ssh-ed25519");
    }
    let _pub32 = p.string()?;
    let privfield = p.string()?;
    let seed: [u8; 32] = privfield
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .context("ed25519 私钥字段过短")?;
    Ok(seed)
}

/// 极简 SSH-wire 读取器：大端 `u32` 长度前缀字符串 + 原始字节，全程边界检查。
struct SshReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SshReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).context("SSH 读取越界")?;
        let s = self.buf.get(self.pos..end).context("SSH 读取越界")?;
        self.pos = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips_shape() {
        assert_eq!(to_hex(&[0x0a, 0xff]), "0aff");
    }

    /// 用 `ssh-keygen -t ed25519 -N ""` 生成的真实密钥固定样本，确认手写解析抽出正确种子。
    #[test]
    fn extracts_ed25519_seed_from_openssh_pem() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACBjo8ww/m40UxdxXZLoTer/Apl1YZKPNxyjQYFzL//BqgAAAJDB+5rIwfua\n\
yAAAAAtzc2gtZWQyNTUxOQAAACBjo8ww/m40UxdxXZLoTer/Apl1YZKPNxyjQYFzL//Bqg\n\
AAAECKv8Mg8iyLoqFBfi4EzpTai8No7jodcUv/b7TBMX1eUmOjzDD+bjRTF3FdkuhN6v8C\n\
mXVhko83HKNBgXMv/8GqAAAADWlwZ2F0ZS10dW5uZWw=\n\
-----END OPENSSH PRIVATE KEY-----\n";
        let seed = extract_ed25519_seed(pem).expect("应能解析");
        assert_eq!(
            to_hex(&seed),
            "8abfc320f22c8ba2a1417e2e04ce94da8bc368ee3a1d714bff6fb4c1317d5e52"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(extract_ed25519_seed("not a key").is_err());
    }

    #[test]
    fn random_is_nonzero_and_distinct() {
        let a = random_bytes::<32>();
        let b = random_bytes::<32>();
        assert_ne!(a, b);
        assert!(a.iter().any(|&x| x != 0));
    }
}
