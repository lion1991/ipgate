//! 小工具：CSPRNG 随机字节与十六进制编码。

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

/// 冒号分隔的大写十六进制（指纹展示用）。
pub fn to_hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips_shape() {
        assert_eq!(to_hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(to_hex_colon(&[0x0a, 0xff]), "0A:FF");
    }

    #[test]
    fn random_is_nonzero_and_distinct() {
        let a = random_bytes::<32>();
        let b = random_bytes::<32>();
        assert_ne!(a, b);
        assert!(a.iter().any(|&x| x != 0));
    }
}
