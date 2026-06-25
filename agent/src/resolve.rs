//! 转发目标的域名解析（DNAT 需要具体 IPv4）。
//!
//! 用 std 的系统解析器（阻塞，仅在对账线程/管理 API 调用，频率极低）。失败由上层
//! 回退到上次成功解析的 IP（见 `forward.rs`），对齐动态域名「解析挂了也别断转发」的诉求。

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

/// 把 host 解析成首个 IPv4。host 本身是 IPv4 字面量时直接返回（不走 DNS）。
///
/// 返回 `None` 表示解析失败或无 A 记录（IPv6-only 目标 v1 不支持）。
pub fn resolve_ipv4(host: &str) -> Option<Ipv4Addr> {
    let host = host.trim();
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    // 端口 0 仅用于满足 ToSocketAddrs 形态，解析只取地址。
    (host, 0u16)
        .to_socket_addrs()
        .ok()?
        .find_map(|sa| match sa.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_ipv4_passthrough() {
        assert_eq!(resolve_ipv4("203.0.113.7"), Some("203.0.113.7".parse().unwrap()));
        assert_eq!(resolve_ipv4("  10.0.0.1 "), Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn localhost_resolves_to_v4() {
        // localhost 一般解析含 127.0.0.1；CI 上若仅 ::1 则跳过断言（不让测试因环境抖）。
        if let Some(ip) = resolve_ipv4("localhost") {
            assert!(ip.is_loopback());
        }
    }
}
