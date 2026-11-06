//! 主机公网出口 IP 探测：并发问几家成熟的公网 echo 服务，v4 / v6 各取最先返回的有效结果。
//!
//! 走明文 HTTP/1.0（agent 不带 TLS 栈）：结果只用于展示、不参与放行，被篡改也只影响显示。
//! 按解析出的地址族建连来区分 v4 / v6，三家都有 A + AAAA 记录。

use ipgate_proto::EgressIp;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

const SOURCES: &[(&str, &str)] = &[("icanhazip.com", "/"), ("api64.ipify.org", "/"), ("ifconfig.me", "/ip")];
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 4096;

pub async fn probe() -> EgressIp {
    let (v4, v6) = tokio::join!(probe_family(false), probe_family(true));
    EgressIp {
        ipv4: v4.and_then(|ip| match ip {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        }),
        ipv6: v6.and_then(|ip| match ip {
            IpAddr::V6(a) => Some(a),
            IpAddr::V4(_) => None,
        }),
    }
}

async fn probe_family(v6: bool) -> Option<IpAddr> {
    first_some(SOURCES.iter().map(|&(host, path)| fetch(host, path, v6))).await
}

/// 并发跑完，取最先返回的 `Some`；总时长受 [`TIMEOUT`] 约束。
async fn first_some<F>(futs: impl Iterator<Item = F>) -> Option<IpAddr>
where
    F: Future<Output = Option<IpAddr>> + Send + 'static,
{
    let mut set: JoinSet<Option<IpAddr>> = futs.collect();
    let race = async {
        while let Some(r) = set.join_next().await {
            if let Ok(Some(ip)) = r {
                return Some(ip);
            }
        }
        None
    };
    tokio::time::timeout(TIMEOUT, race).await.ok().flatten()
}

async fn fetch(host: &'static str, path: &'static str, v6: bool) -> Option<IpAddr> {
    let addr: SocketAddr = tokio::net::lookup_host((host, 80))
        .await
        .ok()?
        .find(|a| a.is_ipv6() == v6)?;
    let mut stream = TcpStream::connect(addr).await.ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: ipgate-agent\r\nAccept: text/plain\r\n\r\n");
    stream.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    stream.take(MAX_RESPONSE as u64).read_to_end(&mut buf).await.ok()?;
    let ip = parse_response(&buf)?;
    (ip.is_ipv6() == v6).then_some(ip)
}

/// 只认 200 且正文是一个 IP 的响应。
fn parse_response(raw: &[u8]) -> Option<IpAddr> {
    let text = std::str::from_utf8(raw).ok()?;
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head.lines().next()?;
    if status.split_whitespace().nth(1) != Some("200") {
        return None;
    }
    let ip: IpAddr = body.trim().parse().ok()?;
    let usable = match ip {
        IpAddr::V4(a) => !(a.is_private() || a.is_loopback() || a.is_unspecified() || a.is_link_local()),
        IpAddr::V6(a) => !(a.is_loopback() || a.is_unspecified()),
    };
    usable.then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_ip_body() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n203.0.113.7\n";
        assert_eq!(parse_response(r), Some("203.0.113.7".parse().unwrap()));
        let r = b"HTTP/1.0 200 OK\r\n\r\n2001:db8::5\n";
        assert_eq!(parse_response(r), Some("2001:db8::5".parse().unwrap()));
    }

    #[test]
    fn rejects_non_200_html_and_private() {
        assert_eq!(parse_response(b"HTTP/1.1 301 Moved\r\n\r\n203.0.113.7"), None);
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n<html>203.0.113.7</html>"), None);
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n10.0.0.1"), None);
        assert_eq!(parse_response(b"garbage"), None);
    }

    #[tokio::test]
    async fn first_some_skips_failures() {
        let slow_ok = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Some("203.0.113.9".parse().unwrap())
        };
        let futs: Vec<std::pin::Pin<Box<dyn Future<Output = Option<IpAddr>> + Send>>> =
            vec![Box::pin(async { None }), Box::pin(slow_ok)];
        assert_eq!(first_some(futs.into_iter()).await, Some("203.0.113.9".parse().unwrap()));
    }

    /// 真网络探测，手动跑：`cargo test -p ipgate-agent egress::tests::live -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn live() {
        let r = probe().await;
        println!("{r:?}");
        assert!(r.ipv4.is_some() || r.ipv6.is_some());
    }
}
