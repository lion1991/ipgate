//! 主机网卡 / 路由 / 转发开关探测（端口转发用）。
//!
//! 经 `ip` 命令读取（不引第三方 crate）：解析稳定的 `-o`（oneline）文本输出，
//! 在 el7 的老 iproute2 上也可用（不依赖 `-j` JSON）。

use anyhow::{Context, Result};
use ipgate_proto::InterfaceInfo;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::process::Command;

/// 默认路由所在网卡（`iface=None` 的转发规则会落到它）。
pub fn default_route_iface() -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // 形如：default via 10.0.0.1 dev eth0 proto dhcp ...
    let mut it = text.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            return it.next().map(|s| s.to_string());
        }
    }
    None
}

/// 枚举所有带 IPv4 的网卡（含其 IPv4 列表与是否默认路由网卡）。
pub fn interfaces() -> Vec<InterfaceInfo> {
    let default = default_route_iface();
    let out = match Command::new("ip").args(["-o", "-4", "addr", "show"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    // 形如：2: eth0    inet 10.0.0.5/24 brd ... scope global eth0 ...
    let mut map: BTreeMap<String, Vec<Ipv4Addr>> = BTreeMap::new();
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 4 {
            continue;
        }
        let ifname = toks[1].to_string();
        if let Some(pos) = toks.iter().position(|&t| t == "inet") {
            if let Some(ipcidr) = toks.get(pos + 1) {
                if let Some(ip) = ipcidr
                    .split('/')
                    .next()
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                {
                    map.entry(ifname).or_default().push(ip);
                }
            }
        }
    }
    map.into_iter()
        .map(|(name, ipv4)| InterfaceInfo {
            is_default_route: default.as_deref() == Some(name.as_str()),
            name,
            ipv4,
        })
        .collect()
}

/// 取某网卡的首个 IPv4（`source=auto` 的 SNAT 源）。
pub fn first_ipv4(iface: &str) -> Option<Ipv4Addr> {
    interfaces()
        .into_iter()
        .find(|i| i.name == iface)
        .and_then(|i| i.ipv4.into_iter().next())
}

/// 某网卡是否持有给定 IPv4（校验显式指定的 source）。
pub fn iface_has_ipv4(iface: &str, ip: Ipv4Addr) -> bool {
    interfaces()
        .into_iter()
        .find(|i| i.name == iface)
        .map(|i| i.ipv4.contains(&ip))
        .unwrap_or(false)
}

/// 开启 IPv4 转发：运行时立即生效 + 写 sysctl.d 持久化（重启后仍在）。
///
/// 运行时写失败才返回错误（转发不开 = DNAT 无效）；持久化失败仅记日志、不致命。
pub fn ensure_ip_forward() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1")
        .context("开启 net.ipv4.ip_forward 失败（需 root）")?;
    // 持久化：best-effort，失败不致命（运行时已生效）。
    let dropin = "/etc/sysctl.d/99-ipgate-forward.conf";
    if let Err(e) = std::fs::write(dropin, b"net.ipv4.ip_forward=1\n") {
        tracing::warn!(error = %e, path = dropin, "写 sysctl 持久化失败（运行时已生效，重启可能丢失）");
    }
    Ok(())
}
