//! nftables ruleset 文本生成（纯函数，可单测）。

use chrono::{DateTime, Utc};
use ipgate_proto::{
    Entry, PortRange, RulesetConfig, NFT_SET_ALLOW4, NFT_SET_ALLOW6, NFT_SET_PUBLIC_TCP,
    NFT_SET_PUBLIC_UDP, NFT_TABLE,
};
use ipnet::IpNet;

/// 必要的 ICMPv6 类型：缺了 IPv6 直接瘫（邻居发现/RA/PMTUD）。
const ICMPV6_TYPES: &str = "nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, \
nd-router-advert, echo-request, echo-reply, destination-unreachable, packet-too-big, \
time-exceeded, parameter-problem";
const ICMP_TYPES: &str =
    "echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem";

/// 返回 `inet ipgate` 这个表的限定名（`inet ipgate`）。
fn table() -> String {
    format!("inet {NFT_TABLE}")
}

/// 选择条目应落入的 set 名（按 v4/v6）。
fn allow_set(net: &IpNet) -> &'static str {
    match net {
        IpNet::V4(_) => NFT_SET_ALLOW4,
        IpNet::V6(_) => NFT_SET_ALLOW6,
    }
}

/// 渲染单个 set 元素 token：`<cidr>` 或 `<cidr> timeout <n>s`。
fn element_token(target: &IpNet, expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    match expires_at {
        Some(t) => {
            let secs = (t - now).num_seconds().max(1);
            format!("{target} timeout {secs}s")
        }
        None => target.to_string(),
    }
}

fn render_ports(ports: &[PortRange]) -> String {
    ports
        .iter()
        .map(|p| {
            if p.start == p.end {
                p.start.to_string()
            } else {
                format!("{}-{}", p.start, p.end)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// 渲染完整的原子事务（喂给 `nft -f -`）：幂等重建 table/set/chain 并载入当前条目。
///
/// 「确保存在 → 删除 → 重建」是 nftables 的标准幂等重置惯用法，整份在一个事务里，
/// 因此 default-drop 与管理端口放行**同时**生效，绝无中间窗口。
pub fn render_apply(cfg: &RulesetConfig, entries: &[Entry], now: DateTime<Utc>) -> String {
    let t = table();
    let mut s = String::new();

    s.push_str(&format!("table {t}\n"));
    s.push_str(&format!("delete table {t}\n"));
    s.push_str(&format!("table {t} {{\n"));
    s.push_str(&format!(
        "    set {NFT_SET_ALLOW4} {{ type ipv4_addr; flags interval, timeout; }}\n"
    ));
    s.push_str(&format!(
        "    set {NFT_SET_ALLOW6} {{ type ipv6_addr; flags interval, timeout; }}\n"
    ));
    s.push_str(&format!(
        "    set {NFT_SET_PUBLIC_TCP} {{ type inet_service; flags interval; }}\n"
    ));
    s.push_str(&format!(
        "    set {NFT_SET_PUBLIC_UDP} {{ type inet_service; flags interval; }}\n"
    ));
    s.push_str("    chain input {\n");
    // 用数字 priority 0（= filter），兼容老版本 nft（命名优先级 0.9+ 才支持）。
    s.push_str("        type filter hook input priority 0; policy drop;\n");
    s.push_str("        ct state established,related accept\n");
    s.push_str("        ct state invalid drop\n");
    s.push_str("        iif lo accept\n");
    s.push_str(&format!(
        "        ip6 nexthdr icmpv6 icmpv6 type {{ {ICMPV6_TYPES} }} accept\n"
    ));
    s.push_str(&format!(
        "        ip protocol icmp icmp type {{ {ICMP_TYPES} }} accept\n"
    ));
    // 管理端口：无条件放行（ADR 0003 不变量），字面规则、不可被 API 移除。
    s.push_str(&format!("        tcp dport {} accept\n", cfg.mgmt_port));
    s.push_str(&format!("        tcp dport @{NFT_SET_PUBLIC_TCP} accept\n"));
    s.push_str(&format!("        udp dport @{NFT_SET_PUBLIC_UDP} accept\n"));
    s.push_str(&format!("        ip saddr @{NFT_SET_ALLOW4} accept\n"));
    s.push_str(&format!("        ip6 saddr @{NFT_SET_ALLOW6} accept\n"));
    s.push_str("    }\n");
    s.push_str("}\n");

    // 在同一事务内载入当前条目（避免 default-drop 下名单短暂为空）。
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for e in entries {
        if e.is_expired(now) {
            continue;
        }
        let tok = element_token(&e.target, e.expires_at, now);
        match e.target {
            IpNet::V4(_) => v4.push(tok),
            IpNet::V6(_) => v6.push(tok),
        }
    }
    if !v4.is_empty() {
        s.push_str(&format!(
            "add element {t} {NFT_SET_ALLOW4} {{ {} }}\n",
            v4.join(", ")
        ));
    }
    if !v6.is_empty() {
        s.push_str(&format!(
            "add element {t} {NFT_SET_ALLOW6} {{ {} }}\n",
            v6.join(", ")
        ));
    }
    let tcp = render_ports(&cfg.public_tcp);
    if !tcp.is_empty() {
        s.push_str(&format!("add element {t} {NFT_SET_PUBLIC_TCP} {{ {tcp} }}\n"));
    }
    let udp = render_ports(&cfg.public_udp);
    if !udp.is_empty() {
        s.push_str(&format!("add element {t} {NFT_SET_PUBLIC_UDP} {{ {udp} }}\n"));
    }
    s
}

/// 增量放行一个条目（单条原子）。
pub fn add_element_script(
    target: &IpNet,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> String {
    format!(
        "add element {} {} {{ {} }}",
        table(),
        allow_set(target),
        element_token(target, expires_at, now)
    )
}

/// 增量撤销一个目标（单条原子）。
pub fn delete_element_script(target: &IpNet) -> String {
    format!(
        "delete element {} {} {{ {target} }}",
        table(),
        allow_set(target)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipgate_proto::{DeviceId, EntryId};

    fn entry(target: &str, expires: Option<DateTime<Utc>>) -> Entry {
        Entry {
            id: EntryId::new(),
            target: target.parse().unwrap(),
            note: String::new(),
            expires_at: expires,
            created_at: Utc::now(),
            created_by: DeviceId::new(),
        }
    }

    #[test]
    fn ruleset_holds_the_invariants() {
        let cfg = RulesetConfig::default(); // mgmt_port = 19186
        let s = render_apply(&cfg, &[], Utc::now());
        // default-drop
        assert!(s.contains("policy drop;"));
        // 管理端口字面放行（不变量）
        assert!(s.contains("tcp dport 19186 accept"));
        // 连接跟踪 / loopback
        assert!(s.contains("ct state established,related accept"));
        assert!(s.contains("iif lo accept"));
        // 必要 ICMPv6（防 IPv6 瘫痪）
        assert!(s.contains("nd-neighbor-solicit"));
        assert!(s.contains("nd-router-advert"));
        // 名单引用
        assert!(s.contains("ip saddr @allow4 accept"));
        assert!(s.contains("ip6 saddr @allow6 accept"));
        // 幂等重置惯用法
        assert!(s.contains("delete table inet ipgate"));
    }

    #[test]
    fn entries_route_to_v4_v6_sets_and_skip_expired() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        let entries = vec![
            entry("203.0.113.0/24", None),
            entry("2001:db8::/32", None),
            entry("198.51.100.9/32", Some(past)), // 已过期 → 不应出现
        ];
        let s = render_apply(&RulesetConfig::default(), &entries, now);
        assert!(s.contains("add element inet ipgate allow4 { 203.0.113.0/24 }"));
        assert!(s.contains("add element inet ipgate allow6 { 2001:db8::/32 }"));
        assert!(!s.contains("198.51.100.9"));
    }

    #[test]
    fn timeout_token_rendered_for_future_expiry() {
        let now = Utc::now();
        let future = now + chrono::Duration::seconds(3600);
        let s = add_element_script(&"192.0.2.5/32".parse().unwrap(), Some(future), now);
        assert!(s.starts_with("add element inet ipgate allow4 { 192.0.2.5/32 timeout "));
        assert!(s.contains("timeout 3600s") || s.contains("timeout 3599s"));
    }

    #[test]
    fn delete_picks_correct_family_set() {
        let s = delete_element_script(&"2001:db8::1/128".parse().unwrap());
        assert_eq!(s, "delete element inet ipgate allow6 { 2001:db8::1/128 }");
    }

    #[test]
    fn public_ports_rendered_as_ranges() {
        let cfg = RulesetConfig {
            mgmt_port: 19186,
            public_tcp: vec![PortRange::single(443), PortRange { start: 8000, end: 8010 }],
            public_udp: vec![],
        };
        let s = render_apply(&cfg, &[], Utc::now());
        assert!(s.contains("add element inet ipgate public_tcp { 443, 8000-8010 }"));
    }
}
