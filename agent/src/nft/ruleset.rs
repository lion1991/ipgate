//! nftables ruleset 文本生成（纯函数，可单测）。

use chrono::{DateTime, Utc};
use ipgate_proto::{
    Entry, PortRange, RulesetConfig, KNOCK_TTL_SECS, NFT_SET_ALLOW4, NFT_SET_ALLOW6,
    NFT_SET_KNOCK4, NFT_SET_KNOCK6, NFT_SET_PUBLIC_TCP, NFT_SET_PUBLIC_UDP, NFT_TABLE,
};
use ipnet::IpNet;

/// 基础设施类 ICMPv6：缺了 IPv6 直接瘫（邻居发现/RA/PMTUD），对**所有来源**无条件放行。
///
/// 刻意**不含 echo-request/echo-reply（ping）**：ping 被视作访问/探测面，只放给名单内
/// 源 IP（见 chain 末尾 `ip6 saddr @allow6 accept`），未放行的 IP 一律 ping 不通。
/// 本机主动外发 ping 的回包走 `ct state established,related`，无需在此放行 echo-reply。
const ICMPV6_INFRA_TYPES: &str = "nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, \
nd-router-advert, destination-unreachable, packet-too-big, \
time-exceeded, parameter-problem";
/// 基础设施类 ICMPv4：PMTUD/错误类，对**所有来源**无条件放行。
///
/// 同样**不含 echo（ping）**——ping 只放给名单内源 IP（`ip saddr @allow4 accept`）。
/// 保留这些错误类是为防 PMTUD 黑洞（路径 MTU 探测失败会让连接神秘卡死）。
const ICMP_INFRA_TYPES: &str =
    "destination-unreachable, time-exceeded, parameter-problem";

/// 敲门日志前缀（ADR 0012 决策 10）：开门、敲错、经敲门放行的 SSH 新连接。
const KNOCK_LOG_OK: &str = "ipgate knock ok: ";
const KNOCK_LOG_BAD: &str = "ipgate knock bad: ";
const KNOCK_LOG_SSH: &str = "ipgate knock ssh: ";
/// 每条敲门日志规则各自的限速，防重放 / 伪造源刷爆内核日志。
const KNOCK_LOG_LIMIT: &str = "limit rate 10/minute burst 10 packets";

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

/// 先排序合并重叠/相邻区间：interval set 内联重叠元素会被 nft 拒（config 与客户端添加的可能重叠）。
fn render_ports(ports: &[PortRange]) -> String {
    let mut sorted = ports.to_vec();
    sorted.sort_by_key(|p| p.start);
    let mut merged: Vec<PortRange> = Vec::new();
    for p in sorted {
        match merged.last_mut() {
            Some(last) if u32::from(p.start) <= u32::from(last.end) + 1 => {
                last.end = last.end.max(p.end)
            }
            _ => merged.push(p),
        }
    }
    merged
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

/// 渲染一个 set 定义；元素**内联**在定义里（`elements = {...}`）。
///
/// 内联而非用单独的 `add element` 语句：老版本 nft（如 el7 的 0.8）不认同一份
/// `-f` 文件里对刚定义的 set 做 `add element`（"Set does not exist"），内联在新旧版本都可用。
fn set_def(name: &str, typ: &str, flags: &str, elements: &str) -> String {
    if elements.is_empty() {
        format!("    set {name} {{ type {typ}; flags {flags}; }}\n")
    } else {
        format!("    set {name} {{ type {typ}; flags {flags}; elements = {{ {elements} }} }}\n")
    }
}

/// 渲染完整的原子事务（喂给 `nft -f <file>`）：幂等重建 table/set/chain 并载入当前条目。
///
/// 「确保存在 → 删除 → 重建」是 nftables 的标准幂等重置惯用法，整份在一个事务里，
/// 因此 default-drop 与管理端口放行**同时**生效，绝无中间窗口。
pub fn render_apply(cfg: &RulesetConfig, entries: &[Entry], now: DateTime<Utc>) -> String {
    let t = table();

    // 先算出各 set 的元素，内联进 set 定义（见 set_def 说明）。
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for e in crate::reconcile::effective(entries, now) {
        let tok = element_token(&e.target, e.expires_at, now);
        match e.target {
            IpNet::V4(_) => v4.push(tok),
            IpNet::V6(_) => v6.push(tok),
        }
    }
    let tcp = render_ports(&cfg.public_tcp);
    let udp = render_ports(&cfg.public_udp);

    let mut s = String::new();
    s.push_str(&format!("table {t}\n"));
    s.push_str(&format!("delete table {t}\n"));
    s.push_str(&format!("table {t} {{\n"));
    s.push_str(&set_def(
        NFT_SET_ALLOW4,
        "ipv4_addr",
        "interval, timeout",
        &v4.join(", "),
    ));
    s.push_str(&set_def(
        NFT_SET_ALLOW6,
        "ipv6_addr",
        "interval, timeout",
        &v6.join(", "),
    ));
    s.push_str(&set_def(NFT_SET_PUBLIC_TCP, "inet_service", "interval", &tcp));
    s.push_str(&set_def(NFT_SET_PUBLIC_UDP, "inet_service", "interval", &udp));
    let knock = cfg.knock();
    if knock.is_some() {
        // 由下方敲门规则在包路径上动态写入（ADR 0012）；整表重建会清空，已建立连接不受影响。
        s.push_str(&set_def(NFT_SET_KNOCK4, "ipv4_addr", "dynamic, timeout", ""));
        s.push_str(&set_def(NFT_SET_KNOCK6, "ipv6_addr", "dynamic, timeout", ""));
    }
    s.push_str("    chain input {\n");
    // 用数字 priority 0（= filter），兼容老版本 nft（命名优先级 0.9+ 才支持）。
    s.push_str("        type filter hook input priority 0; policy drop;\n");
    s.push_str("        ct state established,related accept\n");
    s.push_str("        ct state invalid drop\n");
    s.push_str("        iif lo accept\n");
    // 仅基础设施类 ICMP 对所有来源放行；echo（ping）不在内，故未放行的 IP ping 不通，
    // 名单内源 IP 的 ping 由下方 saddr 规则放行（名单源获全量访问）。
    s.push_str(&format!(
        "        ip6 nexthdr icmpv6 icmpv6 type {{ {ICMPV6_INFRA_TYPES} }} accept\n"
    ));
    s.push_str(&format!(
        "        ip protocol icmp icmp type {{ {ICMP_INFRA_TYPES} }} accept\n"
    ));
    // 敲门（ADR 0012）：载荷前 16 字节等于口令 → 记下源 IP 并丢弃，不回应。只丢口令匹配的包，
    // 派生端口撞上真实 UDP 服务时其余包照常往下走。
    // 日志进内核日志（`journalctl -k -g ipgate`）：只记开门那一包（源 IP 还不在 set 里），
    // 门开着时的补敲与续期不记；限速只挂在无裁决的日志规则上，超限只少记，不影响放行。
    if let Some(k) = knock {
        let m = format!(
            "udp dport {} @th,64,128 0x{}",
            k.port,
            crate::util::to_hex(&k.token)
        );
        s.push_str(&format!(
            "        meta nfproto ipv4 {m} ip saddr != @{NFT_SET_KNOCK4} {KNOCK_LOG_LIMIT} log prefix \"{KNOCK_LOG_OK}\" level info\n"
        ));
        s.push_str(&format!(
            "        meta nfproto ipv4 {m} update @{NFT_SET_KNOCK4} {{ ip saddr timeout {KNOCK_TTL_SECS}s }} drop\n"
        ));
        s.push_str(&format!(
            "        meta nfproto ipv6 {m} ip6 saddr != @{NFT_SET_KNOCK6} {KNOCK_LOG_LIMIT} log prefix \"{KNOCK_LOG_OK}\" level info\n"
        ));
        s.push_str(&format!(
            "        meta nfproto ipv6 {m} update @{NFT_SET_KNOCK6} {{ ip6 saddr timeout {KNOCK_TTL_SECS}s }} drop\n"
        ));
        // 口令对的包上面已丢弃；到这里的 16 字节载荷包按敲错记（多为重置 access key 后没重新配对的设备）。
        s.push_str(&format!(
            "        udp dport {} udp length 24 {KNOCK_LOG_LIMIT} log prefix \"{KNOCK_LOG_BAD}\" level info\n",
            k.port
        ));
    }
    // SSH 管理端口（ADR 0007 唯一入口）。默认无条件放行（自锁不变量，最稳）；开启
    // ssh_allowlist_only 后去掉这条——SSH 改由下方 `ip saddr @allow accept` 命中（名单内源 IP），
    // 以及刚敲过门的源 IP。Noise 服务仅 loopback，命中上面 `iif lo accept`。
    if cfg.ssh_allowlist_only {
        s.push_str(&format!(
            "        # ssh dport {} 仅名单可连（见末尾 saddr 规则）\n",
            cfg.ssh_port
        ));
        if knock.is_some() {
            s.push_str(&format!(
                "        tcp dport {} ip saddr @{NFT_SET_KNOCK4} {KNOCK_LOG_LIMIT} log prefix \"{KNOCK_LOG_SSH}\" level info\n",
                cfg.ssh_port
            ));
            s.push_str(&format!(
                "        tcp dport {} ip6 saddr @{NFT_SET_KNOCK6} {KNOCK_LOG_LIMIT} log prefix \"{KNOCK_LOG_SSH}\" level info\n",
                cfg.ssh_port
            ));
            s.push_str(&format!(
                "        tcp dport {} ip saddr @{NFT_SET_KNOCK4} accept\n",
                cfg.ssh_port
            ));
            s.push_str(&format!(
                "        tcp dport {} ip6 saddr @{NFT_SET_KNOCK6} accept\n",
                cfg.ssh_port
            ));
        }
    } else {
        s.push_str(&format!("        tcp dport {} accept\n", cfg.ssh_port));
    }
    s.push_str(&format!("        tcp dport @{NFT_SET_PUBLIC_TCP} accept\n"));
    s.push_str(&format!("        udp dport @{NFT_SET_PUBLIC_UDP} accept\n"));
    s.push_str(&format!("        ip saddr @{NFT_SET_ALLOW4} accept\n"));
    s.push_str(&format!("        ip6 saddr @{NFT_SET_ALLOW6} accept\n"));
    if cfg.open_all {
        // 放行所有 IP（ADR 0013）：排在名单之后，名单内源照常命中上面的规则（含 SSH）。
        // SSH 不放，仍按上面的「仅名单」/ 全网开放。
        s.push_str("        meta l4proto != tcp accept\n");
        s.push_str(&format!("        tcp dport != {} accept\n", cfg.ssh_port));
    }
    s.push_str("    }\n");
    if cfg.forward_allowlist_only {
        s.push_str(&render_forward_gate(cfg.open_all));
    }
    s.push_str("}\n");
    s
}

/// 转发名单门（ADR 0008）：被任何表 DNAT 过的新建连接（native 转发 / dnat 工具 / Docker `-p`）
/// 只放名单源 IP 与公开端口（按 DNAT 前的原始目的端口），其余丢弃。
///
/// 无参静态模板，不含任何转发条目——渲染风险面与 input 链相同，不破两表隔离（ADR 0005）。
/// policy accept：未被 DNAT 的转发（容器出网、VPN 路由）不受影响。drop 终局，故其它表
/// （Docker、`ip ipgate_nat`、dnat_utils）forward 链里的 accept 救不回被门丢弃的包；
/// priority -10 让门先于它们（filter 0）求值。
fn render_forward_gate(open_all: bool) -> String {
    let dnat_new = "ct state new ct status dnat";
    let mut s = String::from("    chain forward {\n");
    s.push_str("        type filter hook forward priority -10; policy accept;\n");
    s.push_str("        ct state established,related accept\n");
    s.push_str(&format!("        {dnat_new} ip saddr @{NFT_SET_ALLOW4} accept\n"));
    s.push_str(&format!("        {dnat_new} ip6 saddr @{NFT_SET_ALLOW6} accept\n"));
    s.push_str(&format!(
        "        {dnat_new} meta l4proto tcp ct original proto-dst @{NFT_SET_PUBLIC_TCP} accept\n"
    ));
    s.push_str(&format!(
        "        {dnat_new} meta l4proto udp ct original proto-dst @{NFT_SET_PUBLIC_UDP} accept\n"
    ));
    if open_all {
        s.push_str(&format!("        {dnat_new} accept\n"));
    }
    s.push_str(&format!("        {dnat_new} counter drop\n"));
    s.push_str("    }\n");
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
        // SSH 端口字面放行（ADR 0007 自锁不变量）
        assert!(s.contains("tcp dport 22 accept"));
        // 连接跟踪 / loopback
        assert!(s.contains("ct state established,related accept"));
        assert!(s.contains("iif lo accept"));
        // 必要 ICMPv6（防 IPv6 瘫痪）
        assert!(s.contains("nd-neighbor-solicit"));
        assert!(s.contains("nd-router-advert"));
        // PMTUD 错误类保留（防黑洞）
        assert!(s.contains("packet-too-big"));
        assert!(s.contains("destination-unreachable"));
        // ping（echo）绝不无条件放行 —— 未放行的 IP ping 不通（仅名单源 IP 经 saddr 规则可 ping）
        assert!(!s.contains("echo-request"));
        assert!(!s.contains("echo-reply"));
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
        // 元素内联在 set 定义里
        assert!(s.contains("set allow4 { type ipv4_addr; flags interval, timeout; elements = { 203.0.113.0/24 } }"));
        assert!(s.contains("set allow6 { type ipv6_addr; flags interval, timeout; elements = { 2001:db8::/32 } }"));
        assert!(!s.contains("198.51.100.9"));
    }

    #[test]
    fn overlapping_entries_render_outermost_only() {
        // 回归：内联重叠元素会让 nft -f 报 conflicting intervals，整表落地失败、agent 起不来。
        let now = Utc::now();
        let entries = vec![entry("203.0.113.5/32", None), entry("203.0.113.0/24", None)];
        let s = render_apply(&RulesetConfig::default(), &entries, now);
        assert!(s.contains("set allow4 { type ipv4_addr; flags interval, timeout; elements = { 203.0.113.0/24 } }"));
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
            public_tcp: vec![PortRange::single(443), PortRange { start: 8000, end: 8010 }],
            ..RulesetConfig::default()
        };
        let s = render_apply(&cfg, &[], Utc::now());
        assert!(s.contains("set public_tcp { type inet_service; flags interval; elements = { 443, 8000-8010 } }"));
    }

    #[test]
    fn public_ports_overlaps_are_merged() {
        let cfg = RulesetConfig {
            public_tcp: vec![
                PortRange { start: 8005, end: 8020 },
                PortRange::single(443),
                PortRange { start: 8000, end: 8010 },
                PortRange::single(8021),
                PortRange::single(443),
            ],
            ..RulesetConfig::default()
        };
        let s = render_apply(&cfg, &[], Utc::now());
        assert!(s.contains("set public_tcp { type inet_service; flags interval; elements = { 443, 8000-8021 } }"), "{s}");
    }

    #[test]
    fn ssh_allowlist_only_drops_unconditional_accept() {
        // 默认（开放）：有字面 SSH 放行。
        let open = render_apply(&RulesetConfig::default(), &[], Utc::now());
        assert!(open.contains("tcp dport 22 accept"));

        // 仅名单：去掉无条件放行，但 saddr 规则仍在（名单内源 IP 经它连 SSH）。
        let restricted = RulesetConfig {
            ssh_allowlist_only: true,
            ..RulesetConfig::default()
        };
        let s = render_apply(&restricted, &[], Utc::now());
        assert!(!s.contains("tcp dport 22 accept"));
        assert!(s.contains("ip saddr @allow4 accept"));
        assert!(s.contains("ip6 saddr @allow6 accept"));
        // 仍保持 default-drop 与 loopback 不变量。
        assert!(s.contains("policy drop;"));
        assert!(s.contains("iif lo accept"));
    }

    fn knock_cfg(ssh_allowlist_only: bool) -> RulesetConfig {
        RulesetConfig {
            ssh_allowlist_only,
            ssh_knock: Some(ipgate_proto::SshKnock { port: 44707, token: [0xab; 16] }),
            ..RulesetConfig::default()
        }
    }

    #[test]
    fn knock_rendered_only_when_ssh_allowlist_only() {
        let open = render_apply(&knock_cfg(false), &[], Utc::now());
        assert!(!open.contains("knock"), "SSH 对全网开放时不渲染敲门：{open}");
        assert!(open.contains("tcp dport 22 accept"));

        let s = render_apply(&knock_cfg(true), &[], Utc::now());
        let tok = "ab".repeat(16);
        assert!(s.contains("set knock4 { type ipv4_addr; flags dynamic, timeout; }"));
        assert!(s.contains("set knock6 { type ipv6_addr; flags dynamic, timeout; }"));
        let lines: Vec<&str> = s.lines().map(str::trim).collect();
        let at = |l: &str| lines.iter().position(|x| *x == l).unwrap_or_else(|| panic!("缺少 `{l}`：{s}"));
        let k4 = at(&format!("meta nfproto ipv4 udp dport 44707 @th,64,128 0x{tok} update @knock4 {{ ip saddr timeout 60s }} drop"));
        let k6 = at(&format!("meta nfproto ipv6 udp dport 44707 @th,64,128 0x{tok} update @knock6 {{ ip6 saddr timeout 60s }} drop"));
        let s4 = at("tcp dport 22 ip saddr @knock4 accept");
        let s6 = at("tcp dport 22 ip6 saddr @knock6 accept");
        // 敲门规则须在公开 UDP 端口放行之前，否则派生端口撞上公开端口时敲门包被提前 accept。
        let pub_udp = at("udp dport @public_udp accept");
        assert!(k4 < pub_udp && k6 < pub_udp);
        assert!(s4 < pub_udp && s6 < pub_udp);
        // 不再有无条件的 SSH 放行；名单 saddr 规则仍在。
        assert!(!s.contains("tcp dport 22 accept"));
        assert!(s.contains("ip saddr @allow4 accept"));
        // 不回应：没有对错误口令的 reject / 显式 drop 规则，错口令包照常落到 policy drop。
        assert_eq!(s.matches("udp dport 44707").count(), 5);

        // 日志：开门那包先记再入 set；敲错与经敲门的 SSH 新连接各记一条。日志规则都不带裁决。
        let lim = "limit rate 10/minute burst 10 packets";
        let l4 = at(&format!("meta nfproto ipv4 udp dport 44707 @th,64,128 0x{tok} ip saddr != @knock4 {lim} log prefix \"ipgate knock ok: \" level info"));
        let l6 = at(&format!("meta nfproto ipv6 udp dport 44707 @th,64,128 0x{tok} ip6 saddr != @knock6 {lim} log prefix \"ipgate knock ok: \" level info"));
        assert!(l4 < k4 && l6 < k6, "开门日志须在写 set 之前，否则 != 永远不成立");
        let bad = at(&format!("udp dport 44707 udp length 24 {lim} log prefix \"ipgate knock bad: \" level info"));
        assert!(k4 < bad && k6 < bad, "敲错日志须在口令匹配规则之后");
        let ls4 = at(&format!("tcp dport 22 ip saddr @knock4 {lim} log prefix \"ipgate knock ssh: \" level info"));
        let ls6 = at(&format!("tcp dport 22 ip6 saddr @knock6 {lim} log prefix \"ipgate knock ssh: \" level info"));
        assert!(ls4 < s4 && ls6 < s6);
        assert!(lines.iter().filter(|l| l.contains("log prefix")).all(|l| !l.ends_with("accept") && !l.ends_with("drop")));
    }

    #[test]
    fn ssh_allowlist_only_without_knock_params_has_no_knock_rules() {
        // 内核不认敲门时的降级形态：仅名单，无敲门（与 0.2.10 行为一致）。
        let s = render_apply(&RulesetConfig { ssh_allowlist_only: true, ..RulesetConfig::default() }, &[], Utc::now());
        assert!(!s.contains("knock"));
        assert!(!s.contains("tcp dport 22 accept"));
    }

    fn gated() -> RulesetConfig {
        RulesetConfig {
            forward_allowlist_only: true,
            ..RulesetConfig::default()
        }
    }

    #[test]
    fn forward_gate_off_leaves_forward_hook_untouched() {
        // 默认关：不接管 forward hook —— 升级后转发行为与旧版一致。
        let s = render_apply(&RulesetConfig::default(), &[], Utc::now());
        assert!(!s.contains("hook forward"));
    }

    #[test]
    fn forward_gate_drops_dnat_new_conns_not_from_allowlist() {
        let s = render_apply(&gated(), &[], Utc::now());
        let gate = &s[s.find("    chain forward {").expect("应渲染 forward 链")..];
        let lines: Vec<&str> = gate.lines().map(str::trim).collect();
        assert_eq!(
            lines[1..8],
            [
                "type filter hook forward priority -10; policy accept;",
                "ct state established,related accept",
                "ct state new ct status dnat ip saddr @allow4 accept",
                "ct state new ct status dnat ip6 saddr @allow6 accept",
                "ct state new ct status dnat meta l4proto tcp ct original proto-dst @public_tcp accept",
                "ct state new ct status dnat meta l4proto udp ct original proto-dst @public_udp accept",
                "ct state new ct status dnat counter drop",
            ]
        );
    }

    #[test]
    fn forward_gate_keeps_input_chain_byte_identical() {
        // 门只追加 forward 链：input 链（SSH 自锁不变量所在）逐字节不变，与 SSH 开关正交。
        for ssh_allowlist_only in [false, true] {
            let off = RulesetConfig { ssh_allowlist_only, ..RulesetConfig::default() };
            let on = RulesetConfig { ssh_allowlist_only, ..gated() };
            let a = render_apply(&off, &[], Utc::now());
            let b = render_apply(&on, &[], Utc::now());
            let input_end = a.rfind("    }\n").unwrap();
            assert_eq!(a[..input_end], b[..input_end]);
            assert!(b.ends_with("    }\n}\n"));
        }
    }

    #[test]
    fn open_all_off_renders_nothing_extra() {
        let s = render_apply(&gated(), &[], Utc::now());
        assert!(!s.contains("!="));
        assert_eq!(s.matches("ct status dnat accept").count(), 0);
    }

    #[test]
    fn open_all_appends_after_allowlist_and_keeps_ssh() {
        // ADR 0013：除 SSH 外全放；SSH 仍按「仅名单」（名单 / 敲门），排在名单规则之后。
        for ssh_allowlist_only in [false, true] {
            let off = RulesetConfig { ssh_allowlist_only, ssh_port: 2222, ..gated() };
            let on = RulesetConfig { open_all: true, ..off.clone() };
            let a = render_apply(&off, &[], Utc::now());
            let b = render_apply(&on, &[], Utc::now());
            let tail = "        ip6 saddr @allow6 accept\n";
            let (i, j) = (a.find(tail).unwrap() + tail.len(), b.find(tail).unwrap() + tail.len());
            assert_eq!(a[..i], b[..j], "开关之前的 input 链逐字节不变");
            assert!(b[j..].starts_with(
                "        meta l4proto != tcp accept\n        tcp dport != 2222 accept\n    }\n"
            ));
            assert_eq!(b.contains("tcp dport 2222 accept"), !ssh_allowlist_only);
        }
    }

    #[test]
    fn open_all_lets_dnat_through_gate() {
        let s = render_apply(&RulesetConfig { open_all: true, ..gated() }, &[], Utc::now());
        let gate = &s[s.find("    chain forward {").unwrap()..];
        let lines: Vec<&str> = gate.lines().map(str::trim).collect();
        assert_eq!(
            lines[7..9],
            ["ct state new ct status dnat accept", "ct state new ct status dnat counter drop"]
        );
    }
}
