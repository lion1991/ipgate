//! 端口转发 nftables 渲染（独立 `ip ipgate_nat` 表）。纯函数，可单测。
//!
//! 与 `ruleset.rs`（`inet ipgate` 放行名单表）**刻意分离**：两张表互不引用，
//! 转发的 DNAT/SNAT 逻辑就算渲染出错、被 `delete table` 重建，也碰不到
//! `inet ipgate` 里的管理端口放行不变量（ADR 0002/0003）。
//!
//! 优先级用**数字**（-100/100/0）而非 `dstnat`/`srcnat`/`filter` 命名：命名优先级要
//! nft 0.9+，数字在 el7 的 0.8 也认（与 `ruleset.rs` 的兼容口径一致）。

use ipgate_proto::{ForwardProto, PortRange, NFT_NAT_TABLE};
use std::net::Ipv4Addr;

/// 解析后的转发规则：域名/auto 已落实为具体 IP 与网卡，可直接渲染成 nft 规则。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedForward {
    pub proto: ForwardProto,
    pub iface: String,
    pub listen: PortRange,
    pub remote_ip: Ipv4Addr,
    pub dest_port: PortRange,
    pub source_ip: Ipv4Addr,
}

fn table() -> String {
    format!("ip {NFT_NAT_TABLE}")
}

/// 端口段：单端口 `443`，区间 `8000-8010`。
fn port_spec(p: &PortRange) -> String {
    if p.start == p.end {
        p.start.to_string()
    } else {
        format!("{}-{}", p.start, p.end)
    }
}

/// 渲染完整原子事务：幂等重建 `ip ipgate_nat` 表并载入所有转发规则。
///
/// `table; delete table; table {…}` 是 nftables 标准幂等重置惯用法，整份在一个
/// 事务里，因此转发规则整体原子切换、无中间窗口。
pub fn render_nat_apply(forwards: &[ResolvedForward]) -> String {
    let t = table();
    let mut s = String::new();
    s.push_str(&format!("table {t}\n"));
    s.push_str(&format!("delete table {t}\n"));
    s.push_str(&format!("table {t} {{\n"));

    // prerouting：DNAT —— 本机入向包改写目的地址/端口到远端。
    s.push_str("    chain prerouting {\n");
    s.push_str("        type nat hook prerouting priority -100; policy accept;\n");
    for f in forwards {
        for proto in f.proto.l4_protos() {
            s.push_str(&format!(
                "        iifname \"{iface}\" {proto} dport {lport} dnat to {ip}:{dport}\n",
                iface = f.iface,
                lport = port_spec(&f.listen),
                ip = f.remote_ip,
                dport = port_spec(&f.dest_port),
            ));
        }
    }
    s.push_str("    }\n");

    // postrouting：SNAT —— 回程出向包改写源地址为 source_ip，保证回包能找回本机。
    s.push_str("    chain postrouting {\n");
    s.push_str("        type nat hook postrouting priority 100; policy accept;\n");
    for f in forwards {
        for proto in f.proto.l4_protos() {
            s.push_str(&format!(
                "        ip daddr {ip} {proto} dport {dport} snat to {src}\n",
                ip = f.remote_ip,
                dport = port_spec(&f.dest_port),
                src = f.source_ip,
            ));
        }
    }
    s.push_str("    }\n");

    // forward：放行被转发流量。policy accept（多数 VPS 默认即转发可达）；
    // 显式 accept 一是表意，二是日后做「只放名单内源 IP」时的挂点（改 policy drop + saddr 匹配）。
    s.push_str("    chain forward {\n");
    s.push_str("        type filter hook forward priority 0; policy accept;\n");
    s.push_str("        ct state established,related accept\n");
    for f in forwards {
        for proto in f.proto.l4_protos() {
            // DNAT 在 prerouting 已改写目的，故此处按改写后的 remote_ip/dest_port 匹配新建连接。
            s.push_str(&format!(
                "        iifname \"{iface}\" ip daddr {ip} {proto} dport {dport} ct state new accept\n",
                iface = f.iface,
                ip = f.remote_ip,
                dport = port_spec(&f.dest_port),
            ));
        }
    }
    s.push_str("    }\n");

    s.push_str("}\n");
    s
}

/// 渲染「清空转发」：幂等删除整张 `ip ipgate_nat` 表（无转发时用）。
///
/// ensure-then-delete：表不存在时先建空表再删，避免裸 `delete` 报「No such file」。
pub fn render_nat_flush() -> String {
    let t = table();
    format!("table {t}\ndelete table {t}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rf(proto: ForwardProto, listen: PortRange, dport: PortRange) -> ResolvedForward {
        ResolvedForward {
            proto,
            iface: "eth0".into(),
            listen,
            remote_ip: "10.0.0.9".parse().unwrap(),
            dest_port: dport,
            source_ip: "192.168.1.5".parse().unwrap(),
        }
    }

    #[test]
    fn single_port_tcp_renders_all_three_chains() {
        let s = render_nat_apply(&[rf(
            ForwardProto::Tcp,
            PortRange::single(443),
            PortRange::single(8443),
        )]);
        assert!(s.contains("table ip ipgate_nat {"));
        assert!(s.contains("type nat hook prerouting priority -100"));
        assert!(s.contains("type nat hook postrouting priority 100"));
        assert!(s.contains("type filter hook forward priority 0"));
        assert!(s.contains("iifname \"eth0\" tcp dport 443 dnat to 10.0.0.9:8443"));
        assert!(s.contains("ip daddr 10.0.0.9 tcp dport 8443 snat to 192.168.1.5"));
        assert!(s.contains("iifname \"eth0\" ip daddr 10.0.0.9 tcp dport 8443 ct state new accept"));
        // 幂等重置惯用法
        assert!(s.contains("delete table ip ipgate_nat"));
        // 绝不触碰放行名单表
        assert!(!s.contains("inet ipgate"));
    }

    #[test]
    fn both_proto_renders_tcp_and_udp() {
        let s = render_nat_apply(&[rf(
            ForwardProto::Both,
            PortRange::single(53),
            PortRange::single(53),
        )]);
        assert!(s.contains("tcp dport 53 dnat to 10.0.0.9:53"));
        assert!(s.contains("udp dport 53 dnat to 10.0.0.9:53"));
    }

    #[test]
    fn port_range_rendered_with_dash() {
        let s = render_nat_apply(&[rf(
            ForwardProto::Tcp,
            PortRange { start: 8000, end: 8010 },
            PortRange { start: 9000, end: 9010 },
        )]);
        assert!(s.contains("tcp dport 8000-8010 dnat to 10.0.0.9:9000-9010"));
        assert!(s.contains("ip daddr 10.0.0.9 tcp dport 9000-9010 snat to 192.168.1.5"));
    }

    #[test]
    fn range_to_single_dest() {
        let s = render_nat_apply(&[rf(
            ForwardProto::Udp,
            PortRange { start: 7000, end: 7005 },
            PortRange::single(7000),
        )]);
        assert!(s.contains("udp dport 7000-7005 dnat to 10.0.0.9:7000"));
    }

    #[test]
    fn flush_is_idempotent_delete() {
        assert_eq!(render_nat_flush(), "table ip ipgate_nat\ndelete table ip ipgate_nat\n");
    }

    #[test]
    fn empty_forwards_still_valid_table() {
        let s = render_nat_apply(&[]);
        assert!(s.contains("table ip ipgate_nat {"));
        assert!(s.contains("chain prerouting"));
        // 没有具体规则
        assert!(!s.contains("dnat to"));
    }
}
