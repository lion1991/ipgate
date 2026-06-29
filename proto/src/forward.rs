//! 端口转发（DNAT/SNAT）规则类型。
//!
//! 落地见 agent `nft::nat`：写入**独立**的 `ip ipgate_nat` 表，与放行名单的
//! `inet ipgate` 表完全隔离——转发逻辑出错也碰不到管理端口的 bootstrap 不变量。
//! v1 仅 IPv4。语义对齐经典的 `本地端口>网卡>目标:目标端口>源`：本机 `listen`
//! 收到的包 DNAT 到 `dest_host:dest_port`，回程按 `source` 做 SNAT。

use crate::ids::{DeviceId, ForwardId};
use crate::ruleset::PortRange;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// 转发协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardProto {
    Tcp,
    Udp,
    /// TCP+UDP 同时转发（渲染成两条规则）。
    Both,
}

impl ForwardProto {
    /// 展开成内核 l4 协议名（渲染 nft 规则用）。
    pub fn l4_protos(self) -> &'static [&'static str] {
        match self {
            ForwardProto::Tcp => &["tcp"],
            ForwardProto::Udp => &["udp"],
            ForwardProto::Both => &["tcp", "udp"],
        }
    }
}

/// 回程 SNAT 源地址策略。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "ip")]
pub enum ForwardSource {
    /// 自动取出口网卡的首个 IPv4（IP 漂移时跟随）。
    #[default]
    Auto,
    /// 指定源 IPv4。
    Ip(Ipv4Addr),
}

/// 一条端口转发规则（期望态，存 ipgate 存储）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRule {
    pub id: ForwardId,
    pub proto: ForwardProto,
    /// 入口网卡；`None` = agent 自动选默认路由网卡。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    /// 本地监听端口/区间。
    pub listen: PortRange,
    /// 目标主机：IPv4 字面量或域名（域名由 agent 周期解析）。
    pub dest_host: String,
    /// 目标端口/区间。单端口时映射整个 `listen` 段；区间时须与 `listen` 等长。
    pub dest_port: PortRange,
    /// 回程 SNAT 源。
    #[serde(default)]
    pub source: ForwardSource,
    #[serde(default)]
    pub note: String,
    pub created_at: DateTime<Utc>,
    pub created_by: DeviceId,
}

impl ForwardRule {
    /// 校验端口区间与目标合法性（不校验网卡是否存在，那是 agent 落地时的事）。
    pub fn validate(&self) -> Result<(), String> {
        validate_ports(&self.listen, &self.dest_port)?;
        if self.dest_host.trim().is_empty() {
            return Err("目标主机为空".into());
        }
        Ok(())
    }

    /// `dest_host` 是否为 IPv4 字面量（否则视作域名，需解析）。
    pub fn dest_is_literal_ip(&self) -> Option<Ipv4Addr> {
        self.dest_host.trim().parse::<Ipv4Addr>().ok()
    }
}

/// 合法网卡名：非空、≤15 字符（Linux `IFNAMSIZ`-1）、仅 `[A-Za-z0-9._-]`。
///
/// 安全用途：`iface` 会被原样插进 `nft -f` 文本脚本的 `iifname "{iface}"`（agent
/// `nft::nat`，ADR 0005）。若不限制字符集，含 `"`/换行/`;`/`{` 的值可闭合字符串、
/// 追加任意 nftables 语句（如 `flush table inet ipgate`，冲掉放行不变量）。本白名单
/// 不含任何这类元字符，从源头堵死注入。点号保留是为 VLAN 子接口（如 `eth0.100`）。
pub fn valid_iface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// 已知**不在** 169.254/16 链路本地段内的云元数据端点：阿里云 ECS 的元数据服务在
/// `100.100.100.200`（明文 HTTP，可取 RAM/STS 临时凭证；`100.100.100.136` 为同族端点），
/// 它们落在 `100.64/10` CGNAT 段内。该段整体须放行（Tailscale 等合法远端也用 100.64/10），
/// 故按**精确 IP** 拦这两个端点，而非拦整段。其余主流云（AWS/GCP/Azure/腾讯/华为）的元
/// 数据走 `169.254.169.254`，已由链路本地分支覆盖。
const CLOUD_METADATA_IPS: [Ipv4Addr; 2] = [
    Ipv4Addr::new(100, 100, 100, 200),
    Ipv4Addr::new(100, 100, 100, 136),
];

/// 转发目标 IPv4 是否落在「绝不允许 DNAT 过去」的禁区；`Some(原因)` 即拒绝。
///
/// 安全用途（ADR 0007 的「零开放端口 / 仅 loopback」不变量）：
/// - **云元数据端点**：`169.254.169.254`（链路本地分支）与阿里云 `100.100.100.200`
///   （[`CLOUD_METADATA_IPS`]）——重新发布到公网即等于把 RAM/STS/IAM 凭证泄露给外网。
/// - **环回 127/8**：会把 agent 自身 loopback-only 的管理面、或本机其它本地服务
///   重新发布到公网（再叠加 DNS 重绑定，纯网络攻击者可直达 Noise 端口）。
/// - **链路本地 169.254/16**：含上面的通用元数据地址。
/// - **0.0.0.0/8 / 广播 / 组播**：本就不是合法的 DNAT 单播目标。
///
/// 刻意**不**拦 RFC1918 私网与 100.64/10 CGNAT 整段：「公网端口 → 内网 LAN 服务」「转发到
/// Tailscale 远端」都是合法用途（ADR 0005），拦了会回归既有功能。调用点须对**每次解析后**
/// 的 IP 复检（覆盖域名 DNS 重绑定），见 agent `forward::resolve_one`。
pub fn forbidden_forward_target(ip: Ipv4Addr) -> Option<&'static str> {
    if CLOUD_METADATA_IPS.contains(&ip) {
        Some("云元数据端点（阿里云 100.100.100.200，可窃取 RAM/STS 凭证）")
    } else if ip.is_loopback() {
        Some("环回地址（会把本机管理面/本地服务暴露到公网）")
    } else if ip.is_link_local() {
        Some("链路本地地址（含云元数据 169.254.169.254）")
    } else if ip.octets()[0] == 0 {
        Some("0.0.0.0/8（本网络，非法单播目标）")
    } else if ip.is_broadcast() {
        Some("广播地址")
    } else if ip.is_multicast() {
        Some("组播地址")
    } else {
        None
    }
}

/// 校验监听/目标端口区间：各自合法，且区间长度匹配（或目标为单端口）。
pub fn validate_ports(listen: &PortRange, dest: &PortRange) -> Result<(), String> {
    if !listen.is_valid() || !dest.is_valid() {
        return Err("端口区间非法（start > end）".into());
    }
    let dest_single = dest.start == dest.end;
    if !dest_single && (listen.end - listen.start) != (dest.end - dest.start) {
        return Err(format!(
            "端口区间长度不一致：监听 {}-{} vs 目标 {}-{}",
            listen.start, listen.end, dest.start, dest.end
        ));
    }
    Ok(())
}

/// 新增/更新转发请求（API + CLI 共用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddForwardRequest {
    pub proto: ForwardProto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    pub listen: PortRange,
    pub dest_host: String,
    pub dest_port: PortRange,
    #[serde(default)]
    pub source: ForwardSource,
    #[serde(default)]
    pub note: String,
}

/// 客户端视角的一条转发：规则 + agent 侧解析/落地观测。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardView {
    #[serde(flatten)]
    pub rule: ForwardRule,
    /// 当前解析到的目标 IPv4（域名解析失败时可能为上次成功值或缺省）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_ip: Option<Ipv4Addr>,
    /// 该规则当前是否已在内核生效。
    pub active: bool,
}

/// 转发列表快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardList {
    pub forwards: Vec<ForwardView>,
    /// 单调递增修订号（与放行名单各自独立）。
    pub revision: u64,
}

/// 一条转发的来源（统一列表区分 native 与 dnat 适配，ADR 0006）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardOrigin {
    /// ipgate 自己的 native 转发（`ip ipgate_nat` 表，全增删改）。
    Ipgate,
    /// 外部 dnat 工具创建（`ip dnat_utils` 表）；排空模型下只读+删+迁移。
    Dnat,
}

/// 客户端对一条转发能做什么（排空模型：dnat 规则不可改、可删、可迁移）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardCaps {
    pub can_edit: bool,
    pub can_delete: bool,
    pub can_migrate: bool,
}

/// 统一列表里的一条转发（合并 native + dnat 两来源，ADR 0006）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedForwardView {
    pub origin: ForwardOrigin,
    pub proto: ForwardProto,
    /// native 可为 `None`（默认路由网卡）；dnat 总为具体网卡名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    pub listen: PortRange,
    pub dest_host: String,
    pub dest_port: PortRange,
    pub source: ForwardSource,
    #[serde(default)]
    pub note: String,
    /// 当前解析到的目标 IPv4。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_ip: Option<Ipv4Addr>,
    /// 是否已在内核生效。
    pub active: bool,
    pub caps: ForwardCaps,
    /// 与另一来源存在同网卡同端口重叠（过渡期碰撞提示）。
    #[serde(default)]
    pub conflict: bool,
    /// native 规则 id（`origin=ipgate` 时 `Some`；删除/编辑目标）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<ForwardId>,
    /// dnat 规则键（`origin=dnat` 时 `Some`；URL 安全，删除/迁移用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnat_key: Option<String>,
}

/// 统一转发列表快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedForwardList {
    pub forwards: Vec<UnifiedForwardView>,
    /// native 修订号（dnat 侧无版本，仅 native 计）。
    pub revision: u64,
}

/// 主机网卡信息（客户端做下拉选择 + 源 IP 提示）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4: Vec<Ipv4Addr>,
    /// 是否为默认路由网卡（`iface=None` 时 agent 会选它）。
    pub is_default_route: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(listen: PortRange, dest: PortRange, host: &str) -> ForwardRule {
        ForwardRule {
            id: ForwardId::new(),
            proto: ForwardProto::Tcp,
            iface: None,
            listen,
            dest_host: host.into(),
            dest_port: dest,
            source: ForwardSource::Auto,
            note: String::new(),
            created_at: Utc::now(),
            created_by: DeviceId::new(),
        }
    }

    #[test]
    fn single_port_ok() {
        assert!(rule(PortRange::single(443), PortRange::single(8443), "1.2.3.4")
            .validate()
            .is_ok());
    }

    #[test]
    fn equal_length_ranges_ok() {
        let r = rule(
            PortRange { start: 8000, end: 8010 },
            PortRange { start: 9000, end: 9010 },
            "ex.com",
        );
        assert!(r.validate().is_ok());
    }

    #[test]
    fn range_to_single_ok() {
        // 一段本地端口全转到同一个远端单端口，是允许的。
        let r = rule(
            PortRange { start: 8000, end: 8010 },
            PortRange::single(9000),
            "ex.com",
        );
        assert!(r.validate().is_ok());
    }

    #[test]
    fn mismatched_ranges_rejected() {
        let r = rule(
            PortRange { start: 8000, end: 8010 },
            PortRange { start: 9000, end: 9005 },
            "ex.com",
        );
        assert!(r.validate().is_err());
    }

    #[test]
    fn empty_host_rejected() {
        assert!(rule(PortRange::single(80), PortRange::single(80), "  ")
            .validate()
            .is_err());
    }

    #[test]
    fn literal_ip_detected() {
        let r = rule(PortRange::single(80), PortRange::single(80), "203.0.113.9");
        assert_eq!(r.dest_is_literal_ip(), Some("203.0.113.9".parse().unwrap()));
        let d = rule(PortRange::single(80), PortRange::single(80), "example.com");
        assert!(d.dest_is_literal_ip().is_none());
    }

    #[test]
    fn source_default_is_auto() {
        // 缺省 source 反序列化为 Auto。
        let json = r#"{"proto":"tcp","listen":{"start":80,"end":80},"dest_host":"a.com","dest_port":{"start":80,"end":80}}"#;
        let req: AddForwardRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.source, ForwardSource::Auto);
        assert_eq!(req.iface, None);
    }

    #[test]
    fn proto_expands() {
        assert_eq!(ForwardProto::Both.l4_protos(), &["tcp", "udp"]);
        assert_eq!(ForwardProto::Udp.l4_protos(), &["udp"]);
    }

    #[test]
    fn valid_iface_names_accepted() {
        // 真实网卡名都应通过（含 VLAN 点号、网桥连字符、下划线、单字符）。
        for ok in [
            "eth0", "ens18", "enp0s3", "br-lan", "wg0", "tailscale0", "eth0.100", "bond0", "a",
            "veth_abc", "ABCDEFGHIJKLMNO", // 15 字符上限
        ] {
            assert!(valid_iface_name(ok), "{ok:?} 应合法");
        }
    }

    #[test]
    fn injection_iface_names_rejected() {
        // 任何能逃逸 `iifname "{iface}"` 的字符/形态都必须拒。
        for bad in [
            "",
            "eth0\"",                  // 闭合引号
            "eth0\nflush ruleset",     // 换行注入
            "a b",                     // 空格
            "x;reboot",                // 分号
            "eth0{",                   // 花括号
            "eth0}",
            "eth0\\",                  // 反斜杠
            "../etc",                  // 斜杠
            "ABCDEFGHIJKLMNOP",        // 16 字符，超 IFNAMSIZ-1
            "网卡",                    // 非 ASCII
        ] {
            assert!(!valid_iface_name(bad), "{bad:?} 应被拒");
        }
    }

    #[test]
    fn forbidden_targets_blocked() {
        for ip in [
            "127.0.0.1",
            "127.5.6.7",       // 整个 127/8
            "169.254.169.254", // 通用云元数据
            "169.254.0.1",
            "100.100.100.200", // 阿里云元数据（在 100.64/10 内，按精确 IP 拦）
            "100.100.100.136", // 阿里云同族端点
            "0.0.0.0",
            "0.1.2.3",   // 0.0.0.0/8 本网络
            "0.255.0.1", // 0.0.0.0/8
            "255.255.255.255",
            "224.0.0.1", // 组播
            "239.1.2.3",
        ] {
            assert!(
                forbidden_forward_target(ip.parse().unwrap()).is_some(),
                "{ip} 应被拒"
            );
        }
    }

    #[test]
    fn legit_targets_allowed_including_private_lan() {
        // 公网 + 私网 LAN 都是合法转发目标，绝不能误伤（防回归）。
        for ip in [
            "1.2.3.4",
            "8.8.8.8",
            "203.0.113.9",
            "10.0.0.5",     // RFC1918
            "192.168.1.10", // RFC1918
            "172.16.0.1",   // RFC1918
            "100.64.0.1",   // CGNAT/Tailscale 远端（整段放行）
            "100.100.100.1", // 100.64/10 内、但非阿里云元数据 → 允许（精确拦，不拦整段）
            "100.127.255.254",
        ] {
            assert!(
                forbidden_forward_target(ip.parse().unwrap()).is_none(),
                "{ip} 应允许（含私网 LAN / CGNAT，ADR 0005 合法用途）"
            );
        }
    }
}
