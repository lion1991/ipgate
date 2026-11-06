//! nftables ruleset 配置与对账类型（ADR 0002，全主机 default-drop）。

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// agent 的 ruleset 配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesetConfig {
    /// SSH 管理端口（ADR 0007 唯一入口）。默认对全世界放行（防自锁）；置
    /// [`ssh_allowlist_only`](Self::ssh_allowlist_only) 后改为仅名单内源 IP 可连。
    pub ssh_port: u16,
    /// SSH 端口是否仅对放行名单开放（默认 false = 对所有人开放）。
    ///
    /// false：字面 `tcp dport <ssh_port> accept`，全世界可连（自锁不变量，最稳）。
    /// true：去掉该无条件放行，SSH 只放名单内源 IP 与刚敲过门的源 IP（[`Self::ssh_knock`]，
    /// ADR 0012）。敲门也不通时只能从 VPS 控制台用 `ipgate-agent ssh-expose --open` 恢复。
    #[serde(default)]
    pub ssh_allowlist_only: bool,
    /// SSH 敲门参数（由 access key 派生，ADR 0012）。仅在 `ssh_allowlist_only` 时渲染；
    /// `None` = 不渲染敲门规则（内核不支持时的降级）。含口令，不序列化。
    #[serde(skip)]
    pub ssh_knock: Option<SshKnock>,
    /// 转发名单门（ADR 0008）：被 DNAT 进来的新建连接（native 转发 / dnat 工具 / Docker `-p`）
    /// 是否也仅放行名单内源 IP 与公开端口。默认 false = 不接管 forward hook，转发对全网开放。
    #[serde(default)]
    pub forward_allowlist_only: bool,
    /// 对全世界开放的 TCP 端口/区间（默认空）。
    #[serde(default)]
    pub public_tcp: Vec<PortRange>,
    /// 对全世界开放的 UDP 端口/区间（默认空）。
    #[serde(default)]
    pub public_udp: Vec<PortRange>,
}

impl Default for RulesetConfig {
    fn default() -> Self {
        Self {
            ssh_port: crate::DEFAULT_SSH_PORT,
            ssh_allowlist_only: false,
            ssh_knock: None,
            forward_allowlist_only: false,
            public_tcp: Vec::new(),
            public_udp: Vec::new(),
        }
    }
}

impl RulesetConfig {
    /// 是否渲染敲门规则：「仅名单」开着且有敲门参数。
    pub fn knock(&self) -> Option<&SshKnock> {
        self.ssh_knock.as_ref().filter(|_| self.ssh_allowlist_only)
    }
}

/// SSH 敲门参数（ADR 0012）：发往 UDP `port`、载荷前 16 字节等于 `token` 的包让源 IP 获准连 SSH
/// [`KNOCK_TTL_SECS`] 秒。agent 与客户端各自从 access key 派生（proto 不引密码学库）。
#[derive(Clone, PartialEq, Eq)]
pub struct SshKnock {
    pub port: u16,
    pub token: [u8; 16],
}

impl core::fmt::Debug for SshKnock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SshKnock").field("port", &self.port).finish_non_exhaustive()
    }
}

/// 敲门后源 IP 获准新建 SSH 连接的时长（秒）。已建立的连接不受此限（conntrack）。
pub const KNOCK_TTL_SECS: u32 = 60;

/// 敲门端口派生区间起点；端口 = 起点 + 派生值 % [`KNOCK_PORT_SPAN`]。
pub const KNOCK_PORT_BASE: u16 = 20000;
pub const KNOCK_PORT_SPAN: u16 = 40000;

/// 端口或闭区间端口范围 `start..=end`（单端口时 `start == end`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }
    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
    pub fn is_valid(&self) -> bool {
        self.start <= self.end
    }
    /// 两闭区间是否相交（端口转发碰撞检测用）。
    pub fn overlaps(&self, other: &PortRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

/// 公开端口：对全世界放行的端口/区间（不看源 IP），落地进 `public_tcp` / `public_udp` set。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPort {
    pub proto: crate::ForwardProto,
    pub ports: PortRange,
    #[serde(default)]
    pub note: String,
    /// 来自 agent 的 `config.json`（只读，客户端删不掉）；false = 客户端经 RPC 添加。
    #[serde(default)]
    pub from_config: bool,
}

/// 新增公开端口；同 `(proto, ports)` 已存在时只更新备注。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPortRequest {
    pub proto: crate::ForwardProto,
    pub ports: PortRange,
    #[serde(default)]
    pub note: String,
}

/// 主机自己往外连时的公网出口 IP（agent 经公网 echo 服务探测）。探不到的一族为 `None`。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressIp {
    #[serde(default)]
    pub ipv4: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    pub ipv6: Option<std::net::Ipv6Addr>,
}

/// 内核 set 中的一个元素（由 `nft -j list set` 解析得到）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelElement {
    pub target: IpNet,
    /// 内核侧 timeout 到期时间（若该元素设置了 timeout）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// 期望态（ipgate 存储）与内核实际态的差异。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diff {
    /// 在存储中、内核缺失 → 需补加。
    pub missing_in_kernel: Vec<IpNet>,
    /// 在内核中、存储无 → 需删（含被内核 timeout 删后残留的不一致）。
    pub stale_in_kernel: Vec<IpNet>,
    /// 已过期、待 agent 清理的存储条目。
    pub expired: Vec<IpNet>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.missing_in_kernel.is_empty()
            && self.stale_in_kernel.is_empty()
            && self.expired.is_empty()
    }
}
