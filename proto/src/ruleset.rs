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
    /// true：去掉该无条件放行，SSH 仅经 `ip saddr @allow accept` 命中——即只有名单内
    /// 源 IP 能连。**有自锁风险**：当前外网 IP 不在名单时会把自己（含管理隧道）挡在外，
    /// 只能从 VPS 控制台用 `ipgate-agent ssh-expose --open` 恢复。开启前务必先放行自己。
    #[serde(default)]
    pub ssh_allowlist_only: bool,
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
            public_tcp: Vec::new(),
            public_udp: Vec::new(),
        }
    }
}

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
