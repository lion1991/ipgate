//! nftables ruleset 配置与对账类型（ADR 0002，全主机 default-drop）。

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// agent 的 ruleset 配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesetConfig {
    /// 管理端口：无条件放行，**永不**进受管名单。
    pub mgmt_port: u16,
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
            mgmt_port: crate::DEFAULT_MGMT_PORT,
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
