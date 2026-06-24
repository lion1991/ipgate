//! 放行名单与条目。

use crate::ids::{DeviceId, EntryId};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// 放行名单中的一条记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: EntryId,
    /// 目标地址，支持单 IP（如 `/32`、`/128`）或 CIDR 段，v4/v6 皆可。
    pub target: IpNet,
    /// 备注。仅 ipgate 存储，不落内核。
    #[serde(default)]
    pub note: String,
    /// 过期时间；`None` 表示永久。到期后由 agent 对账删除（内核 timeout 兜底）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// 创建该条目的设备。
    pub created_by: DeviceId,
}

impl Entry {
    /// 相对给定的「现在」是否已过期。
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(t) if t <= now)
    }
}

/// 新增放行（Allow）请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowRequest {
    pub target: IpNet,
    #[serde(default)]
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// 撤销放行（Revoke）请求：按条目 id 或按目标地址。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "by", content = "value")]
pub enum RevokeRequest {
    Id(EntryId),
    Target(IpNet),
}

/// 放行名单快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowlist {
    pub entries: Vec<Entry>,
    /// 单调递增修订号，用于客户端缓存失效与并发检测。
    pub revision: u64,
}
