//! 期望态（存储）与内核实际态的对账。

use chrono::{DateTime, Utc};
use ipgate_proto::{Diff, Entry, KernelElement};
use ipnet::IpNet;
use std::collections::HashSet;

/// 计算存储条目与内核元素之间的差异。
///
/// - `missing_in_kernel`：仍有效、但内核里没有 → 需补加。
/// - `stale_in_kernel`：内核里有、但存储里无（含被内核 timeout 删后的不一致）→ 需删。
/// - `expired`：存储里已过期、待清理。
pub fn diff(desired: &[Entry], kernel: &[KernelElement], now: DateTime<Utc>) -> Diff {
    let active: HashSet<IpNet> = desired
        .iter()
        .filter(|e| !e.is_expired(now))
        .map(|e| e.target)
        .collect();
    let in_kernel: HashSet<IpNet> = kernel.iter().map(|k| k.target).collect();

    Diff {
        missing_in_kernel: active.difference(&in_kernel).copied().collect(),
        stale_in_kernel: in_kernel.difference(&active).copied().collect(),
        expired: desired
            .iter()
            .filter(|e| e.is_expired(now))
            .map(|e| e.target)
            .collect(),
    }
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

    fn kel(target: &str) -> KernelElement {
        KernelElement {
            target: target.parse().unwrap(),
            expires_at: None,
        }
    }

    #[test]
    fn computes_missing_stale_expired() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        let desired = vec![
            entry("203.0.113.0/24", None), // 内核有 → 一致
            entry("198.51.100.7/32", None), // 内核无 → missing
            entry("192.0.2.9/32", Some(past)), // 已过期 → expired
        ];
        let kernel = vec![
            kel("203.0.113.0/24"),
            kel("10.0.0.0/8"), // 存储无 → stale
        ];
        let d = diff(&desired, &kernel, now);
        assert_eq!(d.missing_in_kernel, vec!["198.51.100.7/32".parse().unwrap()]);
        assert_eq!(d.stale_in_kernel, vec!["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(d.expired, vec!["192.0.2.9/32".parse().unwrap()]);
        assert!(!d.is_empty());
    }

    #[test]
    fn in_sync_is_empty() {
        let now = Utc::now();
        let desired = vec![entry("203.0.113.0/24", None)];
        let kernel = vec![kel("203.0.113.0/24")];
        assert!(diff(&desired, &kernel, now).is_empty());
    }
}
