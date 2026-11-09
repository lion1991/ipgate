//! 期望态（存储）与内核实际态的对账。

use chrono::{DateTime, Utc};
use ipgate_proto::{Diff, Entry, KernelElement};
use ipnet::IpNet;
use std::collections::HashSet;

/// 要落进内核的条目：仍有效，且不被另一条有效条目包含。
///
/// interval set 不接受重叠元素，名单里互相包含时整表落地会被拒、agent 起不来。放行时已拒绝
/// 重叠（`Store::allow`），这里兜住旧版本存下的：只落外层那条，外层过期或撤销后，
/// 被包含的由对账补进内核。网段相同只是写法不同（如 `1.2.3.4/24` 与 `1.2.3.0/24`）时留先出现的。
pub fn effective(entries: &[Entry], now: DateTime<Utc>) -> Vec<&Entry> {
    let active: Vec<(usize, IpNet, &Entry)> = entries
        .iter()
        .filter(|e| !e.is_expired(now))
        .enumerate()
        .map(|(i, e)| (i, e.target.trunc(), e))
        .collect();
    active
        .iter()
        .filter(|(i, net, _)| {
            !active
                .iter()
                .any(|(j, outer, _)| j != i && outer.contains(net) && (outer != net || j < i))
        })
        .map(|(_, _, e)| *e)
        .collect()
}

/// 计算存储条目与内核元素之间的差异。
///
/// - `missing_in_kernel`：该落内核（见 [`effective`]）、但内核里没有 → 需补加。
/// - `stale_in_kernel`：内核里有、但不该落（含被内核 timeout 删后的不一致）→ 需删。
/// - `expired`：存储里已过期、待清理。
pub fn diff(desired: &[Entry], kernel: &[KernelElement], now: DateTime<Utc>) -> Diff {
    let active: HashSet<IpNet> = effective(desired, now).iter().map(|e| e.target).collect();
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
    fn effective_keeps_outermost() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        let entries = vec![
            entry("203.0.113.5/32", None),
            entry("203.0.113.0/24", None),
            entry("203.0.113.9/24", None), // 同网段不同写法：留先出现的 /24
            entry("198.51.100.0/24", Some(past)), // 外层已过期 → 不算覆盖
            entry("198.51.100.7/32", None),
            entry("2001:db8::1/128", None),
        ];
        let got: Vec<String> = effective(&entries, now).iter().map(|e| e.target.to_string()).collect();
        assert_eq!(got, vec!["203.0.113.0/24", "198.51.100.7/32", "2001:db8::1/128"]);
    }

    #[test]
    fn covered_entry_is_neither_missing_nor_stale() {
        let now = Utc::now();
        let desired = vec![entry("203.0.113.0/24", None), entry("203.0.113.5/32", None)];
        assert!(diff(&desired, &[kel("203.0.113.0/24")], now).is_empty());
        // 旧版本落下的内层元素：换成外层。
        let d = diff(&desired, &[kel("203.0.113.5/32")], now);
        assert_eq!(d.missing_in_kernel, vec!["203.0.113.0/24".parse().unwrap()]);
        assert_eq!(d.stale_in_kernel, vec!["203.0.113.5/32".parse().unwrap()]);
        // 外层撤销后，内层变为该补。
        let d = diff(&desired[1..], &[], now);
        assert_eq!(d.missing_in_kernel, vec!["203.0.113.5/32".parse().unwrap()]);
    }

    #[test]
    fn in_sync_is_empty() {
        let now = Utc::now();
        let desired = vec![entry("203.0.113.0/24", None)];
        let kernel = vec![kel("203.0.113.0/24")];
        assert!(diff(&desired, &kernel, now).is_empty());
    }
}
