//! 端口转发编排：解析每条规则的目标 IP / 网卡 / SNAT 源 → 渲染 → 落地
//! `ip ipgate_nat` 表。包含启动期一次性应用与周期重解析循环（域名漂移自愈）。
//!
//! 与放行名单的对账循环（`reconcile`）平行、互不干扰：转发是整表全量切换，
//! 名单是 set 元素增量。

use crate::netinfo;
use crate::nft::{NatBackend, ResolvedForward};
use crate::resolve;
use crate::store::{LockExt, Store};
use ipgate_proto::{ForwardId, ForwardRule, ForwardSource};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

type Nat = Arc<dyn NatBackend + Send + Sync>;

/// 把一条规则解析成可渲染的 [`ResolvedForward`]；解析不出则 `Err(原因)`（该条跳过）。
///
/// - 网卡：显式 `iface`，否则默认路由网卡。
/// - 目标 IP：解析 `dest_host`，失败时回退 `prev`（上次成功 IP，动态域名兜底）。
/// - SNAT 源：`auto` 取网卡首个 IPv4；显式 IP 若已不在网卡上则回退当前网卡 IP（IP 漂移自愈）。
fn resolve_one(rule: &ForwardRule, prev: Option<Ipv4Addr>) -> Result<ResolvedForward, String> {
    let iface = match &rule.iface {
        Some(i) => {
            // 安全闸：网卡名要被原样插进 `nft -f` 的 `iifname "{}"`，非白名单字符
            // 可注入任意 nftables 语句（见 proto::valid_iface_name）。落地前再挡一道，
            // 兜住任何绕过 API 校验写进 store 的脏数据。
            if !ipgate_proto::valid_iface_name(i) {
                return Err(format!("非法网卡名 {i:?}（仅允许字母数字与 . _ -，≤15）"));
            }
            i.clone()
        }
        None => netinfo::default_route_iface()
            .ok_or_else(|| "无默认路由网卡，且未指定 iface".to_string())?,
    };

    let remote_ip = match resolve::resolve_ipv4(&rule.dest_host) {
        Some(ip) => ip,
        None => prev.ok_or_else(|| format!("解析 {} 失败且无历史 IP", rule.dest_host))?,
    };
    // 安全闸：拒绝把流量 DNAT 到环回/链路本地等禁区。**每次解析后**都查，故能挡住
    // 域名先解析到良性 IP、之后被 DNS 重绑定到 127.0.0.1:<mgmt>/169.254.169.254 的攻击
    // （周期 resolve_loop 同样走这里）。私网 LAN 不拦，保留 ADR 0005 合法转发用途。
    if let Some(why) = ipgate_proto::forbidden_forward_target(remote_ip) {
        return Err(format!("目标 {remote_ip} 被拒：{why}"));
    }

    let source_ip = match rule.source {
        ForwardSource::Auto => netinfo::first_ipv4(&iface)
            .ok_or_else(|| format!("网卡 {iface} 无 IPv4，无法做 SNAT 源"))?,
        ForwardSource::Ip(ip) => {
            if netinfo::iface_has_ipv4(&iface, ip) {
                ip
            } else {
                netinfo::first_ipv4(&iface)
                    .ok_or_else(|| format!("源 {ip} 不在网卡 {iface} 上，且该网卡无可用 IPv4"))?
            }
        }
    };

    Ok(ResolvedForward {
        proto: rule.proto,
        iface,
        listen: rule.listen,
        remote_ip,
        dest_port: rule.dest_port,
        source_ip,
    })
}

/// 解析 store 中全部转发规则。返回（可渲染规则、新解析缓存、各条跳过原因）。
fn resolve_all(
    store: &Arc<Mutex<Store>>,
) -> (Vec<ResolvedForward>, HashMap<ForwardId, Ipv4Addr>, Vec<String>) {
    let (rules, prev): (Vec<ForwardRule>, HashMap<ForwardId, Ipv4Addr>) = {
        let s = store.lock_safe();
        let rules = s.forwards().to_vec();
        let prev = rules
            .iter()
            .filter_map(|r| s.resolved_ip(r.id).map(|ip| (r.id, ip)))
            .collect();
        (rules, prev)
    };

    let mut resolved = Vec::new();
    let mut new_map = HashMap::new();
    let mut warnings = Vec::new();
    for rule in &rules {
        match resolve_one(rule, prev.get(&rule.id).copied()) {
            Ok(rf) => {
                new_map.insert(rule.id, rf.remote_ip);
                resolved.push(rf);
            }
            Err(e) => warnings.push(format!(
                "{}:{}→{} 跳过：{e}",
                rule.iface.clone().unwrap_or_else(|| "auto".into()),
                rule.listen.start,
                rule.dest_host
            )),
        }
    }
    (resolved, new_map, warnings)
}

/// 落地一组已解析规则：空则 flush 整表；否则开 ip_forward + apply_nat。成功后回写解析缓存。
fn commit(
    store: &Arc<Mutex<Store>>,
    nat: &Nat,
    resolved: &[ResolvedForward],
    new_map: HashMap<ForwardId, Ipv4Addr>,
) -> anyhow::Result<()> {
    if resolved.is_empty() {
        nat.flush_nat()?;
    } else {
        // 有规则就必须开转发，否则 DNAT 形同虚设。失败仅告警（可能是只读 /proc 的容器）。
        if let Err(e) = netinfo::ensure_ip_forward() {
            warn!(error = %e, "转发：开启 ip_forward 失败");
        }
        nat.apply_nat(resolved)?;
    }
    let mut s = store.lock_safe();
    s.set_resolved(new_map);
    let _ = s.save();
    Ok(())
}

/// 立即解析 + 落地一次（API handler / 启动期用）。返回（生效条数、跳过告警）。
///
/// 落地失败返回 `Err` 且**不回写**解析缓存——保留上次良态，避免一次抖动污染回退源。
pub fn apply_now(store: &Arc<Mutex<Store>>, nat: &Nat) -> anyhow::Result<(usize, Vec<String>)> {
    let (resolved, new_map, warnings) = resolve_all(store);
    commit(store, nat, &resolved, new_map)?;
    Ok((resolved.len(), warnings))
}

fn hash_of(resolved: &[ResolvedForward]) -> u64 {
    let mut h = DefaultHasher::new();
    resolved.len().hash(&mut h);
    for r in resolved {
        r.hash(&mut h);
    }
    h.finish()
}

/// 周期重解析循环（独立阻塞线程）：域名 IP 漂移后自动重建 nat 表。
///
/// 用解析结果的 hash 跳过「无变化」的轮次，避免每 tick 都 `nft -f` 刷内核/日志。
pub fn resolve_loop(store: Arc<Mutex<Store>>, nat: Nat, interval: u64) {
    let mut last_hash: Option<u64> = None;
    loop {
        std::thread::sleep(Duration::from_secs(interval));
        let (resolved, new_map, warnings) = resolve_all(&store);
        let h = hash_of(&resolved);
        if Some(h) == last_hash {
            continue; // 解析结果未变，跳过
        }
        match commit(&store, &nat, &resolved, new_map) {
            Ok(()) => {
                for w in &warnings {
                    warn!("转发：{w}");
                }
                info!(applied = resolved.len(), "转发：解析结果变化，已重新落地");
                last_hash = Some(h);
            }
            Err(e) => warn!(error = %e, "转发：周期落地失败（保留上次状态）"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipgate_proto::{ForwardProto, PortRange};

    fn rule(iface: Option<&str>, dest: &str) -> ForwardRule {
        ForwardRule {
            id: ForwardId::new(),
            proto: ForwardProto::Tcp,
            iface: iface.map(|s| s.to_string()),
            listen: PortRange::single(443),
            dest_host: dest.to_string(),
            dest_port: PortRange::single(8443),
            source: ForwardSource::Auto,
            note: String::new(),
            created_at: chrono::Utc::now(),
            created_by: ipgate_proto::DeviceId::new(),
        }
    }

    // 注：iface 校验在最前、目标禁区校验紧随域名解析之后，二者都先于任何 `ip` 子进程，
    // 故这些断言不依赖测试机的网络/iproute2 环境，结果确定。

    #[test]
    fn resolve_one_rejects_injection_iface() {
        let r = rule(Some("eth0\"\nflush ruleset"), "1.2.3.4");
        let err = resolve_one(&r, None).unwrap_err();
        assert!(err.contains("非法网卡名"), "应因网卡名被拒，实际：{err}");
    }

    #[test]
    fn resolve_one_rejects_loopback_target() {
        // 把转发目标设成本机环回（典型攻击：暴露 loopback-only 管理面）。
        let r = rule(Some("eth0"), "127.0.0.1");
        let err = resolve_one(&r, None).unwrap_err();
        assert!(err.contains("被拒") && err.contains("环回"), "实际：{err}");
    }

    #[test]
    fn resolve_one_rejects_metadata_target() {
        let r = rule(Some("eth0"), "169.254.169.254");
        let err = resolve_one(&r, None).unwrap_err();
        assert!(err.contains("被拒") && err.contains("链路本地"), "实际：{err}");
    }

    // 注：prev 回退路径（域名解析失败时退回上次成功 IP）也走同一个 `remote_ip` 禁区检查，
    // 故安全属性与上面字面量用例同源；此处不再单测，因为无法在不联网/不被解析器劫持
    // NXDOMAIN 的前提下确定性地“强制解析失败”。
}
