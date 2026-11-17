//! 多目标转发的探测与按延迟选择（ADR 0014）。
//!
//! 探测线程每 5 秒对每条多目标规则的每个目标做一次 TCP connect，维护内存里的健康与延迟窗口；
//! 选中目标变了就写进 store（持久化）并调 [`crate::forward::apply_now`] 重建 nat 表。
//! 健康与延迟只在 agent 进程内存里，重启后从 Unknown 重新攒。

use crate::conntrack;
use crate::forward;
use crate::nft::NatBackend;
use crate::resolve;
use crate::store::{LockExt, Store};
use chrono::Utc;
use ipgate_proto::{
    ForwardId, ForwardRule, ForwardSwitch, ForwardTarget, SwitchReason, TargetHealth, TargetStatus,
};
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// 一轮探测（含域名解析）最多等多久；没按时回来的目标记一次失败。getaddrinfo 没有超时，
/// 不设截止的话 DNS 不通会拖住整轮，连纯 IP 目标的判挂也跟着变慢。
const ROUND_DEADLINE: Duration = Duration::from_secs(4);
/// 延迟取最近几次成功样本的中位数。
const WINDOW: usize = 6;
const DOWN_AFTER: u32 = 3;
const UP_AFTER: u32 = 2;
/// 另一目标要持续更快多久才切过去。
const HOLD: Duration = Duration::from_secs(60);
/// 快多少才算「更快」：低于当前的 80%，且至少快这么多微秒。
const MIN_GAIN_US: u32 = 10_000;

/// 一个目标的探测状态。
#[derive(Debug, Clone)]
pub struct TargetState {
    pub health: TargetHealth,
    ok: u32,
    fail: u32,
    samples: VecDeque<u32>,
    /// 最近一次解析成功的 IP（域名解析失败时回退，也供落地用）。
    pub ip: Option<Ipv4Addr>,
}

impl Default for TargetState {
    fn default() -> Self {
        TargetState { health: TargetHealth::Unknown, ok: 0, fail: 0, samples: VecDeque::new(), ip: None }
    }
}

impl TargetState {
    /// 记一次探测：`Some(握手微秒)` 成功，`None` 失败。
    pub fn record(&mut self, r: Option<u32>) {
        match r {
            Some(us) => {
                self.ok += 1;
                self.fail = 0;
                self.samples.push_back(us);
                if self.samples.len() > WINDOW {
                    self.samples.pop_front();
                }
                if self.health != TargetHealth::Up && self.ok >= UP_AFTER {
                    self.health = TargetHealth::Up;
                }
            }
            None => {
                self.fail += 1;
                self.ok = 0;
                if self.health != TargetHealth::Down && self.fail >= DOWN_AFTER {
                    self.health = TargetHealth::Down;
                    // 恢复后按新样本算延迟，不拿挂之前的数比。
                    self.samples.clear();
                }
            }
        }
    }

    /// 延迟中位数（偶数个取下中位）。
    pub fn latency(&self) -> Option<u32> {
        let mut v: Vec<u32> = self.samples.iter().copied().collect();
        if v.is_empty() {
            return None;
        }
        v.sort_unstable();
        Some(v[(v.len() - 1) / 2])
    }
}

/// 根据各目标状态决定要不要换目标。`candidate` 记「哪个目标从何时起一直更快」。
pub fn decide(
    selected: usize,
    targets: &[TargetState],
    candidate: &mut Option<(usize, Instant)>,
    now: Instant,
) -> Option<(usize, SwitchReason)> {
    let best = targets
        .iter()
        .enumerate()
        .filter(|(_, t)| t.health == TargetHealth::Up)
        .filter_map(|(i, t)| t.latency().map(|l| (i, l)))
        .min_by_key(|&(i, l)| (l, i));
    let cur = targets.get(selected)?;

    if cur.health == TargetHealth::Down {
        *candidate = None;
        return best.map(|(i, _)| (i, SwitchReason::Down));
    }
    let (cur_lat, (b, b_lat)) = match (cur.latency(), best) {
        (Some(c), Some(b)) if cur.health == TargetHealth::Up => (c, b),
        _ => {
            *candidate = None;
            return None;
        }
    };
    let faster = b != selected
        && (b_lat as u64) * 5 < (cur_lat as u64) * 4
        && cur_lat - b_lat >= MIN_GAIN_US;
    if !faster {
        *candidate = None;
        return None;
    }
    match *candidate {
        Some((c, since)) if c == b => {
            if now.duration_since(since) >= HOLD {
                *candidate = None;
                Some((b, SwitchReason::Latency))
            } else {
                None
            }
        }
        _ => {
            *candidate = Some((b, now));
            None
        }
    }
}

/// 决定探测状态是否还对得上规则：目标或探测端口变了就重来。
fn fingerprint(rule: &ForwardRule) -> Vec<(ForwardTarget, u16)> {
    (0..rule.target_count())
        .filter_map(|i| rule.target(i))
        .map(|t| {
            let p = rule.probe_port_for(&t);
            (t, p)
        })
        .collect()
}

struct RuleState {
    key: Vec<(ForwardTarget, u16)>,
    targets: Vec<TargetState>,
    candidate: Option<(usize, Instant)>,
}

static HEALTH: LazyLock<Mutex<HashMap<ForwardId, RuleState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 探测线程最近解析到的目标 IP（落地时优先用它，比持久化缓存新）。规则刚被改过、
/// 探测状态还没按新目标重来时不返回，免得把旧目标的 IP 当成新目标的回退。
pub fn last_ip(rule: &ForwardRule, idx: usize) -> Option<Ipv4Addr> {
    let health = HEALTH.lock_safe();
    let st = health.get(&rule.id).filter(|s| s.key == fingerprint(rule))?;
    st.targets.get(idx)?.ip
}

/// 多目标规则各目标的状态（单目标规则为空）。
pub fn statuses(rule: &ForwardRule, selected: usize) -> Vec<TargetStatus> {
    if rule.target_count() < 2 {
        return Vec::new();
    }
    let health = HEALTH.lock_safe();
    let st = health.get(&rule.id).filter(|s| s.key == fingerprint(rule));
    (0..rule.target_count())
        .filter_map(|i| rule.target(i))
        .enumerate()
        .map(|(i, t)| {
            let ts = st.and_then(|s| s.targets.get(i));
            TargetStatus {
                host: t.host,
                port: t.port,
                ip: ts.and_then(|s| s.ip),
                health: ts.map_or(TargetHealth::Unknown, |s| s.health),
                latency_us: ts.and_then(|s| s.latency()),
                selected: i == selected,
            }
        })
        .collect()
}

/// 解析 + 禁区检查 + 一次 TCP 握手。返回（解析到的 IP，握手微秒）。
fn probe(t: &ForwardTarget, port: u16, prev_ip: Option<Ipv4Addr>) -> (Option<Ipv4Addr>, Option<u32>) {
    let ip = resolve::resolve_ipv4(&t.host).or(prev_ip);
    let Some(ip) = ip else { return (None, None) };
    if ipgate_proto::forbidden_forward_target(ip).is_some() {
        return (Some(ip), None);
    }
    let start = Instant::now();
    let ok = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), PROBE_TIMEOUT).is_ok();
    let us = ok.then(|| start.elapsed().as_micros().min(u32::MAX as u128) as u32);
    (Some(ip), us)
}

/// 一次需要落地的切换。
struct Switch {
    rule: ForwardRule,
    sw: ForwardSwitch,
    /// 判挂切走时旧目标的 IP（落地后清它的 conntrack）。
    dead_ip: Option<Ipv4Addr>,
}

/// 探测期间规则可能被删改：规则还在、目标没变、选中的仍是 `from` 才写入切换。
/// 判挂时清 conntrack 用实际 DNAT 到的 IP（`resolved`），没有才用探测解析到的。
fn accept(s: &mut Store, mut sw: Switch) -> Option<Switch> {
    let now = s.find_forward(sw.rule.id)?;
    if fingerprint(now) != fingerprint(&sw.rule) || s.failover(sw.rule.id).selected != sw.sw.from {
        return None;
    }
    if sw.sw.reason == SwitchReason::Down {
        sw.dead_ip = s.resolved_ip(sw.rule.id).or(sw.dead_ip);
    }
    s.set_selected(sw.rule.id, sw.sw);
    Some(sw)
}

fn round(store: &Arc<Mutex<Store>>) -> Vec<Switch> {
    let rules: Vec<(ForwardRule, usize)> = {
        let s = store.lock_safe();
        s.forwards()
            .iter()
            .filter(|r| r.target_count() > 1)
            .map(|r| (r.clone(), s.failover(r.id).selected))
            .collect()
    };

    // 清掉已删或改回单目标的规则；目标变了的重来。
    let jobs: Vec<(usize, usize, ForwardTarget, u16, Option<Ipv4Addr>)> = {
        let mut health = HEALTH.lock_safe();
        health.retain(|id, _| rules.iter().any(|(r, _)| r.id == *id));
        let mut jobs = Vec::new();
        for (ri, (rule, _)) in rules.iter().enumerate() {
            let key = fingerprint(rule);
            let st = health.entry(rule.id).or_insert_with(|| RuleState {
                key: key.clone(),
                targets: Vec::new(),
                candidate: None,
            });
            if st.key != key || st.targets.len() != key.len() {
                *st = RuleState {
                    key: key.clone(),
                    targets: vec![TargetState::default(); key.len()],
                    candidate: None,
                };
            }
            for (ti, (t, port)) in key.into_iter().enumerate() {
                jobs.push((ri, ti, t, port, st.targets[ti].ip));
            }
        }
        jobs
    };

    // 每个目标一个线程，按截止时间收结果；卡在 DNS 上的线程不等，它返回后结果被丢弃。
    let (tx, rx) = std::sync::mpsc::channel();
    let total = jobs.len();
    for (ri, ti, t, port, prev) in jobs.iter().cloned() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let (ip, us) = probe(&t, port, prev);
            let _ = tx.send((ri, ti, ip, us));
        });
    }
    drop(tx);
    let deadline = Instant::now() + ROUND_DEADLINE;
    let mut got = std::collections::HashSet::new();
    let mut results = Vec::with_capacity(total);
    while results.len() < total {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(r) => {
                got.insert((r.0, r.1));
                results.push(r);
            }
            Err(_) => break,
        }
    }
    for (ri, ti, ..) in &jobs {
        if !got.contains(&(*ri, *ti)) {
            results.push((*ri, *ti, None, None));
        }
    }

    let now = Instant::now();
    let mut health = HEALTH.lock_safe();
    for (ri, ti, ip, us) in results {
        debug!(listen = rules[ri].0.listen.start, target = ti, ip = ?ip, latency_us = ?us, "转发：探测");
        if let Some(t) = health.get_mut(&rules[ri].0.id).and_then(|s| s.targets.get_mut(ti)) {
            if ip.is_some() {
                t.ip = ip;
            }
            t.record(us);
        }
    }
    let mut out = Vec::new();
    for (rule, selected) in rules {
        let Some(st) = health.get_mut(&rule.id) else { continue };
        if let Some((to, reason)) = decide(selected, &st.targets, &mut st.candidate, now) {
            let dead_ip = match reason {
                SwitchReason::Down => st.targets[selected].ip,
                SwitchReason::Latency => None,
            };
            let sw = ForwardSwitch { at: Utc::now(), from: selected, to, reason };
            out.push(Switch { rule, sw, dead_ip });
        }
    }
    out
}

/// 探测循环（独立阻塞线程）。
pub fn probe_loop(store: Arc<Mutex<Store>>, nat: Arc<dyn NatBackend + Send + Sync>) {
    loop {
        let start = Instant::now();
        let switches = round(&store);
        if !switches.is_empty() {
            let (switches, applied) = forward::mutate_and_apply(&store, &nat, |s| {
                switches.into_iter().filter_map(|sw| accept(s, sw)).collect::<Vec<_>>()
            });
            for sw in &switches {
                let host = |i| sw.rule.target(i).map(|t| t.host).unwrap_or_default();
                info!(
                    listen = sw.rule.listen.start,
                    from = %host(sw.sw.from),
                    to = %host(sw.sw.to),
                    reason = ?sw.sw.reason,
                    "转发：切换目标"
                );
            }
            match applied {
                Ok(_) => {
                    // 先落新规则再删旧记录：删掉后下一个包按新规则 DNAT。
                    for sw in &switches {
                        flush_dead(sw);
                    }
                }
                Err(e) => warn!(error = %e, "转发：切换后落地失败（周期重解析会重试）"),
            }
        }
        std::thread::sleep(PROBE_INTERVAL.saturating_sub(start.elapsed()));
    }
}

fn flush_dead(sw: &Switch) {
    let (Some(ip), Some(t)) = (sw.dead_ip, sw.rule.target(sw.sw.from)) else { return };
    let f = conntrack::Filter {
        target_ip: ip,
        target_ports: t.port,
        listen: sw.rule.listen,
        protos: conntrack::l4_numbers(sw.rule.proto),
    };
    match conntrack::flush(&f) {
        Ok(0) => {}
        Ok(n) => info!(target = %ip, removed = n, "转发：已清除到失效目标的连接跟踪记录"),
        Err(e) => warn!(error = %e, target = %ip, "转发：清除连接跟踪记录失败"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(lat_us: u32) -> TargetState {
        let mut t = TargetState::default();
        for _ in 0..WINDOW {
            t.record(Some(lat_us));
        }
        t
    }

    fn down() -> TargetState {
        let mut t = TargetState::default();
        for _ in 0..DOWN_AFTER {
            t.record(None);
        }
        t
    }

    #[test]
    fn health_thresholds() {
        let mut t = TargetState::default();
        t.record(Some(1000));
        assert_eq!(t.health, TargetHealth::Unknown);
        t.record(Some(3000));
        assert_eq!(t.health, TargetHealth::Up);
        assert_eq!(t.latency(), Some(1000));
        t.record(None);
        t.record(None);
        assert_eq!(t.health, TargetHealth::Up, "两次失败还不算挂");
        t.record(Some(1000));
        t.record(None);
        t.record(None);
        assert_eq!(t.health, TargetHealth::Up, "失败计数被成功打断");
        t.record(None);
        assert_eq!(t.health, TargetHealth::Down);
        assert_eq!(t.latency(), None, "判挂清掉旧样本");
        t.record(Some(5000));
        assert_eq!(t.health, TargetHealth::Down);
        t.record(Some(5000));
        assert_eq!(t.health, TargetHealth::Up);
    }

    #[test]
    fn median_uses_recent_window() {
        let mut t = up(100_000);
        for us in [1, 2, 3, 4, 5, 6] {
            t.record(Some(us * 1000));
        }
        assert_eq!(t.latency(), Some(3000));
    }

    #[test]
    fn down_switches_immediately_to_fastest_up() {
        let now = Instant::now();
        let mut c = None;
        let ts = [down(), up(50_000), up(20_000), TargetState::default()];
        assert_eq!(decide(0, &ts, &mut c, now), Some((2, SwitchReason::Down)));
    }

    #[test]
    fn all_down_stays() {
        let mut c = None;
        let ts = [down(), down(), TargetState::default()];
        assert_eq!(decide(1, &ts, &mut c, Instant::now()), None);
    }

    #[test]
    fn latency_switch_needs_hold_and_margin() {
        let t0 = Instant::now();
        let mut c = None;
        // 100ms vs 70ms：快 30%、30ms，满足条件，但要持续 60 秒
        let ts = [up(100_000), up(70_000)];
        assert_eq!(decide(0, &ts, &mut c, t0), None);
        assert_eq!(decide(0, &ts, &mut c, t0 + Duration::from_secs(59)), None);
        assert_eq!(
            decide(0, &ts, &mut c, t0 + Duration::from_secs(60)),
            Some((1, SwitchReason::Latency))
        );

        // 中途不再更快：计时清零
        let mut c = None;
        decide(0, &ts, &mut c, t0);
        let close = [up(100_000), up(90_000)];
        assert_eq!(decide(0, &close, &mut c, t0 + Duration::from_secs(30)), None);
        assert_eq!(decide(0, &ts, &mut c, t0 + Duration::from_secs(61)), None);
    }

    #[test]
    fn latency_margin_rules() {
        let t0 = Instant::now();
        let later = t0 + HOLD;
        let run = |ts: &[TargetState]| {
            let mut c = None;
            decide(0, ts, &mut c, t0);
            decide(0, ts, &mut c, later)
        };
        // 快 20% 不够（要低于 80%）
        assert_eq!(run(&[up(100_000), up(80_000)]), None);
        // 比例够但绝对值不到 10ms
        assert_eq!(run(&[up(20_000), up(11_000)]), None);
        // 都够
        assert_eq!(run(&[up(20_000), up(9_000)]), Some((1, SwitchReason::Latency)));
        // 当前还没攒够样本：不按延迟切
        assert_eq!(run(&[TargetState::default(), up(1_000)]), None);
        // 当前就是最快的
        assert_eq!(run(&[up(1_000), up(50_000)]), None);
    }

    fn multi_rule() -> ForwardRule {
        use ipgate_proto::{DeviceId, ForwardProto, ForwardSource, PortRange};
        ForwardRule {
            id: ForwardId::new(),
            proto: ForwardProto::Tcp,
            iface: None,
            listen: PortRange::single(443),
            dest_host: "a.com".into(),
            dest_port: PortRange::single(8443),
            source: ForwardSource::Auto,
            note: String::new(),
            created_at: Utc::now(),
            created_by: DeviceId::new(),
            extra_targets: vec![ForwardTarget { host: "b.com".into(), port: PortRange::single(8443) }],
            probe_port: None,
        }
    }

    #[test]
    fn last_ip_ignores_state_of_edited_rule() {
        let r = multi_rule();
        let t = TargetState { ip: Some("10.0.0.1".parse().unwrap()), ..Default::default() };
        HEALTH.lock_safe().insert(
            r.id,
            RuleState { key: fingerprint(&r), targets: vec![t, TargetState::default()], candidate: None },
        );
        assert_eq!(last_ip(&r, 0), Some("10.0.0.1".parse().unwrap()));
        let mut edited = r.clone();
        edited.dest_host = "c.com".into();
        assert_eq!(last_ip(&edited, 0), None);
        HEALTH.lock_safe().remove(&r.id);
    }

    #[test]
    fn stale_switch_is_dropped() {
        use ipgate_proto::AddForwardRequest;
        let dir = std::env::temp_dir().join(format!("ipgate-fo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = Store::load(&dir.join("state.json")).unwrap();
        let tmpl = multi_rule();
        let req = AddForwardRequest {
            proto: tmpl.proto,
            iface: None,
            listen: tmpl.listen,
            dest_host: tmpl.dest_host.clone(),
            dest_port: tmpl.dest_port,
            source: tmpl.source,
            note: String::new(),
            extra_targets: tmpl.extra_targets.clone(),
            probe_port: None,
        };
        let rule = s.add_forward(req.clone(), tmpl.created_by, Utc::now());
        s.set_resolved([(rule.id, "10.0.0.1".parse().unwrap())].into());
        let mk = |from, to| Switch {
            rule: rule.clone(),
            sw: ForwardSwitch { at: Utc::now(), from, to, reason: SwitchReason::Down },
            dead_ip: Some("10.9.9.9".parse().unwrap()),
        };

        // from 对不上当前选中
        assert!(accept(&mut s, mk(1, 0)).is_none());
        // 正常：dead_ip 用实际落地的 IP
        let ok = accept(&mut s, mk(0, 1)).unwrap();
        assert_eq!(ok.dead_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(s.failover(rule.id).selected, 1);

        // 规则目标被改过
        let mut changed = req.clone();
        changed.extra_targets[0].host = "c.com".into();
        s.update_forward(rule.id, changed).unwrap();
        assert!(accept(&mut s, mk(0, 1)).is_none());
        assert_eq!(s.failover(rule.id).selected, 0);

        // 规则已删：不留孤儿记录
        s.remove_forward(rule.id);
        assert!(accept(&mut s, mk(0, 1)).is_none());
        assert_eq!(s.failover(rule.id), crate::store::FailoverState::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn selected_out_of_range_is_noop() {
        let mut c = None;
        assert_eq!(decide(5, &[up(1)], &mut c, Instant::now()), None);
    }
}
