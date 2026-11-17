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
/// 清 conntrack 连续失败几次就不再试（比如内核没加载 ctnetlink），免得每轮刷告警。
const MAX_FLUSH_TRIES: u8 = 3;

/// 一个目标的探测状态。
#[derive(Debug, Clone)]
pub struct TargetState {
    pub health: TargetHealth,
    ok: u32,
    fail: u32,
    samples: VecDeque<u32>,
    /// 最近一次解析成功的 IP（域名解析失败时回退，也供落地用）。
    pub ip: Option<Ipv4Addr>,
    /// 判挂后待清 conntrack 的 IP：不管它当时是不是在用目标，按延迟切走后留在它上面的
    /// 长连接（尤其持续发包的 UDP 流）也得清掉才会改走别的目标。清掉或恢复后置空。
    flush_ip: Option<Ipv4Addr>,
    flush_tries: u8,
}

impl Default for TargetState {
    fn default() -> Self {
        TargetState {
            health: TargetHealth::Unknown,
            ok: 0,
            fail: 0,
            samples: VecDeque::new(),
            ip: None,
            flush_ip: None,
            flush_tries: 0,
        }
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
                    self.flush_ip = None;
                }
            }
            None => {
                self.fail += 1;
                self.ok = 0;
                if self.health != TargetHealth::Down && self.fail >= DOWN_AFTER {
                    self.health = TargetHealth::Down;
                    // 恢复后按新样本算延迟，不拿挂之前的数比。
                    self.samples.clear();
                    self.flush_ip = self.ip;
                    self.flush_tries = 0;
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
}

/// 探测期间规则可能被删改：规则还在、目标没变、选中的仍是 `from` 才写入切换。
/// 判挂切走时，旧目标待清的 IP 换成实际 DNAT 到的（`resolved`），域名换过解析也清得对。
fn accept(s: &mut Store, mut sw: Switch) -> Option<Switch> {
    let now = s.find_forward(sw.rule.id)?.clone();
    let key = fingerprint(&now);
    if key != fingerprint(&sw.rule) || s.failover(now.id).selected != sw.sw.from {
        return None;
    }
    if sw.sw.reason == SwitchReason::Down {
        if let Some(ip) = s.resolved_ip(now.id) {
            let mut health = HEALTH.lock_safe();
            let t = health
                .get_mut(&now.id)
                .filter(|st| st.key == key)
                .and_then(|st| st.targets.get_mut(sw.sw.from));
            if let Some(t) = t {
                t.flush_ip = Some(ip);
            }
        }
    }
    s.set_selected(now.id, sw.sw);
    sw.rule = now;
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
        // 起不了线程（如碰到 TasksMax）就当这次探测失败，不让探测线程整个 panic。
        let spawned = std::thread::Builder::new().spawn(move || {
            let (ip, us) = probe(&t, port, prev);
            let _ = tx.send((ri, ti, ip, us));
        });
        if let Err(e) = spawned {
            warn!(error = %e, "转发：探测线程启动失败");
        }
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
            let sw = ForwardSwitch { at: Utc::now(), from: selected, to, reason };
            out.push(Switch { rule, sw });
        }
    }
    out
}

/// 探测循环（独立阻塞线程）。
pub fn probe_loop(store: Arc<Mutex<Store>>, nat: Arc<dyn NatBackend + Send + Sync>) {
    // 切换写进了 store 但落地失败：内核里可能还 DNAT 到旧目标，这时清它的 conntrack，
    // 新包又会按旧规则建回去。先补落地，成功了再清。
    let mut apply_pending = false;
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
            apply_pending = match applied {
                Ok(_) => false,
                Err(e) => {
                    warn!(error = %e, "转发：切换后落地失败（下一轮重试）");
                    true
                }
            };
        } else if apply_pending {
            apply_pending = match forward::apply_now(&store, &nat) {
                Ok(_) => false,
                Err(e) => {
                    warn!(error = %e, "转发：补落地失败（下一轮重试）");
                    true
                }
            };
        }
        if !apply_pending {
            flush_down(&store);
        }
        std::thread::sleep(PROBE_INTERVAL.saturating_sub(start.elapsed()));
    }
}

type FlushJob = (ForwardId, Vec<(ForwardTarget, u16)>, usize, conntrack::Filter);

/// 清掉到已判挂、且不是当前在用目标的连接跟踪记录。在用目标挂了但没得切时不清：
/// 规则还指着它，清了新包也会再建回去。失败的下一轮重试，最多 [`MAX_FLUSH_TRIES`] 次。
fn flush_down(store: &Arc<Mutex<Store>>) {
    let jobs = {
        let s = store.lock_safe();
        let health = HEALTH.lock_safe();
        flush_jobs(&s, &health)
    };
    for (id, key, i, f) in jobs {
        let result = conntrack::flush(&f);
        let mut health = HEALTH.lock_safe();
        let Some(t) = health.get_mut(&id).filter(|st| st.key == key).and_then(|st| st.targets.get_mut(i))
        else {
            continue;
        };
        match result {
            Ok(n) => {
                if n > 0 {
                    info!(target = %f.target_ip, removed = n, "转发：已清除到失效目标的连接跟踪记录");
                }
                t.flush_ip = None;
            }
            Err(e) => {
                t.flush_tries += 1;
                let give_up = t.flush_tries >= MAX_FLUSH_TRIES;
                warn!(error = %e, target = %f.target_ip, give_up, "转发：清除连接跟踪记录失败");
                if give_up {
                    t.flush_ip = None;
                }
            }
        }
    }
}

/// 该清哪些：已判挂、有待清 IP、且不是当前在用的目标。过滤条件用规则当前的监听段与协议。
fn flush_jobs(s: &Store, health: &HashMap<ForwardId, RuleState>) -> Vec<FlushJob> {
    let mut jobs = Vec::new();
    for rule in s.forwards().iter().filter(|r| r.target_count() > 1) {
        let key = fingerprint(rule);
        let Some(st) = health.get(&rule.id).filter(|st| st.key == key) else { continue };
        let selected = s.failover(rule.id).selected;
        for (i, t) in st.targets.iter().enumerate() {
            let (Some(ip), Some(target)) = (t.flush_ip, rule.target(i)) else { continue };
            if i == selected || t.health != TargetHealth::Down {
                continue;
            }
            let f = conntrack::Filter {
                target_ip: ip,
                target_ports: target.port,
                listen: rule.listen,
                protos: conntrack::l4_numbers(rule.proto),
            };
            jobs.push((rule.id, key.clone(), i, f));
        }
    }
    jobs
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
        };
        let mut dead = down();
        dead.flush_ip = Some("10.9.9.9".parse().unwrap());
        HEALTH.lock_safe().insert(
            rule.id,
            RuleState { key: fingerprint(&rule), targets: vec![dead, up(1000)], candidate: None },
        );

        // from 对不上当前选中
        assert!(accept(&mut s, mk(1, 0)).is_none());
        // 正常：待清的 IP 换成实际落地的 IP
        accept(&mut s, mk(0, 1)).unwrap();
        assert_eq!(HEALTH.lock_safe()[&rule.id].targets[0].flush_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(s.failover(rule.id).selected, 1);
        // 判挂且不在用的目标 0 要清，用规则当前的监听段
        let jobs = flush_jobs(&s, &HEALTH.lock_safe());
        assert_eq!(jobs.len(), 1);
        assert_eq!((jobs[0].2, jobs[0].3.target_ip, jobs[0].3.listen), (0, "10.0.0.1".parse().unwrap(), rule.listen));
        HEALTH.lock_safe().remove(&rule.id);

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
    fn down_marks_flush_until_recovered() {
        let mut t = TargetState { ip: Some("10.0.0.1".parse().unwrap()), ..Default::default() };
        t.record(Some(1000));
        t.record(Some(1000));
        for _ in 0..DOWN_AFTER {
            t.record(None);
        }
        assert_eq!(t.flush_ip, Some("10.0.0.1".parse().unwrap()));
        for _ in 0..UP_AFTER {
            t.record(Some(1000));
        }
        assert_eq!((t.health, t.flush_ip), (TargetHealth::Up, None));
    }

    #[test]
    fn flush_skips_selected_and_live_targets() {
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
        let rule = s.add_forward(req, tmpl.created_by, Utc::now());
        let ip = Some("10.0.0.1".parse().unwrap());
        let mut health = HashMap::new();
        // 在用的目标 0 判挂但没得切：不清（规则还指着它）。
        let both_down = |a: Option<Ipv4Addr>| {
            let mut d = down();
            d.flush_ip = a;
            d
        };
        health.insert(
            rule.id,
            RuleState { key: fingerprint(&rule), targets: vec![both_down(ip), both_down(None)], candidate: None },
        );
        assert!(flush_jobs(&s, &health).is_empty());
        // 按延迟切到 1 之后，0 才挂：要清 0。
        s.set_selected(rule.id, ForwardSwitch { at: Utc::now(), from: 0, to: 1, reason: SwitchReason::Latency });
        let jobs = flush_jobs(&s, &health);
        assert_eq!(jobs.iter().map(|j| j.2).collect::<Vec<_>>(), [0]);
        // 0 恢复了：不清。
        health.get_mut(&rule.id).unwrap().targets[0] = up(1000);
        assert!(flush_jobs(&s, &health).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn selected_out_of_range_is_noop() {
        let mut c = None;
        assert_eq!(decide(5, &[up(1)], &mut c, Instant::now()), None);
    }
}
