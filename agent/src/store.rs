//! 条目 / 设备的持久化存储（v1：单 JSON 文件）。
//!
//! 备注、过期时间等内核不保存的元数据以这里为权威；agent 对账时以此为期望态。

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ipgate_proto::{
    AddForwardRequest, AllowRequest, Device, DeviceId, Entry, EntryId, ForwardId, ForwardRule,
    NoisePublicKey, PublicPort,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// 容忍中毒的取锁扩展（P1 修复：防 Mutex 中毒级联）。
///
/// `std::sync::Mutex` 一旦某个持有者在临界区内 panic 即**永久中毒**，之后所有
/// `lock().unwrap()` 都会 panic。原先这会把对账线程（防火墙漂移自愈）、TTL 清理、
/// 以及每条 RPC 一起拖死，进程却仍卡在 `block_on` 不退出 → systemd 不重启、防火墙可能
/// fail-open。`lock_safe()` 在中毒时取回内层数据继续跑：Store 的变更要么是 Vec 增删、
/// 要么随后 `save()` 落盘，最坏只是一次半更新的内存态，远好于守护进程僵死。
pub trait LockExt<T> {
    fn lock_safe(&self) -> MutexGuard<'_, T>;
}

impl<T> LockExt<T> for Mutex<T> {
    fn lock_safe(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct State {
    pub entries: Vec<Entry>,
    pub devices: Vec<Device>,
    /// 放行名单单调递增修订号。
    pub revision: u64,
    /// 端口转发规则（独立于放行名单）。
    #[serde(default)]
    pub forwards: Vec<ForwardRule>,
    /// 端口转发单调递增修订号（与 `revision` 各自独立）。
    #[serde(default)]
    pub forward_revision: u64,
    /// 上次成功解析的转发目标 IP（域名解析失败时回退用，对齐动态域名诉求）。
    #[serde(default)]
    pub resolved: HashMap<ForwardId, Ipv4Addr>,
    /// SSH 端口是否仅对放行名单开放（ADR 0007）。默认 false=对所有人开放（防自锁）；
    /// 客户端可经 `SetSshExposure` 切换。运行期可调，故存这里而非静态 config.json。
    #[serde(default)]
    pub ssh_allowlist_only: bool,
    /// 转发名单门开关（ADR 0008）。默认 false=转发对全网开放（升级零行为变化）；
    /// 客户端可经 `SetForwardExposure` 切换。
    #[serde(default)]
    pub forward_allowlist_only: bool,
    /// 客户端添加的公开端口（与 config.json 里的合并落地）。
    #[serde(default)]
    pub public_ports: Vec<PublicPort>,
    /// 「放行所有 IP」（ADR 0013）；`None` = 关。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_all: Option<OpenAll>,
}

/// 「放行所有 IP」开着时的状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAll {
    /// 到期时间；`None` = 永久。到期由对账循环关闭。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
}

/// ruleset 的运行期设置（存 store），由 [`crate::config::AgentConfig::ruleset_with`] 注入渲染。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesetFlags {
    pub ssh_allowlist_only: bool,
    pub forward_allowlist_only: bool,
    pub public_ports: Vec<PublicPort>,
    pub open_all: bool,
}

/// 放行被拒的原因（见 [`Store::allow`]）。`Display` 即给用户看的提示。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowError {
    /// `0.0.0.0/0`、`::/0`：会绕过 SSH「仅名单」，改用「放行所有 IP」（ADR 0013）。
    AllAddresses,
    /// 已被这条覆盖。
    CoveredBy(IpNet),
    /// 会覆盖这些已有条目。
    Covers(Vec<IpNet>),
}

impl std::fmt::Display for AllowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 单地址不带 /32、/128，与客户端名单的显示一致。
        let show = |t: &IpNet| {
            if t.prefix_len() == t.max_prefix_len() {
                t.addr().to_string()
            } else {
                t.to_string()
            }
        };
        match self {
            Self::AllAddresses => {
                f.write_str("不能把所有地址加入名单（SSH 会随之对全网开放）。要对所有 IP 开放，请在 Mac 客户端的「安全」里打开「放行所有 IP」")
            }
            Self::CoveredBy(t) => write!(f, "已被 {} 覆盖，无需重复放行", show(t)),
            Self::Covers(ts) => {
                let list = ts.iter().map(show).collect::<Vec<_>>().join("、");
                let it = if ts.len() > 1 { "它们" } else { "它" };
                write!(f, "会覆盖已有的 {list}，请先撤销{it}")
            }
        }
    }
}

pub struct Store {
    path: PathBuf,
    state: State,
}

impl Store {
    /// 加载；文件不存在时返回空存储。
    pub fn load(path: &Path) -> Result<Self> {
        let state = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("读取存储失败: {}", path.display()))?;
            serde_json::from_str(&text).with_context(|| format!("解析存储失败: {}", path.display()))?
        } else {
            State::default()
        };
        Ok(Self {
            path: path.to_path_buf(),
            state,
        })
    }

    /// 原子写盘（temp + rename）。
    pub fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("创建目录失败: {}", dir.display()))?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.state)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn entries(&self) -> &[Entry] {
        &self.state.entries
    }

    pub fn revision(&self) -> u64 {
        self.state.revision
    }

    pub fn find_by_id(&self, id: EntryId) -> Option<&Entry> {
        self.state.entries.iter().find(|e| e.id == id)
    }

    // ---- 设备（authorized_keys 模型，ADR 0003）----

    pub fn devices(&self) -> &[Device] {
        &self.state.devices
    }

    /// 登记设备；同 id 或同公钥的旧记录会被替换。
    pub fn add_device(&mut self, device: Device) {
        self.state
            .devices
            .retain(|d| d.id != device.id && d.pubkey != device.pubkey);
        self.state.devices.push(device);
    }

    /// 按 Noise 静态公钥查设备（ADR 0007：握手鉴权用）。
    pub fn get_device_by_pubkey(&self, pubkey: &NoisePublicKey) -> Option<&Device> {
        self.state.devices.iter().find(|d| &d.pubkey == pubkey)
    }

    pub fn remove_device(&mut self, id: DeviceId) -> bool {
        let before = self.state.devices.len();
        self.state.devices.retain(|d| d.id != id);
        self.state.devices.len() != before
    }

    pub fn touch_device(&mut self, id: DeviceId, now: DateTime<Utc>) {
        if let Some(d) = self.state.devices.iter_mut().find(|d| d.id == id) {
            d.last_seen = Some(now);
        }
    }

    /// 新增放行；若该目标已存在则覆盖其元数据。返回最终条目。
    ///
    /// 与其它有效条目互相包含时拒绝：interval set 不接受重叠元素，增量添加与整表落地都会被 nft 拒。
    pub fn allow(
        &mut self,
        req: AllowRequest,
        by: DeviceId,
        now: DateTime<Utc>,
    ) -> Result<Entry, AllowError> {
        if req.target.prefix_len() == 0 {
            return Err(AllowError::AllAddresses);
        }
        let net = req.target.trunc();
        let others = || {
            self.state
                .entries
                .iter()
                .filter(|e| e.target != req.target && !e.is_expired(now))
                .map(|e| e.target)
        };
        if let Some(outer) = others().find(|t| t.trunc().contains(&net)) {
            return Err(AllowError::CoveredBy(outer));
        }
        let inner: Vec<IpNet> = others().filter(|t| net.contains(&t.trunc())).collect();
        if !inner.is_empty() {
            return Err(AllowError::Covers(inner));
        }
        self.state.entries.retain(|e| e.target != req.target);
        let entry = Entry {
            id: EntryId::new(),
            target: req.target,
            note: req.note,
            expires_at: req.expires_at,
            created_at: now,
            created_by: by,
        };
        self.state.entries.push(entry.clone());
        self.state.revision += 1;
        Ok(entry)
    }

    // ---- SSH 端口暴露模式（ADR 0007）----

    /// 设置 SSH 暴露模式；返回是否发生了变化（便于调用方决定是否需要重建 ruleset）。
    pub fn set_ssh_allowlist_only(&mut self, on: bool) -> bool {
        let changed = self.state.ssh_allowlist_only != on;
        self.state.ssh_allowlist_only = on;
        changed
    }

    // ---- 转发名单门（ADR 0008）----

    pub fn ruleset_flags(&self) -> RulesetFlags {
        RulesetFlags {
            ssh_allowlist_only: self.state.ssh_allowlist_only,
            forward_allowlist_only: self.state.forward_allowlist_only,
            public_ports: self.state.public_ports.clone(),
            // 已到期按关算：服务停着时的救援 CLI、到期后对账关掉之前的其它整表重建，都不能把它落回内核。
            open_all: self.state.open_all.is_some() && !self.open_all_expired(Utc::now()),
        }
    }

    pub fn public_ports(&self) -> &[PublicPort] {
        &self.state.public_ports
    }

    pub fn set_public_ports(&mut self, ports: Vec<PublicPort>) {
        self.state.public_ports = ports;
    }

    pub fn open_all(&self) -> Option<&OpenAll> {
        self.state.open_all.as_ref()
    }

    pub fn set_open_all(&mut self, v: Option<OpenAll>) {
        self.state.open_all = v;
    }

    /// 「放行所有 IP」开着且已到期（该由 agent 关掉）。
    pub fn open_all_expired(&self, now: DateTime<Utc>) -> bool {
        matches!(&self.state.open_all, Some(OpenAll { until: Some(t) }) if *t <= now)
    }

    /// 设置转发名单门；返回是否发生了变化。
    pub fn set_forward_allowlist_only(&mut self, on: bool) -> bool {
        let changed = self.state.forward_allowlist_only != on;
        self.state.forward_allowlist_only = on;
        changed
    }

    pub fn revoke_by_target(&mut self, target: &IpNet) -> bool {
        let before = self.state.entries.len();
        self.state.entries.retain(|e| &e.target != target);
        let removed = self.state.entries.len() != before;
        if removed {
            self.state.revision += 1;
        }
        removed
    }

    // ---- 端口转发（独立于放行名单，落地 `ip ipgate_nat` 表）----

    pub fn forwards(&self) -> &[ForwardRule] {
        &self.state.forwards
    }

    pub fn forward_revision(&self) -> u64 {
        self.state.forward_revision
    }

    pub fn find_forward(&self, id: ForwardId) -> Option<&ForwardRule> {
        self.state.forwards.iter().find(|f| f.id == id)
    }

    /// 新增转发；同 `(iface, listen)` 的旧规则被覆盖（避免同端口多条冲突的 DNAT）。
    pub fn add_forward(
        &mut self,
        req: AddForwardRequest,
        by: DeviceId,
        now: DateTime<Utc>,
    ) -> ForwardRule {
        self.state
            .forwards
            .retain(|f| !(f.iface == req.iface && f.listen == req.listen));
        let rule = ForwardRule {
            id: ForwardId::new(),
            proto: req.proto,
            iface: req.iface,
            listen: req.listen,
            dest_host: req.dest_host,
            dest_port: req.dest_port,
            source: req.source,
            note: req.note,
            created_at: now,
            created_by: by,
        };
        self.state.forwards.push(rule.clone());
        self.state.forward_revision += 1;
        rule
    }

    /// 原地修改规则，保留 id 与创建信息。目标变了就丢掉旧解析缓存——否则新域名解析失败时会回退到旧目标 IP。
    pub fn update_forward(&mut self, id: ForwardId, req: AddForwardRequest) -> Option<ForwardRule> {
        let rule = self.state.forwards.iter_mut().find(|f| f.id == id)?;
        if rule.dest_host != req.dest_host {
            self.state.resolved.remove(&id);
        }
        rule.proto = req.proto;
        rule.iface = req.iface;
        rule.listen = req.listen;
        rule.dest_host = req.dest_host;
        rule.dest_port = req.dest_port;
        rule.source = req.source;
        rule.note = req.note;
        let out = rule.clone();
        self.state.forward_revision += 1;
        Some(out)
    }

    pub fn remove_forward(&mut self, id: ForwardId) -> bool {
        let before = self.state.forwards.len();
        self.state.forwards.retain(|f| f.id != id);
        let removed = self.state.forwards.len() != before;
        if removed {
            self.state.resolved.remove(&id);
            self.state.forward_revision += 1;
        }
        removed
    }

    /// 上次成功解析到的目标 IP（域名解析失败时的回退源）。
    pub fn resolved_ip(&self, id: ForwardId) -> Option<Ipv4Addr> {
        self.state.resolved.get(&id).copied()
    }

    /// 整体替换解析缓存（调用方已把「解析失败时沿用旧值」合并进 map）。
    pub fn set_resolved(&mut self, map: HashMap<ForwardId, Ipv4Addr>) {
        self.state.resolved = map;
    }

    /// 删除所有已过期条目，返回被删目标。
    pub fn prune_expired(&mut self, now: DateTime<Utc>) -> Vec<IpNet> {
        let mut removed = Vec::new();
        self.state.entries.retain(|e| {
            if e.is_expired(now) {
                removed.push(e.target);
                false
            } else {
                true
            }
        });
        if !removed.is_empty() {
            self.state.revision += 1;
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(target: &str) -> AllowRequest {
        AllowRequest {
            target: target.parse().unwrap(),
            note: String::new(),
            expires_at: None,
        }
    }

    #[test]
    fn lock_safe_recovers_from_poison() {
        use std::sync::{Arc, Mutex};
        let m = Arc::new(Mutex::new(0u32));
        // 在持锁时 panic → 毒死该锁（模拟某个 handler 在临界区 panic）。
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("临界区内 panic");
        })
        .join();
        // 标准 lock() 此刻返回 Err(Poisoned)，原代码的 .unwrap() 会在这里级联 panic。
        assert!(m.lock().is_err(), "前置：锁应已中毒");
        // lock_safe 取回内层数据继续工作 —— 这正是防级联的关键。
        *m.lock_safe() = 42;
        assert_eq!(*m.lock_safe(), 42);
    }

    fn temp_store() -> Store {
        // 用 uuid 拼唯一临时路径，避免并行测试碰撞。
        let p = std::env::temp_dir().join(format!("ipgate-test-{}.json", EntryId::new()));
        Store::load(&p).unwrap()
    }

    #[test]
    fn allow_revoke_bump_revision() {
        let mut s = temp_store();
        let by = DeviceId::new();
        let now = Utc::now();
        s.allow(req("203.0.113.0/24"), by, now).unwrap();
        s.allow(req("198.51.100.7/32"), by, now).unwrap();
        assert_eq!(s.entries().len(), 2);
        assert_eq!(s.revision(), 2);

        assert!(s.revoke_by_target(&"203.0.113.0/24".parse().unwrap()));
        assert_eq!(s.entries().len(), 1);
        assert_eq!(s.revision(), 3);
        // 撤销不存在的目标不变更修订号
        assert!(!s.revoke_by_target(&"10.0.0.0/8".parse().unwrap()));
        assert_eq!(s.revision(), 3);
    }

    #[test]
    fn allow_same_target_overwrites() {
        let mut s = temp_store();
        let by = DeviceId::new();
        let now = Utc::now();
        s.allow(req("203.0.113.5/32"), by, now).unwrap();
        let mut r = req("203.0.113.5/32");
        r.note = "更新".into();
        s.allow(r, by, now).unwrap();
        assert_eq!(s.entries().len(), 1);
        assert_eq!(s.entries()[0].note, "更新");
    }

    #[test]
    fn allow_rejects_overlap() {
        // 回归：互相包含的条目会让 nft 拒绝增量添加与整表落地（ADR 0013「顺带发现」）。
        let mut s = temp_store();
        let by = DeviceId::new();
        let now = Utc::now();
        s.allow(req("203.0.113.0/24"), by, now).unwrap();
        s.allow(req("198.51.100.7/32"), by, now).unwrap();

        let e = s.allow(req("203.0.113.5/32"), by, now).unwrap_err();
        assert_eq!(e.to_string(), "已被 203.0.113.0/24 覆盖，无需重复放行");
        // 网段相同、写法不同也算覆盖。
        assert!(s.allow(req("203.0.113.9/24"), by, now).is_err());

        let e = s.allow(req("198.51.100.0/24"), by, now).unwrap_err();
        assert_eq!(e.to_string(), "会覆盖已有的 198.51.100.7，请先撤销它");
        let e = s.allow(req("192.0.0.0/2"), by, now).unwrap_err();
        assert_eq!(
            e.to_string(),
            "会覆盖已有的 203.0.113.0/24、198.51.100.7，请先撤销它们"
        );
        assert_eq!(s.entries().len(), 2, "被拒时不改存储");
        assert_eq!(s.revision(), 2);

        // 同目标照旧是覆盖更新；不同地址族互不影响。
        s.allow(req("203.0.113.0/24"), by, now).unwrap();
        s.allow(req("2001:db8::/32"), by, now).unwrap();
        assert_eq!(s.entries().len(), 3);
    }

    #[test]
    fn allow_rejects_all_addresses() {
        let mut s = temp_store();
        for t in ["0.0.0.0/0", "::/0"] {
            assert_eq!(s.allow(req(t), DeviceId::new(), Utc::now()), Err(AllowError::AllAddresses));
        }
        assert!(s.entries().is_empty());
    }

    #[test]
    fn open_all_state_compat_and_expiry() {
        let now = Utc::now();
        // 旧 state.json 没有该字段 → 关；关着时不写出该字段（落盘与旧版一致）。
        let st: State = serde_json::from_str(r#"{"entries":[],"devices":[],"revision":0}"#).unwrap();
        assert!(st.open_all.is_none());
        assert!(!serde_json::to_string(&st).unwrap().contains("open_all"));

        let mut s = temp_store();
        s.set_open_all(Some(OpenAll { until: None }));
        assert!(s.ruleset_flags().open_all);
        assert!(!s.open_all_expired(now), "永久不过期");
        s.set_open_all(Some(OpenAll { until: Some(now + chrono::Duration::minutes(1)) }));
        assert!(!s.open_all_expired(now));
        assert!(s.open_all_expired(now + chrono::Duration::minutes(1)));
        assert!(s.ruleset_flags().open_all);
        // 已到期、还没被对账关掉：渲染一律按关（回归：服务停着时救援 CLI 曾把过期开关重新落进内核）。
        s.set_open_all(Some(OpenAll { until: Some(now - chrono::Duration::seconds(1)) }));
        assert!(!s.ruleset_flags().open_all);
        s.set_open_all(None);
        assert!(!s.ruleset_flags().open_all);
    }

    #[test]
    fn allow_ignores_expired_overlap() {
        let mut s = temp_store();
        let by = DeviceId::new();
        let now = Utc::now();
        let mut old = req("203.0.113.0/24");
        old.expires_at = Some(now - chrono::Duration::minutes(1));
        s.allow(old, by, now - chrono::Duration::hours(1)).unwrap();
        s.allow(req("203.0.113.5/32"), by, now).unwrap();
    }

    #[test]
    fn prune_removes_only_expired() {
        let mut s = temp_store();
        let by = DeviceId::new();
        let now = Utc::now();
        let mut expiring = req("192.0.2.1/32");
        expiring.expires_at = Some(now - chrono::Duration::minutes(1));
        s.allow(expiring, by, now).unwrap();
        s.allow(req("192.0.2.2/32"), by, now).unwrap();

        let removed = s.prune_expired(now);
        assert_eq!(removed, vec!["192.0.2.1/32".parse::<IpNet>().unwrap()]);
        assert_eq!(s.entries().len(), 1);
    }

    fn fwd_req(listen: u16, host: &str, iface: Option<&str>) -> AddForwardRequest {
        use ipgate_proto::{ForwardProto, ForwardSource, PortRange};
        AddForwardRequest {
            proto: ForwardProto::Tcp,
            iface: iface.map(|s| s.to_string()),
            listen: PortRange::single(listen),
            dest_host: host.to_string(),
            dest_port: PortRange::single(listen),
            source: ForwardSource::Auto,
            note: String::new(),
        }
    }

    #[test]
    fn add_forward_dedupes_same_iface_and_listen() {
        let mut s = temp_store();
        let by = DeviceId::new();
        let now = Utc::now();
        s.add_forward(fwd_req(443, "a.com", Some("eth0")), by, now);
        // 同 (iface, listen) 覆盖
        let r = s.add_forward(fwd_req(443, "b.com", Some("eth0")), by, now);
        assert_eq!(s.forwards().len(), 1);
        assert_eq!(s.forwards()[0].dest_host, "b.com");
        assert_eq!(s.forward_revision(), 2);

        // 不同网卡同端口并存
        s.add_forward(fwd_req(443, "c.com", Some("eth1")), by, now);
        assert_eq!(s.forwards().len(), 2);

        assert!(s.remove_forward(r.id));
        assert_eq!(s.forwards().len(), 1);
        assert!(!s.remove_forward(r.id));
    }

    #[test]
    fn resolved_cache_roundtrips() {
        let mut s = temp_store();
        let r = s.add_forward(fwd_req(80, "x.com", None), DeviceId::new(), Utc::now());
        assert_eq!(s.resolved_ip(r.id), None);
        let mut m = std::collections::HashMap::new();
        m.insert(r.id, "10.0.0.9".parse().unwrap());
        s.set_resolved(m);
        assert_eq!(s.resolved_ip(r.id), Some("10.0.0.9".parse().unwrap()));
        // 删除规则同时清缓存
        s.remove_forward(r.id);
        assert_eq!(s.resolved_ip(r.id), None);
    }

    #[test]
    fn update_forward_keeps_identity_and_drops_stale_resolved() {
        let mut s = temp_store();
        let r = s.add_forward(fwd_req(80, "x.com", None), DeviceId::new(), Utc::now());
        let ip: Ipv4Addr = "10.0.0.9".parse().unwrap();
        s.set_resolved([(r.id, ip)].into());

        // 只改端口：解析缓存保留
        let u = s.update_forward(r.id, fwd_req(8080, "x.com", None)).unwrap();
        assert_eq!((u.id, u.created_at, u.created_by), (r.id, r.created_at, r.created_by));
        assert_eq!(u.listen, ipgate_proto::PortRange::single(8080));
        assert_eq!(s.resolved_ip(r.id), Some(ip));
        assert_eq!(s.forward_revision(), 2);

        // 改目标：旧解析缓存作废
        s.update_forward(r.id, fwd_req(8080, "y.com", None)).unwrap();
        assert_eq!(s.forwards()[0].dest_host, "y.com");
        assert_eq!(s.resolved_ip(r.id), None);

        assert!(s.update_forward(ForwardId::new(), fwd_req(1, "z.com", None)).is_none());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let p = std::env::temp_dir().join(format!("ipgate-test-{}.json", EntryId::new()));
        {
            let mut s = Store::load(&p).unwrap();
            s.allow(req("203.0.113.0/24"), DeviceId::new(), Utc::now()).unwrap();
            s.save().unwrap();
        }
        let reloaded = Store::load(&p).unwrap();
        assert_eq!(reloaded.entries().len(), 1);
        assert_eq!(reloaded.revision(), 1);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn legacy_state_loads_with_forward_gate_off() {
        // 升级前的 state.json 没有该字段：必须读成「门关」，否则升级会突然断掉在用的转发。
        let p = std::env::temp_dir().join(format!("ipgate-test-{}.json", EntryId::new()));
        std::fs::write(&p, r#"{"entries":[],"devices":[],"revision":0,"ssh_allowlist_only":true}"#)
            .unwrap();
        let s = Store::load(&p).unwrap();
        assert_eq!(
            s.ruleset_flags(),
            RulesetFlags { ssh_allowlist_only: true, ..RulesetFlags::default() }
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn forward_gate_flag_reports_change_and_persists() {
        let p = std::env::temp_dir().join(format!("ipgate-test-{}.json", EntryId::new()));
        {
            let mut s = Store::load(&p).unwrap();
            assert!(s.set_forward_allowlist_only(true));
            assert!(!s.set_forward_allowlist_only(true));
            s.save().unwrap();
        }
        let s = Store::load(&p).unwrap();
        assert!(s.ruleset_flags().forward_allowlist_only);
        assert!(!s.ruleset_flags().ssh_allowlist_only);
        let _ = std::fs::remove_file(&p);
    }
}
