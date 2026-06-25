//! 条目 / 设备的持久化存储（v1：单 JSON 文件）。
//!
//! 备注、过期时间等内核不保存的元数据以这里为权威；agent 对账时以此为期望态。

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ipgate_proto::{
    AddForwardRequest, AllowRequest, Device, DeviceId, Entry, EntryId, ForwardId, ForwardRule,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

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

    pub fn get_device(&self, id: DeviceId) -> Option<&Device> {
        self.state.devices.iter().find(|d| d.id == id)
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
    pub fn allow(&mut self, req: AllowRequest, by: DeviceId, now: DateTime<Utc>) -> Entry {
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
        entry
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
        s.allow(req("203.0.113.0/24"), by, now);
        s.allow(req("198.51.100.7/32"), by, now);
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
        s.allow(req("203.0.113.5/32"), by, now);
        let mut r = req("203.0.113.5/32");
        r.note = "更新".into();
        s.allow(r, by, now);
        assert_eq!(s.entries().len(), 1);
        assert_eq!(s.entries()[0].note, "更新");
    }

    #[test]
    fn prune_removes_only_expired() {
        let mut s = temp_store();
        let by = DeviceId::new();
        let now = Utc::now();
        let mut expiring = req("192.0.2.1/32");
        expiring.expires_at = Some(now - chrono::Duration::minutes(1));
        s.allow(expiring, by, now);
        s.allow(req("192.0.2.2/32"), by, now);

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
    fn save_then_load_roundtrips() {
        let p = std::env::temp_dir().join(format!("ipgate-test-{}.json", EntryId::new()));
        {
            let mut s = Store::load(&p).unwrap();
            s.allow(req("203.0.113.0/24"), DeviceId::new(), Utc::now());
            s.save().unwrap();
        }
        let reloaded = Store::load(&p).unwrap();
        assert_eq!(reloaded.entries().len(), 1);
        assert_eq!(reloaded.revision(), 1);
        let _ = std::fs::remove_file(&p);
    }
}
