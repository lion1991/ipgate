//! dnat 适配器（ADR 0006，排空模型）。
//!
//! ipgate 客户端统一**查看/删除**本机 dnat 工具创建的转发；**新增走 native**
//! (`ip ipgate_nat`，ADR 0005)。配合逐条「迁移到 agent」把 dnat 渐进排空，
//! 最终该机 native 独占；dnat 工具在别的机器照常独立活。
//!
//! dnat 仍是 `dnat_utils` 表的**唯一落地者**：本适配器只动 dnat 的 conf 文件
//! （持 `conf.lock` 与 dnat 互斥）再触发 `dnat apply`，**绝不直接写内核**——
//! 否则 dnat daemon 每 60s 从 conf 重建会把改动冲掉（ADR 0006）。

mod conf;
mod lock;

pub use conf::DnatRule;

use anyhow::{bail, Context, Result};
use ipgate_proto::{
    AddForwardRequest, DeviceId, ForwardCaps, ForwardId, ForwardOrigin, ForwardProto,
    UnifiedForwardView,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;

/// dnat 适配配置（接进 `AgentConfig.dnat`）。默认**关**。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnatAdapterConfig {
    /// 是否启用：纳入 dnat 规则到统一列表、允许删除/迁移。默认 false。
    pub enabled: bool,
    /// dnat 基目录（`conf`/`state.json`/`conf.lock` 都在此，对应 dnat 的 `/etc/dnat`）。
    pub base_dir: PathBuf,
    /// dnat 二进制路径（触发 `dnat apply`，对应 dnat install 落地的 `/usr/local/bin/dnat`）。
    pub bin: PathBuf,
}

impl Default for DnatAdapterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_dir: PathBuf::from("/etc/dnat"),
            bin: PathBuf::from("/usr/local/bin/dnat"),
        }
    }
}

/// 删除/操作键：native 按 [`ForwardId`]；dnat 按 PrefixKey（`端口段>网卡>`）。
/// 主要供 [`ForwardBackend`] trait 表意；handler 直接用 [`DnatAdapter`] 的固有方法。
// 文档化抽象：native 后端尚未套 trait，故暂未被生产路径引用（ADR 0006）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardKey {
    Ipgate(ForwardId),
    Dnat(String),
}

/// 排空模型下的转发后端抽象。
/// - native 后端：实现全套（现走 `forward.rs` + `ip ipgate_nat`，暂未套此 trait）。
/// - [`DnatAdapter`]：只读 + 删（`upsert` 拒绝，新增走 native）。
// 文档化抽象：handler 现用 DnatAdapter 固有方法，native 套 trait 后此抽象即被引用（ADR 0006）。
#[allow(dead_code)]
pub trait ForwardBackend: Send + Sync {
    fn origin(&self) -> ForwardOrigin;
    /// 本后端在该机是否可用。
    fn present(&self) -> bool {
        true
    }
    /// 列出本后端管理的转发（统一视图；`conflict` 由 handler 跨来源回填）。
    fn list(&self) -> Result<Vec<UnifiedForwardView>>;
    /// 删除一条。
    fn remove(&self, key: &ForwardKey) -> Result<bool>;
    /// 新增。[`DnatAdapter`] **不支持**（排空模型：加走 native）。
    fn upsert(&self, req: &AddForwardRequest, by: DeviceId) -> Result<ForwardKey>;
}

/// 把 dnat PrefixKey 编码为 URL 安全的键（含 `>`，故 base64url）。
pub fn encode_key(prefix: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(prefix.as_bytes())
}

/// 还原 URL 安全键为 dnat PrefixKey；非法则 `None`。
pub fn decode_key(key: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key)
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// dnat 适配器：读 dnat conf/state，按 PrefixKey 删行 + 触发 `dnat apply`。
pub struct DnatAdapter {
    cfg: DnatAdapterConfig,
}

impl DnatAdapter {
    pub fn new(cfg: DnatAdapterConfig) -> Self {
        Self { cfg }
    }

    fn conf_path(&self) -> PathBuf {
        self.cfg.base_dir.join("conf")
    }
    fn state_path(&self) -> PathBuf {
        self.cfg.base_dir.join("state.json")
    }
    fn conf_lock_path(&self) -> PathBuf {
        self.cfg.base_dir.join("conf.lock")
    }

    /// 该机是否启用且 dnat 实际在位（二进制 + conf 目录）。
    pub fn present(&self) -> bool {
        self.cfg.enabled && self.cfg.base_dir.is_dir() && self.cfg.bin.exists()
    }

    /// 读 conf 全部规则（迁移取原始规则、CLI、list 复用）。
    pub fn rules(&self) -> Vec<DnatRule> {
        conf::parse_conf(&std::fs::read_to_string(self.conf_path()).unwrap_or_default())
    }

    /// 按 PrefixKey 找一条规则（迁移用）。
    pub fn find_rule_by_prefix(&self, prefix: &str) -> Option<DnatRule> {
        self.rules().into_iter().find(|r| r.prefix_key() == prefix)
    }

    /// 列出 dnat 转发为统一视图（`conflict` 留给 handler 跨来源回填）。
    pub fn list(&self) -> Vec<UnifiedForwardView> {
        let conf_text = std::fs::read_to_string(self.conf_path()).unwrap_or_default();
        let state =
            conf::parse_state(&std::fs::read_to_string(self.state_path()).unwrap_or_default());

        let mut out = Vec::new();
        for r in conf::parse_conf(&conf_text) {
            let entry = state.find(r.listen.start, &r.iface);
            let resolved_ip = entry.and_then(|e| e.remote_ip.parse::<Ipv4Addr>().ok());
            // active = 该条在 state.json 有已解析项（dnat 仅在成功 apply 后写 entries）。
            // 不按全局 lastError 判：单次失败 tick 会保留旧 entries 且不 flush 内核，
            // 按全局 error 会把所有仍在生效的转发误标为 inactive（评审）。
            let active = entry.is_some();
            let dnat_key = Some(encode_key(&r.prefix_key()));
            out.push(UnifiedForwardView {
                origin: ForwardOrigin::Dnat,
                proto: ForwardProto::Both, // dnat 永远 tcp+udp
                iface: Some(r.iface),
                listen: r.listen,
                dest_host: r.remote_host,
                dest_port: r.dest_port,
                source: r.source,
                note: String::new(),
                resolved_ip,
                active,
                caps: ForwardCaps {
                    can_edit: false,
                    can_delete: true,
                    can_migrate: true,
                },
                conflict: false,
                id: None,
                dnat_key,
            });
        }
        out
    }

    /// 按 PrefixKey **精确**删除一条（改 conf + 触发 apply）。返回是否删到。
    pub fn remove_prefix(&self, prefix: &str) -> Result<bool> {
        let removed;
        {
            // 读-改-写全程持 conf.lock，与 dnat daemon/TUI 互斥。
            let _guard = lock::FileLock::acquire(&self.conf_lock_path())?;
            let conf_text = std::fs::read_to_string(self.conf_path()).unwrap_or_default();
            let (new_text, did) = conf::remove_rule_lines(&conf_text, prefix);
            removed = did;
            if removed {
                self.write_conf_atomic(&new_text)?;
            }
        } // 锁在此释放；apply 不需持 conf.lock（dnat apply 自取 apply.lock）。
        if removed {
            // conf 是真源：写成功即「删除已提交」（dnat daemon ≤60s 内对账落地）。
            // 故即时 apply 失败**不致命**——记日志，别把已提交的删除误报成 500（评审）。
            if let Err(e) = self.run_apply() {
                tracing::warn!(error = %e, "dnat: 删除已写入 conf，但即时 apply 失败（dnat daemon 将在下次对账落地）");
            }
        }
        Ok(removed)
    }

    /// 触发 dnat 立即应用（同步；它自己拿 apply.lock）。
    /// `unchanged`/`applied` 均 exit 0；非零=失败带 stderr。
    pub fn run_apply(&self) -> Result<()> {
        let out = Command::new(&self.cfg.bin)
            .arg("apply")
            .arg("--conf")
            .arg(self.conf_path())
            .output()
            .with_context(|| format!("执行 {} apply 失败", self.cfg.bin.display()))?;
        if !out.status.success() {
            bail!(
                "dnat apply 失败: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// 原子写 conf：tmp + rename（与 dnat 同语义）。调用方须已持 conf.lock。
    fn write_conf_atomic(&self, text: &str) -> Result<()> {
        let path = self.conf_path();
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text).with_context(|| format!("写 {} 失败", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("rename 到 {} 失败", path.display()))?;
        Ok(())
    }
}

impl ForwardBackend for DnatAdapter {
    fn origin(&self) -> ForwardOrigin {
        ForwardOrigin::Dnat
    }
    fn present(&self) -> bool {
        DnatAdapter::present(self)
    }
    fn list(&self) -> Result<Vec<UnifiedForwardView>> {
        Ok(DnatAdapter::list(self))
    }
    fn remove(&self, key: &ForwardKey) -> Result<bool> {
        match key {
            ForwardKey::Dnat(p) => self.remove_prefix(p),
            ForwardKey::Ipgate(_) => bail!("dnat 适配器只能删 dnat 规则"),
        }
    }
    fn upsert(&self, _req: &AddForwardRequest, _by: DeviceId) -> Result<ForwardKey> {
        bail!("排空模型：dnat 适配器不接受新增，请走 native 后端（ip ipgate_nat）");
    }
}

/// 把一条 dnat 规则映射成 native 新增请求（「迁移到 agent」用）。
///
/// **无损**：dnat 永远 tcp+udp → [`ForwardProto::Both`]；dnat 无 id/note 可丢。
pub fn dnat_rule_to_add_request(r: &DnatRule) -> AddForwardRequest {
    AddForwardRequest {
        proto: ForwardProto::Both,
        iface: Some(r.iface.clone()),
        listen: r.listen,
        dest_host: r.remote_host.clone(),
        dest_port: r.dest_port,
        source: r.source,
        note: "迁移自 dnat".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipgate_proto::{ForwardSource, PortRange};

    #[test]
    fn disabled_adapter_not_present() {
        let a = DnatAdapter::new(DnatAdapterConfig::default()); // enabled=false
        assert!(!a.present());
        assert_eq!(ForwardBackend::origin(&a), ForwardOrigin::Dnat);
    }

    #[test]
    fn upsert_rejected_drain_model() {
        let a = DnatAdapter::new(DnatAdapterConfig::default());
        let req = AddForwardRequest {
            proto: ForwardProto::Tcp,
            iface: Some("eth0".into()),
            listen: PortRange::single(80),
            dest_host: "1.2.3.4".into(),
            dest_port: PortRange::single(80),
            source: ForwardSource::Auto,
            note: String::new(),
        };
        assert!(a.upsert(&req, DeviceId::new()).is_err());
    }

    #[test]
    fn key_round_trips() {
        let prefix = "8000-8010>eth0>";
        let k = encode_key(prefix);
        assert!(!k.contains('>')); // URL 安全
        assert_eq!(decode_key(&k).as_deref(), Some(prefix));
        assert!(decode_key("not*valid*b64").is_none());
    }

    #[test]
    fn remove_prefix_exact_match_no_overdelete() {
        // 临时 conf 目录；bin 不存在 → apply 走 best-effort（失败仅记日志，不致命）。
        let dir = std::env::temp_dir().join(format!("ipgate-dnat-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("conf");
        std::fs::write(&conf, "443>eth0>1.2.3.4:8443>auto\n4430>eth0>1.2.3.4:9000>auto\n").unwrap();
        let a = DnatAdapter::new(DnatAdapterConfig {
            enabled: true,
            base_dir: dir.clone(),
            bin: dir.join("no-such-dnat"),
        });

        // 部分前缀（评审 CRITICAL）：不删任何行。
        assert!(!a.remove_prefix("44").unwrap());
        assert_eq!(std::fs::read_to_string(&conf).unwrap().lines().count(), 2);

        // 精确 PrefixKey：只删那一条，4430 那条保留。
        assert!(a.remove_prefix("443>eth0>").unwrap());
        let rest = std::fs::read_to_string(&conf).unwrap();
        assert!(!rest.contains("443>eth0>1.2.3.4:8443"));
        assert!(rest.contains("4430>eth0>"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrate_mapping_is_both_and_keeps_fields() {
        let r = DnatRule {
            listen: PortRange { start: 8000, end: 8010 },
            iface: "eth1".into(),
            remote_host: "ex.com".into(),
            dest_port: PortRange { start: 9000, end: 9010 },
            source: ForwardSource::Ip("10.0.0.5".parse().unwrap()),
        };
        let req = dnat_rule_to_add_request(&r);
        assert_eq!(req.proto, ForwardProto::Both);
        assert_eq!(req.iface.as_deref(), Some("eth1"));
        assert_eq!(req.listen, r.listen);
        assert_eq!(req.dest_port, r.dest_port);
        assert_eq!(req.source, r.source);
        assert_eq!(req.dest_host, "ex.com");
    }
}
