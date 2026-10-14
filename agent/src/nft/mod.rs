//! nftables 落地层（ADR 0002）。
//!
//! 落地机制为 `nft` 子进程：写走 `nft -f -`（stdin 喂原子事务），读走 `nft -j`。
//! 业务逻辑只依赖 [`NftBackend`] trait，便于日后换 netlink 实现。

mod cli;
mod nat;
mod parse;
mod ruleset;

pub use cli::NftCli;
pub use nat::{render_nat_apply, render_nat_flush, ResolvedForward};
pub use parse::{parse_set_elements, parse_set_elements_text};
pub use ruleset::{add_element_script, delete_element_script, render_apply};

use ipgate_proto::{Entry, KernelElement, RulesetConfig};
use ipnet::IpNet;

/// nftables 落地后端。
///
/// 实现须保证两条不变量（ADR 0002 / 0003）：
/// - `apply` 原子重建 ruleset：default-drop 与管理端口放行在**同一事务**内生效。
/// - base chain 里管理端口的放行是**字面规则**、不来自任何用户可改的 set，
///   因此没有任何 `add`/`remove` 能把它移除。
pub trait NftBackend {
    /// 原子全量应用：重建 `inet ipgate` 的 table/set/chain 并载入当前条目。
    fn apply(&self, cfg: &RulesetConfig, entries: &[Entry]) -> anyhow::Result<()>;
    /// 增量放行一个条目。
    fn add(&self, entry: &Entry) -> anyhow::Result<()>;
    /// 增量撤销一个目标。
    fn remove(&self, target: &IpNet) -> anyhow::Result<()>;
    /// 读取内核 set 的当前元素（用于对账）。
    fn list(&self) -> anyhow::Result<Vec<KernelElement>>;
    /// 卸载：删除整张 `inet ipgate` 表。
    fn flush(&self) -> anyhow::Result<()>;
}

/// 整表 apply 后转发名单门的实际状态（ADR 0008）。
#[derive(Debug)]
pub enum Gate {
    /// 开关关闭，未渲染门链。
    Off,
    Active,
    /// 门开但带门 ruleset 被拒，已退回无门；附 nft 原始错误（区分「不支持」与临时故障）。
    Rejected(anyhow::Error),
}

impl Gate {
    pub fn active(&self) -> bool {
        matches!(self, Gate::Active)
    }
}

/// 整表应用 ruleset，返回转发名单门的实际状态。
///
/// 门开但带门 ruleset 加载失败（如老内核/老 nft 不认 `ct status`/`ct original`）时，
/// 告警并退回无门模板：事务原子，失败时内核仍是旧表，重试即回到已知良态——
/// 门的问题绝不能连带 input 链（SSH 入口、放行名单）落地失败。
pub fn apply_ruleset(
    backend: &dyn NftBackend,
    cfg: &RulesetConfig,
    entries: &[Entry],
) -> anyhow::Result<Gate> {
    if !cfg.forward_allowlist_only {
        backend.apply(cfg, entries)?;
        return Ok(Gate::Off);
    }
    match backend.apply(cfg, entries) {
        Ok(()) => Ok(Gate::Active),
        Err(e) => {
            tracing::warn!(error = %e, "转发名单门加载失败，退回无门 ruleset（转发对全网开放）");
            let ungated = RulesetConfig { forward_allowlist_only: false, ..cfg.clone() };
            backend.apply(&ungated, entries)?;
            Ok(Gate::Rejected(e))
        }
    }
}

/// 端口转发落地后端（独立于 [`NftBackend`]，对应 `ip ipgate_nat` 表）。
///
/// 与放行名单分两个 trait：转发是**整表全量重建**（规则少、且 DNS 重解析后需整体换），
/// 与放行名单的增量 add/remove 语义不同；分开也保证两张表互不耦合。
pub trait NatBackend {
    /// 原子全量应用：重建 `ip ipgate_nat` 表并载入所有（已解析的）转发规则。
    fn apply_nat(&self, forwards: &[ResolvedForward]) -> anyhow::Result<()>;
    /// 清空：删除整张 `ip ipgate_nat` 表（无转发时）。
    fn flush_nat(&self) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 记录每次 apply 的配置；`gate_ok=false` 模拟内核/nft 不认门链表达式（老内核/老 nft）。
    struct Recorder {
        gate_ok: bool,
        ungated_ok: bool,
        applied: Mutex<Vec<RulesetConfig>>,
    }

    impl Recorder {
        fn new(gate_ok: bool, ungated_ok: bool) -> Self {
            Self { gate_ok, ungated_ok, applied: Mutex::new(Vec::new()) }
        }
    }

    impl NftBackend for Recorder {
        fn apply(&self, cfg: &RulesetConfig, _entries: &[Entry]) -> anyhow::Result<()> {
            let ok = if cfg.forward_allowlist_only { self.gate_ok } else { self.ungated_ok };
            if !ok {
                anyhow::bail!("nft -f 失败");
            }
            self.applied.lock().unwrap().push(cfg.clone());
            Ok(())
        }
        fn add(&self, _: &Entry) -> anyhow::Result<()> {
            Ok(())
        }
        fn remove(&self, _: &IpNet) -> anyhow::Result<()> {
            Ok(())
        }
        fn list(&self) -> anyhow::Result<Vec<KernelElement>> {
            Ok(Vec::new())
        }
        fn flush(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn cfg(ssh: bool, fwd: bool) -> RulesetConfig {
        RulesetConfig { ssh_allowlist_only: ssh, forward_allowlist_only: fwd, ..RulesetConfig::default() }
    }

    #[test]
    fn gate_reported_active_when_kernel_accepts_it() {
        let b = Recorder::new(true, true);
        assert!(matches!(apply_ruleset(&b, &cfg(false, true), &[]).unwrap(), Gate::Active));
        assert_eq!(*b.applied.lock().unwrap(), vec![cfg(false, true)]);
    }

    #[test]
    fn gate_rejected_falls_back_to_ungated_ruleset() {
        // 门链加载失败不能连带 input 链（SSH 入口）一起失败：退回无门模板，其余开关原样保留。
        let b = Recorder::new(false, true);
        match apply_ruleset(&b, &cfg(true, true), &[]).unwrap() {
            Gate::Rejected(e) => assert!(e.to_string().contains("nft -f 失败"), "须保留 nft 原始错误"),
            g => panic!("期望 Rejected，得到 {g:?}"),
        }
        assert_eq!(*b.applied.lock().unwrap(), vec![cfg(true, false)]);
    }

    #[test]
    fn gate_off_applies_once_and_reports_inactive() {
        let b = Recorder::new(false, true);
        assert!(matches!(apply_ruleset(&b, &cfg(false, false), &[]).unwrap(), Gate::Off));
        assert_eq!(b.applied.lock().unwrap().len(), 1);
    }

    #[test]
    fn ungated_failure_still_surfaces_error() {
        let b = Recorder::new(false, false);
        assert!(apply_ruleset(&b, &cfg(false, true), &[]).is_err());
        assert!(apply_ruleset(&b, &cfg(false, false), &[]).is_err());
    }
}
