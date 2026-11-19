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
use std::sync::atomic::{AtomicBool, Ordering};

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

/// 整表 apply 后一项可选能力（转发名单门 ADR 0008 / SSH 敲门 ADR 0012）的实际状态。
#[derive(Debug)]
pub enum Gate {
    /// 未要求，没有渲染。
    Off,
    Active,
    /// 要求了但带它的 ruleset 被拒，已退回不带它的；附 nft 原始错误（区分「不支持」与临时故障）。
    Rejected(String),
}

impl Gate {
    pub fn active(&self) -> bool {
        matches!(self, Gate::Active)
    }
}

/// 整表 apply 的结果。
#[derive(Debug)]
pub struct Applied {
    pub gate: Gate,
    pub knock: Gate,
    /// 敲门日志（ADR 0012 决策 10）；被拒时只去日志，敲门照常。
    pub knock_log: Gate,
}

/// 最近一次整表 apply 后可选能力的生效态；RPC 与对账线程共享，供 `AgentSettings` 上报。
#[derive(Debug, Default)]
pub struct Live {
    pub gate: AtomicBool,
    pub knock: AtomicBool,
}

impl Live {
    pub fn record(&self, a: &Applied) {
        self.gate.store(a.gate.active(), Ordering::SeqCst);
        self.knock.store(a.knock.active(), Ordering::SeqCst);
    }
}

/// 整表应用 ruleset，返回各项可选能力（转发门、敲门、敲门日志）的实际状态。
///
/// 带可选能力的 ruleset 加载失败（如老内核/老 nft 不认 `ct status` 或 `@th` / 动态 set）时，
/// 告警并逐级退回：先只去敲门日志，再去敲门留门，再去门留敲门（同样先带日志），最后都去掉。
/// 事务原子，失败时内核仍是旧表——
/// 可选能力的问题绝不能连带 input 链（SSH 入口、放行名单）落地失败。
pub fn apply_ruleset(
    backend: &dyn NftBackend,
    cfg: &RulesetConfig,
    entries: &[Entry],
) -> anyhow::Result<Applied> {
    let want_gate = cfg.forward_allowlist_only;
    let want_knock = cfg.knock().is_some();
    let want_log = want_knock && cfg.ssh_knock_log;
    // nft 报错会回显出错的源码行；敲门规则那行带口令，进日志 / RPC 错误前先抹掉。
    let token = cfg.ssh_knock.as_ref().map(|k| crate::util::to_hex(&k.token));
    let redact = |e: anyhow::Error| {
        let s = format!("{e:#}");
        anyhow::anyhow!(match &token {
            Some(t) => s.replace(t.as_str(), "<token>"),
            None => s,
        })
    };
    let (k, l, g) = (want_knock, want_log, want_gate);
    let ladder = [
        (k, l, g),
        (k, false, g),
        (false, false, g),
        (k, l, false),
        (k, false, false),
        (false, false, false),
    ];
    let mut tried: Vec<(bool, bool, bool)> = Vec::new();
    let mut first_err: Option<anyhow::Error> = None;
    for cand in ladder {
        if tried.contains(&cand) {
            continue;
        }
        tried.push(cand);
        let (knock, log, gate) = cand;
        let c = RulesetConfig {
            forward_allowlist_only: gate,
            ssh_knock: if knock { cfg.ssh_knock.clone() } else { None },
            ssh_knock_log: log,
            ..cfg.clone()
        };
        match backend.apply(&c, entries).map_err(redact) {
            Ok(()) => {
                let reason = first_err.as_ref().map(|e| format!("{e:#}")).unwrap_or_default();
                let state = |want: bool, got: bool| match (want, got) {
                    (false, _) => Gate::Off,
                    (true, true) => Gate::Active,
                    (true, false) => Gate::Rejected(reason.clone()),
                };
                let applied = Applied {
                    gate: state(want_gate, gate),
                    knock: state(want_knock, knock),
                    // 敲门本身没了，日志无从谈起，不另报。
                    knock_log: if knock { state(want_log, log) } else { Gate::Off },
                };
                if let Gate::Rejected(e) = &applied.gate {
                    tracing::warn!(error = %e, "转发名单门加载失败，已退回无门 ruleset（转发对全网开放）");
                }
                if let Gate::Rejected(e) = &applied.knock {
                    tracing::warn!(error = %e, "SSH 敲门规则加载失败，已退回不带敲门的 ruleset（SSH 仅名单可连）");
                }
                if let Gate::Rejected(e) = &applied.knock_log {
                    tracing::warn!(error = %e, "敲门日志规则加载失败（常见原因：内核缺 nf_log_syslog），已去掉日志，敲门照常");
                }
                return Ok(applied);
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                } else if cand == (false, false, false) {
                    return Err(e);
                }
            }
        }
    }
    Err(first_err.expect("至少尝试过一次"))
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

    /// 记录每次 apply 的配置；`*_ok=false` 模拟内核/nft 不认对应表达式（老内核/老 nft）。
    struct Recorder {
        gate_ok: bool,
        knock_ok: bool,
        plain_ok: bool,
        /// false：模拟内核缺日志后端，带敲门日志的 ruleset 被拒。
        log_ok: bool,
        /// 每次成功 apply 的 (敲门, 敲门日志, 转发门)。
        applied: Mutex<Vec<(bool, bool, bool)>>,
    }

    impl Recorder {
        fn new(gate_ok: bool, knock_ok: bool, plain_ok: bool) -> Self {
            Self { gate_ok, knock_ok, plain_ok, log_ok: true, applied: Mutex::new(Vec::new()) }
        }
    }

    impl NftBackend for Recorder {
        fn apply(&self, cfg: &RulesetConfig, _entries: &[Entry]) -> anyhow::Result<()> {
            let (knock, gate) = (cfg.knock().is_some(), cfg.forward_allowlist_only);
            let log = knock && cfg.ssh_knock_log;
            let ok = self.plain_ok
                && (!gate || self.gate_ok)
                && (!knock || self.knock_ok)
                && (!log || self.log_ok);
            if !ok {
                anyhow::bail!("nft -f 失败");
            }
            self.applied.lock().unwrap().push((knock, log, gate));
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

    /// `ssh`：仅名单（带敲门参数）；`fwd`：转发名单门。
    fn cfg(ssh: bool, fwd: bool) -> RulesetConfig {
        RulesetConfig {
            ssh_allowlist_only: ssh,
            ssh_knock: Some(ipgate_proto::SshKnock { port: 40000, token: [1; 16] }),
            forward_allowlist_only: fwd,
            ..RulesetConfig::default()
        }
    }

    fn applied(b: &Recorder) -> Vec<(bool, bool, bool)> {
        b.applied.lock().unwrap().clone()
    }

    #[test]
    fn both_reported_active_when_kernel_accepts_them() {
        let b = Recorder::new(true, true, true);
        let a = apply_ruleset(&b, &cfg(true, true), &[]).unwrap();
        assert!(a.gate.active() && a.knock.active());
        assert!(a.knock_log.active());
        assert_eq!(applied(&b), vec![(true, true, true)]);
    }

    #[test]
    fn gate_rejected_falls_back_to_ungated_ruleset() {
        // 门链加载失败不能连带 input 链（SSH 入口）一起失败：退回无门模板，敲门原样保留。
        let b = Recorder::new(false, true, true);
        let a = apply_ruleset(&b, &cfg(true, true), &[]).unwrap();
        match a.gate {
            Gate::Rejected(e) => assert!(e.contains("nft -f 失败"), "须保留 nft 原始错误"),
            g => panic!("期望 Rejected，得到 {g:?}"),
        }
        assert!(a.knock.active());
        assert_eq!(applied(&b), vec![(true, true, false)]);
    }

    #[test]
    fn knock_rejected_keeps_gate_and_allowlist_only() {
        let b = Recorder::new(true, false, true);
        let a = apply_ruleset(&b, &cfg(true, true), &[]).unwrap();
        assert!(matches!(a.knock, Gate::Rejected(_)));
        assert!(a.gate.active());
        assert_eq!(applied(&b), vec![(false, false, true)]);
    }

    #[test]
    fn both_rejected_fall_back_to_plain() {
        let b = Recorder::new(false, false, true);
        let a = apply_ruleset(&b, &cfg(true, true), &[]).unwrap();
        assert!(matches!((&a.gate, &a.knock), (Gate::Rejected(_), Gate::Rejected(_))));
        assert_eq!(applied(&b), vec![(false, false, false)]);
    }

    #[test]
    fn log_rejected_keeps_knock_and_gate() {
        // 内核缺 nf_log_syslog：只去掉敲门日志，敲门与转发门照常（不能因日志丢了敲门）。
        let b = Recorder { log_ok: false, ..Recorder::new(true, true, true) };
        let a = apply_ruleset(&b, &cfg(true, true), &[]).unwrap();
        assert!(a.knock.active() && a.gate.active());
        assert!(matches!(a.knock_log, Gate::Rejected(_)));
        assert_eq!(applied(&b), vec![(true, false, true)]);
    }

    #[test]
    fn log_and_gate_rejected_keeps_knock() {
        let b = Recorder { log_ok: false, ..Recorder::new(false, true, true) };
        let a = apply_ruleset(&b, &cfg(true, true), &[]).unwrap();
        assert!(a.knock.active());
        assert!(matches!((&a.gate, &a.knock_log), (Gate::Rejected(_), Gate::Rejected(_))));
        assert_eq!(applied(&b), vec![(true, false, false)]);
    }

    #[test]
    fn nothing_optional_applies_once_and_reports_off() {
        let b = Recorder::new(false, false, true);
        let a = apply_ruleset(&b, &cfg(false, false), &[]).unwrap();
        assert!(matches!((a.gate, a.knock), (Gate::Off, Gate::Off)));
        assert_eq!(applied(&b).len(), 1);
    }

    #[test]
    fn knock_params_ignored_when_ssh_open() {
        // SSH 对全网开放时不渲染敲门，也就谈不上被拒。
        let b = Recorder::new(true, false, true);
        let a = apply_ruleset(&b, &cfg(false, true), &[]).unwrap();
        assert!(matches!(a.knock, Gate::Off));
        assert!(a.gate.active());
    }

    /// nft 报错回显的源码行带口令。
    struct EchoesToken;

    impl NftBackend for EchoesToken {
        fn apply(&self, cfg: &RulesetConfig, _entries: &[Entry]) -> anyhow::Result<()> {
            if cfg.knock().is_some() {
                anyhow::bail!("Error: syntax error\n@th,64,128 0x01010101010101010101010101010101 update @knock4");
            }
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

    #[test]
    fn rejection_reason_never_carries_knock_token() {
        let a = apply_ruleset(&EchoesToken, &cfg(true, false), &[]).unwrap();
        match a.knock {
            Gate::Rejected(e) => {
                assert!(!e.contains("0101010101010101"), "口令不得进错误原因：{e}");
                assert!(e.contains("<token>"));
            }
            g => panic!("期望 Rejected，得到 {g:?}"),
        }
    }

    #[test]
    fn plain_failure_still_surfaces_error() {
        let b = Recorder::new(false, false, false);
        assert!(apply_ruleset(&b, &cfg(true, true), &[]).is_err());
        assert!(apply_ruleset(&b, &cfg(false, false), &[]).is_err());
    }
}
