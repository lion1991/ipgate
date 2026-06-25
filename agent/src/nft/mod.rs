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
