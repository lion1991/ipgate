//! nftables 落地层（ADR 0002）。
//!
//! 落地机制为 `nft` 子进程：写走 `nft -f -`（stdin 喂原子事务），读走 `nft -j`。
//! 业务逻辑只依赖 [`NftBackend`] trait，便于日后换 netlink 实现。

mod cli;
mod parse;
mod ruleset;

pub use cli::NftCli;
pub use parse::parse_set_elements;
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
