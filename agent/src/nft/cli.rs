//! `nft` 子进程后端：[`NftBackend`] 的真实实现。

use super::{
    add_element_script, delete_element_script, parse_set_elements, parse_set_elements_text,
    render_apply, NftBackend,
};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use ipgate_proto::{Entry, KernelElement, RulesetConfig, NFT_SET_ALLOW4, NFT_SET_ALLOW6, NFT_TABLE};
use ipnet::IpNet;
use std::process::Command;

/// 通过 `nft` 命令行操作内核（ADR 0002）。绝不经过 shell，杜绝注入。
pub struct NftCli {
    bin: String,
}

impl Default for NftCli {
    fn default() -> Self {
        Self::new()
    }
}

impl NftCli {
    pub fn new() -> Self {
        Self { bin: "nft".to_owned() }
    }

    /// 把一段 ruleset 脚本写入临时文件后 `nft -f <file>`（整段仍原子）。
    ///
    /// 用临时文件而非 stdin（`-f -`）：老版本 nft（如 el7 的 0.8）不支持从 stdin 读，
    /// 临时文件在新旧版本上都可用。
    fn run_script(&self, script: &str) -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "ipgate-nft-{}.nft",
            crate::util::to_hex(&crate::util::random_bytes::<8>())
        ));
        crate::util::write_private(&path, script.as_bytes())
            .with_context(|| format!("写临时 ruleset 失败: {}", path.display()))?;
        let out = Command::new(&self.bin)
            .arg("-f")
            .arg(&path)
            .output()
            .with_context(|| format!("无法执行 {}", self.bin));
        let _ = std::fs::remove_file(&path);
        let out = out?;
        if !out.status.success() {
            bail!("nft -f 失败: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    /// 跑一条 `nft` 命令并捕获 stdout（用于读取/list）。
    fn run_capture(&self, args: &[&str]) -> Result<String> {
        let out = Command::new(&self.bin)
            .args(args)
            .output()
            .with_context(|| format!("无法执行 {}", self.bin))?;
        if !out.status.success() {
            bail!(
                "nft {} 失败: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl NftBackend for NftCli {
    fn apply(&self, cfg: &RulesetConfig, entries: &[Entry]) -> Result<()> {
        self.run_script(&render_apply(cfg, entries, Utc::now()))
    }

    fn add(&self, entry: &Entry) -> Result<()> {
        self.run_script(&add_element_script(
            &entry.target,
            entry.expires_at,
            Utc::now(),
        ))
    }

    fn remove(&self, target: &IpNet) -> Result<()> {
        self.run_script(&delete_element_script(target))
    }

    fn list(&self) -> Result<Vec<KernelElement>> {
        let now = Utc::now();
        let mut all = Vec::new();
        for set in [NFT_SET_ALLOW4, NFT_SET_ALLOW6] {
            match self.run_capture(&["-j", "list", "set", "inet", NFT_TABLE, set]) {
                Ok(json) => all.extend(parse_set_elements(&json, now)?),
                // 老 nft（el7 的 0.8）不认 `-j` → 退化解析纯文本输出。
                Err(_) => {
                    let text = self.run_capture(&["list", "set", "inet", NFT_TABLE, set])?;
                    all.extend(parse_set_elements_text(&text, now)?);
                }
            }
        }
        Ok(all)
    }

    fn flush(&self) -> Result<()> {
        self.run_script(&format!("delete table inet {NFT_TABLE}"))
    }
}
