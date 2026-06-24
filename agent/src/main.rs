//! ipgate agent —— 运行在远程 Linux 主机上，落地 nftables 放行名单，并对客户端暴露 TLS API。
//!
//! - 面向内核的半边（ADR 0002）：ruleset 落地 + 对账（`nft`、`config`、`store`、`reconcile`）。
//! - 面向客户端的半边（ADR 0003）：TLS + 鉴权 + REST API（`tls`、`auth`、`api`）。

mod api;
mod auth;
mod config;
mod nft;
mod reconcile;
mod store;
mod tls;
mod util;

#[cfg(test)]
mod e2e;

use anyhow::{Context, Result};
use auth::AuthState;
use chrono::{Duration as ChronoDuration, Utc};
use clap::{Parser, Subcommand};
use config::AgentConfig;
use ipgate_proto::{AllowRequest, DeviceId, PAIRING_CODE_TTL_SECS};
use ipnet::IpNet;
use nft::{NftBackend, NftCli};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store::Store;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "ipgate-agent", version, about)]
struct Cli {
    /// 配置文件路径。
    #[arg(long, default_value = "/etc/ipgate/config.json")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 全功能守护进程：应用 ruleset + 后台对账 + TLS API 服务。
    Run {
        /// 对账间隔（秒）。
        #[arg(long, default_value_t = 30)]
        interval: u64,
    },
    /// 生成一次性配对码（供新设备入网），并打印服务端指纹。
    Pair,
    /// 离线放行一个 IP/CIDR（写存储；服务未运行时用，如安装时防自锁）。
    Allow {
        /// 目标 IP 或 CIDR，如 203.0.113.7/32。
        target: String,
        #[arg(long, default_value = "")]
        note: String,
        /// 过期秒数（默认永久）。
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    /// 离线撤销一个 IP/CIDR。
    Revoke {
        /// 目标 IP 或 CIDR。
        target: String,
    },
    /// 打印将要应用的 nftables ruleset（不改内核，便于审计）。
    PrintRuleset,
    /// 显示存储条目与内核 set 当前状态。
    Status,
    /// 卸载：flush 掉 `inet ipgate` 表。
    Uninstall,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let cfg = AgentConfig::load(&cli.config)?;

    match cli.cmd {
        Cmd::Run { interval } => run(cfg, interval)?,
        Cmd::Pair => pair(&cfg)?,
        Cmd::Allow {
            target,
            note,
            ttl_secs,
        } => allow_cli(&cfg, &target, &note, ttl_secs)?,
        Cmd::Revoke { target } => revoke_cli(&cfg, &target)?,
        Cmd::PrintRuleset => {
            let store = Store::load(&cfg.store_path())?;
            print!(
                "{}",
                nft::render_apply(&cfg.ruleset(), store.entries(), Utc::now())
            );
        }
        Cmd::Status => status(&cfg)?,
        Cmd::Uninstall => {
            NftCli::new().flush()?;
            println!("已删除 inet ipgate 表");
        }
    }
    Ok(())
}

fn pair(cfg: &AgentConfig) -> Result<()> {
    let identity = tls::load_or_generate(&cfg.data_dir)?;
    let code = auth::pairing::create(&cfg.data_dir, PAIRING_CODE_TTL_SECS, Utc::now())?;
    println!(
        "配对码（{} 分钟内有效、单次）：{}",
        PAIRING_CODE_TTL_SECS / 60,
        code.as_str()
    );
    println!("服务端指纹：{}", identity.fingerprint);
    println!("在客户端输入主机地址 + 上面的配对码，并核对指纹。");
    Ok(())
}

/// 离线放行：写存储 + 尽力即时落内核（服务未启动/表不存在则忽略）。
///
/// 注意：服务**运行中**请走 API；CLI 写的是磁盘存储，运行中的进程看不到，
/// 且其对账循环会把 CLI 直接加进内核的元素当作 stale 撤掉。本命令仅供离线/安装期。
fn allow_cli(cfg: &AgentConfig, target: &str, note: &str, ttl_secs: Option<u64>) -> Result<()> {
    let net: IpNet = target
        .parse()
        .with_context(|| format!("非法 IP/CIDR: {target}"))?;
    let now = Utc::now();
    let mut store = Store::load(&cfg.store_path())?;
    let expires_at = ttl_secs.map(|s| now + ChronoDuration::seconds(s as i64));
    // created_by 用 nil uuid 表示「控制台/离线」来源。
    let entry = store.allow(
        AllowRequest {
            target: net,
            note: note.to_owned(),
            expires_at,
        },
        DeviceId(Uuid::nil()),
        now,
    );
    store.save()?;
    let _ = NftCli::new().add(&entry);
    println!("已放行 {net}");
    Ok(())
}

fn revoke_cli(cfg: &AgentConfig, target: &str) -> Result<()> {
    let net: IpNet = target
        .parse()
        .with_context(|| format!("非法 IP/CIDR: {target}"))?;
    let mut store = Store::load(&cfg.store_path())?;
    if store.revoke_by_target(&net) {
        store.save()?;
        let _ = NftCli::new().remove(&net);
        println!("已撤销 {net}");
    } else {
        println!("名单中无 {net}");
    }
    Ok(())
}

fn run(cfg: AgentConfig, interval: u64) -> Result<()> {
    cfg.validate()?;
    // rustls（tls-rustls-no-provider）需要进程级 crypto provider。
    let _ = rustls::crypto::ring::default_provider().install_default();

    let identity = tls::load_or_generate(&cfg.data_dir)?;
    info!(fingerprint = %identity.fingerprint, "服务端 TLS 指纹（首次连接请核对）");

    let backend: Arc<dyn NftBackend + Send + Sync> = Arc::new(NftCli::new());
    let store = Arc::new(Mutex::new(Store::load(&cfg.store_path())?));

    // 启动即清过期 + 全量原子重建（坐实 default-drop 与管理端口放行不变量）。
    {
        let mut s = store.lock().unwrap();
        if !s.prune_expired(Utc::now()).is_empty() {
            s.save()?;
        }
        backend.apply(&cfg.ruleset(), s.entries())?;
    }
    info!("ruleset 已应用");

    let auth = Arc::new(AuthState::load_or_generate(&cfg.data_dir)?);
    let cfg = Arc::new(cfg);

    // 后台对账线程（阻塞式，独立于 async server）。
    {
        let (store, backend, cfg) = (store.clone(), backend.clone(), cfg.clone());
        std::thread::spawn(move || reconcile_loop(cfg, store, backend, interval));
    }

    let addr = cfg.bind;
    let state = api::AppState {
        cfg: cfg.clone(),
        store,
        backend,
        auth,
        fingerprint: identity.fingerprint.clone(),
    };
    info!(%addr, "启动 TLS API 服务");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(api::serve(state, identity, addr))
}

fn reconcile_loop(
    cfg: Arc<AgentConfig>,
    store: Arc<Mutex<Store>>,
    backend: Arc<dyn NftBackend + Send + Sync>,
    interval: u64,
) {
    loop {
        std::thread::sleep(Duration::from_secs(interval));
        let now = Utc::now();
        let entries = {
            let mut s = store.lock().unwrap();
            if !s.prune_expired(now).is_empty() {
                let _ = s.save();
            }
            s.entries().to_vec()
        };
        match backend.list() {
            Ok(kernel) => {
                let d = reconcile::diff(&entries, &kernel, now);
                if !d.is_empty() {
                    info!(
                        missing = d.missing_in_kernel.len(),
                        stale = d.stale_in_kernel.len(),
                        "对账：修正内核差异"
                    );
                }
                for target in &d.missing_in_kernel {
                    if let Some(entry) = entries.iter().find(|e| &e.target == target) {
                        let _ = backend.add(entry);
                    }
                }
                for target in &d.stale_in_kernel {
                    let _ = backend.remove(target);
                }
            }
            Err(e) => {
                warn!(error = %e, "对账读取内核失败，全量重建");
                let _ = backend.apply(&cfg.ruleset(), &entries);
            }
        }
    }
}

fn status(cfg: &AgentConfig) -> Result<()> {
    let store = Store::load(&cfg.store_path())?;
    println!(
        "存储条目：{}（修订 {}），设备：{}",
        store.entries().len(),
        store.revision(),
        store.devices().len()
    );
    for e in store.entries() {
        let exp = e
            .expires_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "永久".to_owned());
        println!("  {} [{}] 到期={}", e.target, e.note, exp);
    }

    match NftCli::new().list() {
        Ok(kernel) => {
            println!("内核元素：{}", kernel.len());
            for el in kernel {
                println!("  {}", el.target);
            }
        }
        Err(e) => println!("读取内核失败（需 root + nftables）：{e}"),
    }
    Ok(())
}
