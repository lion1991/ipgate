//! ipgate agent —— 运行在远程 Linux 主机上，落地 nftables 放行名单，并对客户端暴露 TLS API。
//!
//! - 面向内核的半边（ADR 0002）：ruleset 落地 + 对账（`nft`、`config`、`store`、`reconcile`）。
//! - 面向客户端的半边（ADR 0003）：TLS + 鉴权 + REST API（`tls`、`auth`、`api`）。

mod api;
mod auth;
mod config;
mod dnat;
mod forward;
mod netinfo;
mod nft;
mod noise;
mod reconcile;
mod resolve;
mod sshd;
mod store;
mod util;

#[cfg(test)]
mod e2e;

use anyhow::{Context, Result};
use auth::AuthState;
use chrono::{Duration as ChronoDuration, Utc};
use clap::{Parser, Subcommand};
use config::AgentConfig;
use ipgate_proto::{
    AddForwardRequest, AllowRequest, DeviceId, ForwardId, ForwardProto, ForwardSource, PortRange,
    PAIRING_CODE_TTL_SECS,
};
use ipnet::IpNet;
use nft::{NatBackend, NftBackend, NftCli};
use std::net::{Ipv4Addr, SocketAddr};
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
    Pair {
        /// 额外渲染配对二维码（移动端「扫码配对」一步入网，含指纹 + 口令）。
        #[arg(long)]
        qr: bool,
        /// 写进二维码的主机地址（域名或 IP，客户端用它连接）。`--qr` 时必填。
        #[arg(long)]
        host: Option<String>,
        /// 写进二维码的端口；缺省取 config 的 mgmt_port。
        #[arg(long)]
        port: Option<u16>,
    },
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
    /// 打印（或重置）管理端口访问密钥。
    AccessKey {
        /// 重置为新密钥（旧客户端需用新密钥重配对；运行中的服务需 restart 才生效）。
        #[arg(long)]
        reset: bool,
    },
    /// 列出端口转发规则（存储态 + 当前解析 IP）。
    Forwards,
    /// 新增/更新端口转发（离线写存储 + 尽力即时落地）。同 `(网卡, 监听端口)` 覆盖。
    ForwardAdd {
        /// 本地监听端口或区间，如 443 或 8000-8010。
        #[arg(long)]
        listen: String,
        /// 目标 host:port，如 10.0.0.9:8443 或 ex.com:9000-9010（host 可为域名）。
        #[arg(long)]
        dest: String,
        /// 协议：tcp | udp | both。
        #[arg(long, default_value = "tcp")]
        proto: String,
        /// 入口网卡；缺省用默认路由网卡。
        #[arg(long)]
        iface: Option<String>,
        /// SNAT 源：auto 或具体 IPv4。
        #[arg(long, default_value = "auto")]
        source: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// 删除端口转发（按 id，见 `forwards` 输出）。
    ForwardRm {
        /// 规则 id（uuid）。
        id: String,
    },
    /// 列出本机 dnat 工具创建的转发（ADR 0006 排空模型）。
    DnatForwards,
    /// 迁移一条 dnat 规则到 native（先建 native(-90) 再删 dnat(-100)，零瞬断）。
    DnatMigrate {
        /// 本地监听端口或区间，如 443 或 8000-8010。
        #[arg(long)]
        listen: String,
        /// 入口网卡（dnat 规则总带具体网卡名）。
        #[arg(long)]
        iface: String,
    },
    /// 删除一条 dnat 规则（改 dnat conf + 触发 `dnat apply`）。
    DnatRm {
        /// 本地监听端口或区间。
        #[arg(long)]
        listen: String,
        /// 入口网卡。
        #[arg(long)]
        iface: String,
    },
    /// 切换 SSH 端口暴露模式（控制台救援用）：写存储 + 立刻重建 ruleset。
    ///
    /// 自锁恢复：若误把 SSH 收成「仅名单」而当前 IP 不在名单、连不上了，从 VPS 控制台跑
    /// `ipgate-agent ssh-expose --open` 即可放开。运行中的服务建议随后 restart 同步内存态。
    SshExpose {
        /// 对所有人开放 SSH（解除「仅名单」自锁）。
        #[arg(long, conflicts_with = "allowlist")]
        open: bool,
        /// 仅放行名单内源 IP 可连 SSH。
        #[arg(long)]
        allowlist: bool,
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
        Cmd::Pair { qr, host, port } => pair(&cfg, qr, host, port)?,
        Cmd::Allow {
            target,
            note,
            ttl_secs,
        } => allow_cli(&cfg, &target, &note, ttl_secs)?,
        Cmd::Revoke { target } => revoke_cli(&cfg, &target)?,
        Cmd::AccessKey { reset } => {
            let key = if reset {
                auth::access::reset(&cfg.data_dir)?
            } else {
                auth::access::load_or_generate(&cfg.data_dir)?
            };
            println!("{key}");
            if reset {
                eprintln!(
                    "已重置访问密钥（= Noise 握手 PSK，ADR 0007）。运行中的服务需 \
                     `systemctl restart ipgate-agent` 才生效；所有设备需用新口令重新配对。"
                );
            } else {
                eprintln!(
                    "此密钥即 Noise 握手 PSK：不持有它连握手都完不成。配对口令 = 此密钥.配对码\
                     （见 `ipgate-agent pair`）。"
                );
            }
        }
        Cmd::Forwards => forwards_cli(&cfg)?,
        Cmd::ForwardAdd {
            listen,
            dest,
            proto,
            iface,
            source,
            note,
        } => forward_add_cli(&cfg, &listen, &dest, &proto, iface, &source, &note)?,
        Cmd::ForwardRm { id } => forward_rm_cli(&cfg, &id)?,
        Cmd::DnatForwards => dnat_forwards_cli(&cfg)?,
        Cmd::DnatMigrate { listen, iface } => dnat_migrate_cli(&cfg, &listen, &iface)?,
        Cmd::DnatRm { listen, iface } => dnat_rm_cli(&cfg, &listen, &iface)?,
        Cmd::PrintRuleset => {
            let store = Store::load(&cfg.store_path())?;
            print!(
                "{}",
                nft::render_apply(
                    &cfg.ruleset_with(store.ssh_allowlist_only()),
                    store.entries(),
                    Utc::now()
                )
            );
        }
        Cmd::SshExpose { open, allowlist } => ssh_expose_cli(&cfg, open, allowlist)?,
        Cmd::Status => status(&cfg)?,
        Cmd::Uninstall => {
            NftCli::new().flush()?;
            println!("已删除 inet ipgate 表");
        }
    }
    Ok(())
}

fn pair(cfg: &AgentConfig, qr: bool, host: Option<String>, port: Option<u16>) -> Result<()> {
    let identity = noise::NoiseIdentity::load_or_generate(&cfg.data_dir)?;
    let nk = identity.public_b64();
    let code = auth::pairing::create(&cfg.data_dir, PAIRING_CODE_TTL_SECS, Utc::now())?;
    let ttl_min = PAIRING_CODE_TTL_SECS / 60;
    println!("服务端 Noise 公钥（客户端自动钉死）：{}", nk);
    // join 串 = 访问密钥.配对码。访问密钥同时是 Noise 握手 PSK（ADR 0007）；客户端粘一次自动拆分。
    let access = auth::access::load_or_generate(&cfg.data_dir)?;
    let join = format!("{}.{}", access, code.as_str());
    println!(
        "配对口令（{ttl_min} 分钟内有效、单次，粘贴到客户端「配对码」栏）：\n  {join}"
    );

    if qr {
        let host = host.context("--qr 需配合 --host <地址>（写进二维码、供客户端经 SSH 连接）")?;
        let port = port.unwrap_or(cfg.mgmt_port);
        print_pair_qr(cfg, &host, port, nk.as_str(), &join)?;
    } else {
        println!("在客户端输入主机地址 + 上面的口令即可（Noise 公钥校验自动完成）。");
    }
    Ok(())
}

/// 把配对信息编码成 `ipgate://pair#<base64url(json)>` 并在终端渲染二维码。
///
/// payload = `{v,h,p,fp,c}`：版本 / 主机 / 端口 / 指纹（冒号大写）/ join 串。客户端「扫码配对」
/// 解析后直接 pin `fp`——指纹经二维码（agent 自己屏幕这条可信通道）传达，取代肉眼逐位核对。
/// 二维码含单次配对码，与上面终端明文打印的 join 串同等敏感（单次 + TTL 失效即作废）。
fn print_pair_qr(cfg: &AgentConfig, host: &str, np: u16, noise_pub: &str, join: &str) -> Result<()> {
    use base64::Engine;
    use qrcode::{render::unicode, EcLevel, QrCode};

    // payload v2（ADR 0007）：版本 / 主机 / SSH 端口(ssh) / SSH 用户(u) / loopback 上的
    // Noise 端口(np) / Noise 静态公钥(nk) / join 串(c, 含 PSK+配对码) / 受限转发 SSH 私钥的
    // 32 字节 ed25519 种子(sk, base64, 存在时)。客户端：以 u@h:ssh 用受限 key 建隧道转发到
    // 127.0.0.1:np → Noise 握手钉死 nk → 从 join 拆出 PSK 与配对码。
    // 只放种子（而非整段 PEM）让二维码小一大半——客户端用 from_seed 重建同一把私钥。
    let mut payload = serde_json::json!({
        "v": 2,
        "h": host,
        "ssh": cfg.ssh_port,
        "u": cfg.ssh_user,
        "np": np,
        "nk": noise_pub,
        "c": join,
    });
    match std::fs::read_to_string(cfg.data_dir.join("tunnel_key")) {
        Ok(pem) => match crate::util::extract_ed25519_seed(&pem) {
            Ok(seed) => {
                let sk = base64::engine::general_purpose::STANDARD_NO_PAD.encode(seed);
                payload["sk"] = serde_json::Value::String(sk);
            }
            Err(e) => eprintln!(
                "提示：解析 {}/tunnel_key 失败（{e}）—— 二维码不含 SSH 隧道私钥；\
                 请确保客户端已配置隧道凭据（见 deploy/install.sh）。",
                cfg.data_dir.display()
            ),
        },
        Err(_) => eprintln!(
            "提示：未找到 {}/tunnel_key —— 二维码不含 SSH 隧道私钥；\
             请确保客户端已配置隧道凭据（见 deploy/install.sh）。",
            cfg.data_dir.display()
        ),
    }
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let uri = format!("ipgate://pair#{b64}");

    // EcLevel::L：内容是单次短时口令、又显示在可信屏幕上，用最低纠错换更小（更易扫）的码。
    let code = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::L)
        .context("生成配对二维码失败")?;
    let img = code.render::<unicode::Dense1x2>().quiet_zone(true).build();
    println!("\n用 ipgate 客户端「扫码配对」扫下面的二维码（移动端，含 Noise 公钥 + 口令 + 隧道凭据，单次有效）：\n{img}");
    // 桌面端无摄像头：把整条 uri 粘进客户端「添加主机」即可（与二维码同等敏感、单次有效）。
    println!("桌面端（无摄像头）：把下面这条配对链接整条粘到客户端「添加主机」：\n  {uri}");
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

// ---- 端口转发 CLI（离线/装机/排障；运行中的服务请走客户端 API）----
//
// 与 allow/revoke 同样的离线语义：CLI 写的是**磁盘存储**，运行中的服务进程看不到，
// 且其周期循环会以自己的内存态覆盖。本组命令仅供服务**未运行**时（装机/调试）使用。

fn parse_port_range(s: &str) -> Result<PortRange> {
    let s = s.trim();
    let pr = if let Some((a, b)) = s.split_once('-') {
        let start: u16 = a.trim().parse().with_context(|| format!("非法端口: {a}"))?;
        let end: u16 = b.trim().parse().with_context(|| format!("非法端口: {b}"))?;
        PortRange { start, end }
    } else {
        let p: u16 = s.parse().with_context(|| format!("非法端口: {s}"))?;
        PortRange::single(p)
    };
    if pr.start == 0 || !pr.is_valid() {
        anyhow::bail!("非法端口区间: {s}");
    }
    Ok(pr)
}

fn parse_proto(s: &str) -> Result<ForwardProto> {
    match s.trim().to_ascii_lowercase().as_str() {
        "tcp" => Ok(ForwardProto::Tcp),
        "udp" => Ok(ForwardProto::Udp),
        "both" | "tcp+udp" | "all" => Ok(ForwardProto::Both),
        other => anyhow::bail!("非法协议（tcp|udp|both）: {other}"),
    }
}

fn parse_source(s: &str) -> Result<ForwardSource> {
    let s = s.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("auto") {
        Ok(ForwardSource::Auto)
    } else {
        let ip: std::net::Ipv4Addr = s.parse().with_context(|| format!("非法源 IPv4: {s}"))?;
        Ok(ForwardSource::Ip(ip))
    }
}

fn fmt_ports(p: &PortRange) -> String {
    if p.start == p.end {
        p.start.to_string()
    } else {
        format!("{}-{}", p.start, p.end)
    }
}

fn proto_label(p: ForwardProto) -> &'static str {
    match p {
        ForwardProto::Tcp => "tcp",
        ForwardProto::Udp => "udp",
        ForwardProto::Both => "tcp+udp",
    }
}

fn forwards_cli(cfg: &AgentConfig) -> Result<()> {
    let store = Store::load(&cfg.store_path())?;
    println!(
        "端口转发规则：{}（修订 {}）",
        store.forwards().len(),
        store.forward_revision()
    );
    for f in store.forwards() {
        let iface = f.iface.clone().unwrap_or_else(|| "auto".into());
        let src = match f.source {
            ForwardSource::Auto => "auto".to_string(),
            ForwardSource::Ip(ip) => ip.to_string(),
        };
        let resolved = store
            .resolved_ip(f.id)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "未解析".into());
        println!(
            "  [{}] {} :{} → {}:{}  源={} 解析={}  id={}",
            proto_label(f.proto),
            iface,
            fmt_ports(&f.listen),
            f.dest_host,
            fmt_ports(&f.dest_port),
            src,
            resolved,
            f.id
        );
    }
    Ok(())
}

fn forward_add_cli(
    cfg: &AgentConfig,
    listen: &str,
    dest: &str,
    proto: &str,
    iface: Option<String>,
    source: &str,
    note: &str,
) -> Result<()> {
    let listen = parse_port_range(listen)?;
    let (host, dport) = dest
        .rsplit_once(':')
        .context("目标需 host:port 形式，如 10.0.0.9:8443")?;
    let dest_port = parse_port_range(dport)?;
    let req = AddForwardRequest {
        proto: parse_proto(proto)?,
        iface,
        listen,
        dest_host: host.trim().to_string(),
        dest_port,
        source: parse_source(source)?,
        note: note.to_string(),
    };
    ipgate_proto::validate_ports(&req.listen, &req.dest_port).map_err(|e| anyhow::anyhow!(e))?;
    if req.dest_host.is_empty() {
        anyhow::bail!("目标主机为空");
    }

    // 碰撞检测：与 HTTP add_forward 对齐（评审：CLI 此前漏了这道闸，破坏「同端口不双权威」不变量）。
    let adapter = dnat::DnatAdapter::new(cfg.dnat.clone());
    if adapter.present() {
        if let Some(eff) = req.iface.clone().or_else(netinfo::default_route_iface) {
            if adapter
                .rules()
                .into_iter()
                .any(|d| d.iface == eff && req.listen.overlaps(&d.listen))
            {
                anyhow::bail!("监听端口已被本机 dnat 规则占用，请先 `dnat-migrate` 或换端口");
            }
        }
    }

    let store = Arc::new(Mutex::new(Store::load(&cfg.store_path())?));
    let rule = {
        let mut s = store.lock().unwrap();
        let r = s.add_forward(req, DeviceId(Uuid::nil()), Utc::now());
        s.save()?;
        r
    };
    // 尽力即时落地（装机期把转发拉起）。失败不致命：已写存储，服务启动会接管。
    let nat: Arc<dyn NatBackend + Send + Sync> = Arc::new(NftCli::new());
    match forward::apply_now(&store, &nat) {
        Ok((_, warns)) => {
            for w in warns {
                eprintln!("提示: {w}");
            }
        }
        Err(e) => eprintln!("已写存储，但即时落地失败（服务运行后会自动同步）: {e}"),
    }
    println!(
        "已添加转发 [{}] :{} → {}:{}",
        proto_label(rule.proto),
        fmt_ports(&rule.listen),
        rule.dest_host,
        fmt_ports(&rule.dest_port)
    );
    println!("  id={}", rule.id);
    Ok(())
}

fn forward_rm_cli(cfg: &AgentConfig, id: &str) -> Result<()> {
    let id = ForwardId(Uuid::parse_str(id.trim()).context("非法 id（应为 uuid）")?);
    let store = Arc::new(Mutex::new(Store::load(&cfg.store_path())?));
    let removed = {
        let mut s = store.lock().unwrap();
        let r = s.remove_forward(id);
        if r {
            s.save()?;
        }
        r
    };
    if !removed {
        println!("无此转发规则: {id}");
        return Ok(());
    }
    let nat: Arc<dyn NatBackend + Send + Sync> = Arc::new(NftCli::new());
    let _ = forward::apply_now(&store, &nat);
    println!("已删除转发 {id}");
    Ok(())
}

// ---- dnat 适配 CLI（ADR 0006 排空模型；离线操作 conf + 触发 dnat apply）----

fn dnat_forwards_cli(cfg: &AgentConfig) -> Result<()> {
    let adapter = dnat::DnatAdapter::new(cfg.dnat.clone());
    let rules = adapter.rules();
    println!(
        "dnat 转发规则：{}（{}）",
        rules.len(),
        if adapter.present() {
            "适配已启用"
        } else {
            "适配未启用，仅离线读 conf"
        }
    );
    for r in &rules {
        let src = match r.source {
            ForwardSource::Auto => "auto".to_string(),
            ForwardSource::Ip(ip) => ip.to_string(),
        };
        println!(
            "  [tcp+udp] {} :{} → {}:{}  源={}  键={}",
            r.iface,
            fmt_ports(&r.listen),
            r.remote_host,
            fmt_ports(&r.dest_port),
            src,
            dnat::encode_key(&r.prefix_key()),
        );
    }
    Ok(())
}

/// 离线找一条 dnat 规则（按监听端口 + 网卡）。
fn find_dnat_rule(adapter: &dnat::DnatAdapter, listen: &str, iface: &str) -> Result<dnat::DnatRule> {
    let listen = parse_port_range(listen)?;
    adapter
        .rules()
        .into_iter()
        .find(|r| r.listen == listen && r.iface == iface)
        .with_context(|| format!("无匹配的 dnat 规则：{iface} :{}", fmt_ports(&listen)))
}

fn dnat_rm_cli(cfg: &AgentConfig, listen: &str, iface: &str) -> Result<()> {
    let adapter = dnat::DnatAdapter::new(cfg.dnat.clone());
    let rule = find_dnat_rule(&adapter, listen, iface)?;
    if adapter.remove_prefix(&rule.prefix_key())? {
        println!("已删除 dnat 规则 {} :{}", iface, fmt_ports(&rule.listen));
    } else {
        println!("无此 dnat 规则");
    }
    Ok(())
}

fn dnat_migrate_cli(cfg: &AgentConfig, listen: &str, iface: &str) -> Result<()> {
    let adapter = dnat::DnatAdapter::new(cfg.dnat.clone());
    let rule = find_dnat_rule(&adapter, listen, iface)?;
    let req = dnat::dnat_rule_to_add_request(&rule);

    // native 表达不了的映射不能迁移；目标 (网卡,端口) 已有 native 规则则拒（避免静默覆盖）。评审。
    ipgate_proto::validate_ports(&req.listen, &req.dest_port)
        .map_err(|e| anyhow::anyhow!("该 dnat 规则的端口映射 native 不支持，无法迁移：{e}"))?;
    let store = Arc::new(Mutex::new(Store::load(&cfg.store_path())?));
    {
        let s = store.lock().unwrap();
        if s.forwards().iter().any(|f| {
            f.iface.clone().or_else(netinfo::default_route_iface).as_deref() == Some(rule.iface.as_str())
                && f.listen.overlaps(&rule.listen)
        }) {
            anyhow::bail!("目标 (网卡,端口) 已有 native 转发，迁移会覆盖它；请先处理后再迁移");
        }
    }

    // 先建 native（-90，dnat -100 仍赢→零抖动）→ 落地 → 核实生效 → 再删 dnat（零瞬断）。
    let new_rule = {
        let mut s = store.lock().unwrap();
        let r = s.add_forward(req, DeviceId(Uuid::nil()), Utc::now());
        s.save()?;
        r
    };
    let nat: Arc<dyn NatBackend + Send + Sync> = Arc::new(NftCli::new());
    forward::apply_now(&store, &nat).context("native 落地失败（已写存储，未撤 dnat）")?;
    // native 未解析生效则回滚僵尸规则、保留 dnat（评审：避免在 native 没生效时撤 dnat 致转发全黑）。
    if store.lock().unwrap().resolved_ip(new_rule.id).is_none() {
        {
            let mut s = store.lock().unwrap();
            s.remove_forward(new_rule.id);
            let _ = s.save();
        }
        let _ = forward::apply_now(&store, &nat);
        anyhow::bail!("native 规则未能解析/生效（如域名暂时解析失败），已保留原 dnat，请稍后重试");
    }
    adapter
        .remove_prefix(&rule.prefix_key())
        .context("native 已生效，但撤原 dnat 规则失败（dnat 仍在服务，可重试或手动 dnat-rm）")?;

    println!(
        "已迁移 dnat → native：{} :{} → {}:{}  (native id={})",
        iface,
        fmt_ports(&new_rule.listen),
        new_rule.dest_host,
        fmt_ports(&new_rule.dest_port),
        new_rule.id,
    );
    Ok(())
}

fn run(cfg: AgentConfig, interval: u64) -> Result<()> {
    cfg.validate()?;

    let identity = noise::NoiseIdentity::load_or_generate(&cfg.data_dir)?;
    info!(noise_pubkey = %identity.public_b64(), "服务端 Noise 公钥（客户端首次配对时钉死）");

    let backend: Arc<dyn NftBackend + Send + Sync> = Arc::new(NftCli::new());
    let nat: Arc<dyn NatBackend + Send + Sync> = Arc::new(NftCli::new());
    let store = Arc::new(Mutex::new(Store::load(&cfg.store_path())?));

    // 启动即清过期 + 全量原子重建（坐实 default-drop 与管理端口放行不变量）。
    {
        let mut s = store.lock().unwrap();
        if !s.prune_expired(Utc::now()).is_empty() {
            s.save()?;
        }
        backend.apply(&cfg.ruleset_with(s.ssh_allowlist_only()), s.entries())?;
    }
    info!("ruleset 已应用");

    // 端口转发：启动期解析 + 落地一次（独立 `ip ipgate_nat` 表，与上面互不相干）。
    match forward::apply_now(&store, &nat) {
        Ok((n, warns)) => {
            for w in &warns {
                warn!("转发：{w}");
            }
            if n > 0 {
                info!(applied = n, "端口转发已应用");
            }
        }
        // 转发落地失败绝不拖垮主服务（放行名单/管理端口才是命脉）：记日志、继续。
        Err(e) => warn!(error = %e, "端口转发启动落地失败（不影响放行名单与管理端口）"),
    }

    // 访问密钥转生为 Noise 握手 PSK（psk0，ADR 0007）：无此密钥连握手都完不成。
    let auth = AuthState::load_or_generate(&cfg.data_dir)?;
    let psk = noise::derive_psk(&auth.access_key);
    let cfg = Arc::new(cfg);

    // 后台对账线程（阻塞式，独立于 async server）。
    {
        let (store, backend, cfg) = (store.clone(), backend.clone(), cfg.clone());
        std::thread::spawn(move || reconcile_loop(cfg, store, backend, interval));
    }
    // 端口转发周期重解析线程（域名 IP 漂移自愈，独立于对账）。
    {
        let (store, nat) = (store.clone(), nat.clone());
        std::thread::spawn(move || forward::resolve_loop(store, nat, interval));
    }

    // ADR 0007：只在 loopback 监听 Noise；唯一入口是 SSH 隧道，对外零开放端口。
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, cfg.mgmt_port));
    let dnat = Arc::new(dnat::DnatAdapter::new(cfg.dnat.clone()));
    let state = api::AppState {
        cfg: cfg.clone(),
        store,
        backend,
        nat,
        dnat,
        rate: Arc::new(api::RateLimiter::new(
            cfg.rate_limit_per_min,
            Duration::from_secs(60),
        )),
    };
    info!(%addr, "启动 Noise JSON-RPC 服务（仅 loopback；经 SSH 隧道访问）");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(api::serve(state, identity, psk, addr))
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
        let (entries, ssh_allowlist_only) = {
            let mut s = store.lock().unwrap();
            if !s.prune_expired(now).is_empty() {
                let _ = s.save();
            }
            (s.entries().to_vec(), s.ssh_allowlist_only())
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
                let _ = backend.apply(&cfg.ruleset_with(ssh_allowlist_only), &entries);
            }
        }
    }
}

/// 控制台救援：切换 SSH 暴露模式，写存储并立刻重建 ruleset（服务在跑与否都可用）。
fn ssh_expose_cli(cfg: &AgentConfig, open: bool, allowlist: bool) -> Result<()> {
    let on = match (open, allowlist) {
        (true, false) => false, // --open => 不限名单
        (false, true) => true,  // --allowlist => 仅名单
        _ => anyhow::bail!("请二选一指定 --open（对所有人开放）或 --allowlist（仅放行名单）"),
    };
    let mut store = Store::load(&cfg.store_path())?;
    store.set_ssh_allowlist_only(on);
    store.save()?;
    // 直接落内核（救援场景：可能没有运行中的服务来对账）。
    NftCli::new().apply(&cfg.ruleset_with(on), store.entries())?;
    if on {
        println!("已设为：SSH 端口仅放行名单内源 IP 可连。");
    } else {
        println!("已设为：SSH 端口对所有人开放。");
    }
    eprintln!(
        "若 ipgate-agent 服务正在运行，请执行 `systemctl restart ipgate-agent` 同步其内存状态。"
    );
    Ok(())
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
