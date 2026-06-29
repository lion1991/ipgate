//! 面向客户端的 JSON-RPC over Noise（ADR 0007，取代 0003 的 TLS/REST）。
//!
//! agent 只在 loopback 监听 Noise_IKpsk0；唯一入口是 SSH 隧道。每条连接：
//! 握手（含 per-device 鉴权 / 配对）→ 请求循环（`RpcRequest` → handler → `RpcResponse`）。

mod error;
mod handlers;
mod limit;

pub use limit::RateLimiter;

use crate::config::AgentConfig;
use crate::dnat::DnatAdapter;
use crate::nft::{NatBackend, NftBackend};
use crate::noise::{self, NoiseIdentity};
use crate::store::{LockExt, Store};
use anyhow::{Context, Result};
use chrono::Utc;
use ipgate_proto::{
    ApiError, Device, DeviceId, ErrorCode, HandshakeAck, HandshakeHello, NoisePublicKey, RpcRequest,
    RpcResponse,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Noise 握手必须在此时限内完成，否则关连接（P1 修复：防 pre-auth slowloris——
/// 攻击者连上后不发/半发 msg1 长期占着 fd+任务）。loopback 上握手通常亚秒级，10s 极宽松。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 同时在握手/在线的连接数上限（P1 修复：限流器只管新建速率、不管并发持有，loopback 上
/// 又退化成单桶；这道闸真正封顶 fd/任务占用）。单运维工具 64 条已远超正常用量。
const MAX_CONCURRENT_CONNS: usize = 64;

/// 连接空闲多久没有任何请求就关掉，回收并发名额（也兜住「被撤销设备的纯空闲连接」赖着不走）。
/// 客户端是连接池 + 断线透明重连（见 client transport `rpc_pooled`：传输错即丢弃会话重连），
/// 到点重连无感，故不算回归。10 分钟远超正常操作间隔。
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// 单个已配对设备（按 Noise 静态公钥计）的在线连接数上限。配合全局 [`MAX_CONCURRENT_CONNS`]：
/// 防一个被攻陷/作恶的已配对设备开满全局名额、把运维（另一台设备，公钥不同→独立计数）挤出去。
/// 合法客户端每主机只持 1 条会话，8 远超正常用量。
const PER_DEVICE_MAX_CONNS: usize = 8;

/// 各设备当前在线连接数（按 Noise 静态公钥计），用于 per-device 连接上限。
type DeviceConns = Arc<Mutex<std::collections::HashMap<NoisePublicKey, usize>>>;

/// RAII 在线连接计数：`acquire` 超限返回 `None`；`Drop` 自动减一并清掉归零项（防表无限增长）。
struct DeviceConnGuard {
    map: DeviceConns,
    key: NoisePublicKey,
}

impl DeviceConnGuard {
    fn acquire(map: &DeviceConns, key: NoisePublicKey, max: usize) -> Option<Self> {
        let mut m = map.lock_safe();
        let n = m.entry(key.clone()).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(Self { map: map.clone(), key })
    }
}

impl Drop for DeviceConnGuard {
    fn drop(&mut self) {
        let mut m = self.map.lock_safe();
        if let Some(n) = m.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// 注入到所有 handler 的共享状态（ADR 0007：去掉了 TLS 指纹 / 令牌 / 访问密钥门）。
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AgentConfig>,
    pub store: Arc<Mutex<Store>>,
    pub backend: Arc<dyn NftBackend + Send + Sync>,
    /// 端口转发落地后端（`ip ipgate_nat` 表）。
    pub nat: Arc<dyn NatBackend + Send + Sync>,
    /// dnat 适配器（ADR 0006 排空模型）。
    pub dnat: Arc<DnatAdapter>,
    /// per-IP 限流器。loopback+SSH 模型下主要给（未来的）直连兜底。
    pub rate: Arc<RateLimiter>,
}

/// 启动 Noise JSON-RPC 服务（loopback only，阻塞直到出错）。
pub async fn serve(
    state: AppState,
    identity: NoiseIdentity,
    psk: [u8; 32],
    addr: SocketAddr,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("绑定 {addr} 失败"))?;
    serve_on(state, identity, psk, listener).await
}

/// 在已绑定的 listener 上服务（供 e2e 用 `127.0.0.1:0` 取临时端口）。
pub(crate) async fn serve_on(
    state: AppState,
    identity: NoiseIdentity,
    psk: [u8; 32],
    listener: TcpListener,
) -> Result<()> {
    let identity = Arc::new(identity);
    // 并发连接名额：封顶同时在握手/在线的连接数，防 slowloris/连接堆积耗尽 fd（P1 修复）。
    let conns = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));
    // per-device 在线连接计数：防单个已配对设备占满全局名额把运维挤出（P1 修复）。
    let dev_conns: DeviceConns = Arc::new(Mutex::new(std::collections::HashMap::new()));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "accept 失败");
                continue;
            }
        };
        // 限流：loopback+SSH 模型下 peer 恒为本机，这道闸主要给直连兜底；超额静默丢弃。
        if !state.rate.allow(peer.ip(), Instant::now()) {
            continue;
        }
        // 取并发名额；满了就直接丢这条新连接（不排队、不阻塞 accept 循环）。
        let permit = match conns.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("并发连接达上限（{MAX_CONCURRENT_CONNS}），拒绝新连接");
                continue;
            }
        };
        let st = state.clone();
        let id = identity.clone();
        let dc = dev_conns.clone();
        tokio::spawn(async move {
            let _permit = permit; // 持有至连接结束，drop 时自动归还名额。
            if let Err(e) = handle_conn(stream, peer.ip(), st, id, psk, dc).await {
                tracing::debug!(error = %e, "Noise 连接结束");
            }
        });
    }
}

async fn handle_conn(
    stream: tokio::net::TcpStream,
    peer_ip: IpAddr,
    st: AppState,
    identity: Arc<NoiseIdentity>,
    psk: [u8; 32],
    dev_conns: DeviceConns,
) -> Result<()> {
    // 握手 + 鉴权（authorize 内部锁 store、消费配对码）。失败＝不发 msg2、静默关连接。
    // 整个握手套超时：慢/不发 msg1 的连接到点即弃，不会无限期占着名额与 fd（P1 修复）。
    let accept = noise::accept(stream, &identity, &psk, |peer, hello| authorize(&st, peer, hello));
    let mut conn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, accept).await {
        Ok(r) => r?,
        Err(_) => {
            tracing::debug!("Noise 握手超时，关连接");
            return Ok(());
        }
    };

    // 握手已认证：记下对端静态公钥（设备身份）。注意 **不**把 device id 缓存一辈子——
    // 每轮请求都按公钥重新核验（见下），否则 RevokeDevice 对在途连接形同无效。
    let peer_key = conn.peer().clone();

    // per-device 在线连接上限：单个已配对设备最多占 PER_DEVICE_MAX_CONNS 条，挤不掉运维
    // （另一台设备公钥不同→独立计数）。Drop 时自动归还（P1 修复：防 idle 连接垄断全局名额）。
    let _dev_guard = match DeviceConnGuard::acquire(&dev_conns, peer_key.clone(), PER_DEVICE_MAX_CONNS)
    {
        Some(g) => g,
        None => {
            tracing::warn!("该设备在线连接已达上限（{PER_DEVICE_MAX_CONNS}），拒绝新连接");
            return Ok(());
        }
    };

    // 请求循环：一条 RpcRequest → 一条 RpcResponse。
    loop {
        // 空闲超时：到点没有任何请求就关连接，回收全局/per-device 名额，并兜住「被撤销设备
        // 的纯空闲连接」（其 recheck 只在收到请求时触发，纯空闲不会走到）（P1 修复）。
        let raw = match tokio::time::timeout(CONN_IDLE_TIMEOUT, conn.recv()).await {
            Ok(Ok(b)) => b,
            Ok(Err(_)) => return Ok(()), // 对端关闭 / EOF：正常结束。
            Err(_) => {
                tracing::debug!("Noise 连接空闲超时，关闭以回收名额");
                return Ok(());
            }
        };
        // 每轮复验设备仍在授权列表（P1 修复）：RevokeDevice 只改 store，原先不会断开已建立
        // 的连接，被撤销的恶意客户端可一直发特权 RPC。这里一旦查不到设备即关连接。
        let device = match st.store.lock_safe().get_device_by_pubkey(&peer_key).map(|d| d.id) {
            Some(id) => id,
            None => {
                tracing::info!("设备已被撤销，关闭其在途 Noise 连接");
                return Ok(());
            }
        };
        let resp = match serde_json::from_slice::<RpcRequest>(&raw) {
            Ok(req) => dispatch(&st, device, peer_ip, req),
            Err(e) => {
                RpcResponse::Err(ApiError::new(ErrorCode::BadRequest, format!("请求解析失败：{e}")))
            }
        };
        conn.send(&serde_json::to_vec(&resp)?).await?;
    }
}

/// Noise 握手鉴权回调（同步）：已知设备直接放行；未知设备须带有效配对码。
fn authorize(st: &AppState, peer: &NoisePublicKey, hello: HandshakeHello) -> Result<HandshakeAck> {
    let now = Utc::now();
    // 已配对设备：其静态公钥在授权列表里 → 放行。
    // 注意：单次持锁完成「查 + touch + save」。std::Mutex 不可重入，且 if-let 的临时
    // MutexGuard 会持有到块末（2021 edition），嵌套二次 lock 会自锁——故用显式作用域。
    {
        let mut s = st.store.lock_safe();
        if let Some(id) = s.get_device_by_pubkey(peer).map(|d| d.id) {
            s.touch_device(id, now);
            let _ = s.save();
            return Ok(HandshakeAck { device_id: id, paired: false });
        }
    }
    // 未知设备：必须携带有效（单次、未过期）配对码，方可授权其静态公钥。
    let code = hello
        .pairing_code
        .ok_or_else(|| anyhow::anyhow!("未配对设备且未提供配对码"))?;
    if !crate::auth::pairing::consume(&st.cfg.data_dir, &code, now)? {
        anyhow::bail!("配对码无效 / 过期 / 已用");
    }
    let device = Device {
        id: DeviceId::new(),
        name: hello
            .device_name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| "未命名设备".into()),
        pubkey: peer.clone(),
        created_at: now,
        last_seen: Some(now),
    };
    let id = device.id;
    {
        let mut s = st.store.lock_safe();
        s.add_device(device);
        s.save()?;
    }
    tracing::info!(%id, "新设备配对成功");
    Ok(HandshakeAck { device_id: id, paired: true })
}

/// 把一条 RPC 请求路由到对应 handler，并把结果序列化进 `RpcResponse`。
fn dispatch(st: &AppState, device: DeviceId, peer_ip: IpAddr, req: RpcRequest) -> RpcResponse {
    use RpcRequest::*;
    let out: Result<serde_json::Value, ApiError> = (|| match req {
        ListAllowlist => to_val(handlers::list_allowlist(st)?),
        Allow(r) => to_val(handlers::allow(st, device, r)?),
        Revoke(r) => {
            handlers::revoke(st, r)?;
            Ok(serde_json::Value::Null)
        }
        Whoami => to_val(handlers::whoami(peer_ip)),
        Sync => to_val(handlers::sync(st)?),
        ListForwards => to_val(handlers::list_forwards(st)?),
        AddForward(r) => to_val(handlers::add_forward(st, device, r)?),
        RemoveForward(id) => {
            handlers::remove_forward(st, id)?;
            Ok(serde_json::Value::Null)
        }
        RemoveDnat { key } => {
            handlers::remove_dnat_forward(st, &key)?;
            Ok(serde_json::Value::Null)
        }
        MigrateDnat { key } => to_val(handlers::migrate_dnat_forward(st, device, &key)?),
        ListInterfaces => to_val(handlers::list_interfaces()),
        ListDevices => to_val(handlers::list_devices(st)),
        RevokeDevice(id) => {
            handlers::revoke_device(st, id)?;
            Ok(serde_json::Value::Null)
        }
        GetSettings => to_val(handlers::get_settings(st)),
        SetSshExposure { allowlist_only } => {
            to_val(handlers::set_ssh_exposure(st, allowlist_only)?)
        }
        SetSshPasswordAuth { enabled } => {
            // 审计：改全机 SSH 密码登录是高权操作，记下是哪台设备发起的（P1 修复：原先无痕）。
            tracing::warn!(%device, enabled, "特权操作：设置 SSH 密码登录");
            to_val(handlers::set_ssh_password_auth(st, enabled)?)
        }
        ResetRootPassword { password } => {
            // 审计：重置 root 密码同属高权操作；只记设备 id，绝不记明文。
            tracing::warn!(%device, "特权操作：重置 root 密码");
            handlers::reset_root_password(password)?;
            Ok(serde_json::Value::Null)
        }
    })();
    match out {
        Ok(v) => RpcResponse::Ok(v),
        Err(e) => RpcResponse::Err(e),
    }
}

fn to_val<T: serde::Serialize>(v: T) -> Result<serde_json::Value, ApiError> {
    serde_json::to_value(v).map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))
}
