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
use crate::store::Store;
use anyhow::{Context, Result};
use chrono::Utc;
use ipgate_proto::{
    ApiError, Device, DeviceId, ErrorCode, HandshakeAck, HandshakeHello, NoisePublicKey, RpcRequest,
    RpcResponse,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::TcpListener;

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
        let st = state.clone();
        let id = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer.ip(), st, id, psk).await {
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
) -> Result<()> {
    // 握手 + 鉴权（authorize 内部锁 store、消费配对码）。失败＝不发 msg2、静默关连接。
    let mut conn = noise::accept(stream, &identity, &psk, |peer, hello| {
        authorize(&st, peer, hello)
    })
    .await?;

    // 握手已认证：据静态公钥定位设备 id（authorize 已确保其存在）。
    let device = st
        .store
        .lock()
        .unwrap()
        .get_device_by_pubkey(conn.peer())
        .map(|d| d.id)
        .context("握手后设备记录消失")?;

    // 请求循环：一条 RpcRequest → 一条 RpcResponse。
    loop {
        let raw = match conn.recv().await {
            Ok(b) => b,
            Err(_) => return Ok(()), // 对端关闭 / EOF：正常结束。
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
        let mut s = st.store.lock().unwrap();
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
        let mut s = st.store.lock().unwrap();
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
    })();
    match out {
        Ok(v) => RpcResponse::Ok(v),
        Err(e) => RpcResponse::Err(e),
    }
}

fn to_val<T: serde::Serialize>(v: T) -> Result<serde_json::Value, ApiError> {
    serde_json::to_value(v).map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))
}
