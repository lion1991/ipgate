//! 面向客户端的 REST API（over TLS，ADR 0003）。

mod error;
mod handlers;
mod limit;

pub use limit::RateLimiter;

use crate::auth::AuthState;
use crate::config::AgentConfig;
use crate::nft::NftBackend;
use crate::store::Store;
use crate::tls::ServerIdentity;
use anyhow::Result;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use ipgate_proto::SpkiFingerprint;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// 访问密钥请求头（小写，HTTP/2 强制小写、HTTP/1 大小写不敏感）。
const ACCESS_HEADER: &str = "x-ipgate-key";

/// 注入到所有 handler 的共享状态。
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AgentConfig>,
    pub store: Arc<Mutex<Store>>,
    pub backend: Arc<dyn NftBackend + Send + Sync>,
    pub auth: Arc<AuthState>,
    /// 本服务端 SPKI 指纹（登录挑战绑定信道用）。
    pub fingerprint: SpkiFingerprint,
    /// 是否启用访问密钥门（来自 `cfg.require_access_key`）。
    pub require_access_key: bool,
    /// per-IP 限流器。
    pub rate: Arc<RateLimiter>,
}

pub fn router(state: AppState) -> Router {
    let app = Router::new()
        .route("/healthz", get(handlers::healthz))
        // 预鉴权端点（ADR 0003：面最小化）
        .route("/v1/pair", post(handlers::pair))
        .route("/v1/auth/challenge", post(handlers::auth_challenge))
        .route("/v1/auth/verify", post(handlers::auth_verify))
        // 需 Bearer 令牌
        .route(
            "/v1/allowlist",
            get(handlers::list_allowlist)
                .post(handlers::allow)
                .delete(handlers::revoke),
        )
        .route("/v1/whoami", get(handlers::whoami))
        .route("/v1/sync", post(handlers::sync))
        .route("/v1/devices", get(handlers::list_devices))
        .route("/v1/devices/{id}", delete(handlers::revoke_device))
        .with_state(state.clone());
    // 中间件链（最后 .layer 的最先执行）：限流 → 访问密钥门 → 路由/鉴权。
    // 门挡在路由**之前** → 无密钥者连配对/挑战/JSON 解析的代码都碰不到（堵 0-day/探测面）。
    app.layer(middleware::from_fn_with_state(state.clone(), access_gate))
        .layer(middleware::from_fn_with_state(state, rate_limit))
}

/// 限流中间件：按对端 IP。无 `ConnectInfo`（如单测 oneshot）则跳过。
async fn rate_limit(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(ci) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        if !st.rate.allow(ci.0.ip(), Instant::now()) {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }
    next.run(req).await
}

/// 访问密钥门：要求 `X-Ipgate-Key` 命中，否则一律**裸 404**——
/// 不回 401、不回 JSON 错误，扫描器看到的就是个「死端口」，识别不出 ipgate。
async fn access_gate(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if st.require_access_key {
        let ok = req
            .headers()
            .get(ACCESS_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|k| crate::auth::access::ct_eq(k.as_bytes(), st.auth.access_key.as_bytes()))
            .unwrap_or(false);
        if !ok {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    next.run(req).await
}

/// 启动 TLS API 服务（阻塞直到出错）。调用前需安装 rustls crypto provider。
pub async fn serve(state: AppState, identity: ServerIdentity, addr: SocketAddr) -> Result<()> {
    use axum_server::tls_rustls::RustlsConfig;
    let tls = RustlsConfig::from_pem(
        identity.cert_pem.into_bytes(),
        identity.key_pem.into_bytes(),
    )
    .await?;
    // into_make_service_with_connect_info：让 handler 能经 ConnectInfo 拿到对端地址
    // （/v1/whoami 用它回报客户端来源 IP）。
    axum_server::bind_rustls(addr, tls)
        .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}
