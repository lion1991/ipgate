//! 面向客户端的 REST API（over TLS，ADR 0003）。

mod error;
mod handlers;

use crate::auth::AuthState;
use crate::config::AgentConfig;
use crate::nft::NftBackend;
use crate::store::Store;
use crate::tls::ServerIdentity;
use anyhow::Result;
use axum::routing::{delete, get, post};
use axum::Router;
use ipgate_proto::SpkiFingerprint;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// 注入到所有 handler 的共享状态。
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AgentConfig>,
    pub store: Arc<Mutex<Store>>,
    pub backend: Arc<dyn NftBackend + Send + Sync>,
    pub auth: Arc<AuthState>,
    /// 本服务端 SPKI 指纹（登录挑战绑定信道用）。
    pub fingerprint: SpkiFingerprint,
}

pub fn router(state: AppState) -> Router {
    Router::new()
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
        .route("/v1/sync", post(handlers::sync))
        .route("/v1/devices", get(handlers::list_devices))
        .route("/v1/devices/{id}", delete(handlers::revoke_device))
        .with_state(state)
}

/// 启动 TLS API 服务（阻塞直到出错）。调用前需安装 rustls crypto provider。
pub async fn serve(state: AppState, identity: ServerIdentity, addr: SocketAddr) -> Result<()> {
    use axum_server::tls_rustls::RustlsConfig;
    let tls = RustlsConfig::from_pem(
        identity.cert_pem.into_bytes(),
        identity.key_pem.into_bytes(),
    )
    .await?;
    axum_server::bind_rustls(addr, tls)
        .serve(router(state).into_make_service())
        .await?;
    Ok(())
}
