//! 端到端测试：用 `Router::oneshot` 跑通完整鉴权 + 名单流程（不经真实 socket，
//! 但覆盖路由 / 抽取器 / 鉴权 / serde / 状态码）。nft 后端用内存 mock。

use crate::api::{router, AppState};
use crate::auth::keys::testkit;
use crate::auth::{challenge, pairing, AuthState};
use crate::config::AgentConfig;
use crate::nft::NftBackend;
use crate::store::Store;
use crate::tls;
use crate::util::{random_bytes, to_hex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use chrono::Utc;
use ipgate_proto::*;
use ipnet::IpNet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// 内存版 nft 后端。
#[derive(Default)]
struct MockNft {
    set: Mutex<Vec<IpNet>>,
}

impl NftBackend for MockNft {
    fn apply(&self, _cfg: &RulesetConfig, entries: &[Entry]) -> anyhow::Result<()> {
        *self.set.lock().unwrap() = entries.iter().map(|e| e.target).collect();
        Ok(())
    }
    fn add(&self, entry: &Entry) -> anyhow::Result<()> {
        self.set.lock().unwrap().push(entry.target);
        Ok(())
    }
    fn remove(&self, target: &IpNet) -> anyhow::Result<()> {
        self.set.lock().unwrap().retain(|t| t != target);
        Ok(())
    }
    fn list(&self) -> anyhow::Result<Vec<KernelElement>> {
        Ok(self
            .set
            .lock()
            .unwrap()
            .iter()
            .map(|t| KernelElement {
                target: *t,
                expires_at: None,
            })
            .collect())
    }
    fn flush(&self) -> anyhow::Result<()> {
        self.set.lock().unwrap().clear();
        Ok(())
    }
}

struct Harness {
    app: Router,
    backend: Arc<MockNft>,
    fingerprint: SpkiFingerprint,
    data_dir: std::path::PathBuf,
    access_key: String,
}

fn harness() -> Harness {
    harness_cfg(false)
}

fn harness_cfg(require_access_key: bool) -> Harness {
    let data_dir = std::env::temp_dir().join(format!("ipgate-e2e-{}", to_hex(&random_bytes::<8>())));
    let cfg = AgentConfig {
        data_dir: data_dir.clone(),
        require_access_key,
        ..AgentConfig::default()
    };
    let identity = tls::load_or_generate(&data_dir).unwrap();
    let backend = Arc::new(MockNft::default());
    let store = Arc::new(Mutex::new(Store::load(&cfg.store_path()).unwrap()));
    let auth = Arc::new(AuthState::load_or_generate(&data_dir).unwrap());
    let access_key = auth.access_key.clone();
    let rate = Arc::new(crate::api::RateLimiter::new(
        cfg.rate_limit_per_min,
        std::time::Duration::from_secs(60),
    ));
    let state = AppState {
        cfg: Arc::new(cfg),
        store,
        backend: backend.clone(),
        auth,
        fingerprint: identity.fingerprint.clone(),
        require_access_key,
        rate,
    };
    Harness {
        app: router(state),
        backend,
        fingerprint: identity.fingerprint,
        data_dir,
        access_key,
    }
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
) -> (StatusCode, Vec<u8>) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(bytes) => b
            .header("content-type", "application/json")
            .body(Body::from(bytes))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

fn json<T: serde::Serialize>(v: &T) -> Option<Vec<u8>> {
    Some(serde_json::to_vec(v).unwrap())
}

/// 配对 + 登录，返回可用的 Bearer 令牌。
async fn pair_and_login(
    h: &Harness,
    sk: &ed25519_dalek::SigningKey,
    pubkey: &PublicKey,
) -> String {
    let code = pairing::create(&h.data_dir, PAIRING_CODE_TTL_SECS, Utc::now()).unwrap();
    let pair_req = PairRequest {
        pairing_code: code.clone(),
        device_name: "phone".into(),
        device_pubkey: pubkey.clone(),
        signature: testkit::sign(sk, &pairing::pair_message(&code)),
    };
    let (_, body) = call(&h.app, "POST", "/v1/pair", None, json(&pair_req)).await;
    let paired: PairResponse = serde_json::from_slice(&body).unwrap();

    let (_, body) = call(
        &h.app,
        "POST",
        "/v1/auth/challenge",
        None,
        json(&AuthChallengeRequest {
            device_id: paired.device_id,
        }),
    )
    .await;
    let chal: AuthChallengeResponse = serde_json::from_slice(&body).unwrap();
    let verify_req = AuthVerifyRequest {
        device_id: paired.device_id,
        signature: testkit::sign(sk, &challenge::auth_message(&chal.nonce, &h.fingerprint)),
    };
    let (_, body) = call(&h.app, "POST", "/v1/auth/verify", None, json(&verify_req)).await;
    serde_json::from_slice::<AuthVerifyResponse>(&body)
        .unwrap()
        .token
        .as_str()
        .to_owned()
}

#[tokio::test]
async fn full_pairing_and_allowlist_flow() {
    let h = harness();
    let (sk, pubkey) = testkit::keypair(42);

    // 1) 未鉴权访问被拒
    let (st, _) = call(&h.app, "GET", "/v1/allowlist", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // 2) 烂配对码被拒
    let bad = PairRequest {
        pairing_code: PairingCode::from("deadbeef"),
        device_name: "x".into(),
        device_pubkey: pubkey.clone(),
        signature: testkit::sign(&sk, &pairing::pair_message(&PairingCode::from("deadbeef"))),
    };
    let (st, _) = call(&h.app, "POST", "/v1/pair", None, json(&bad)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // 3) 正常配对（agent 侧生成配对码 → 客户端签名 → 入网）
    let code = pairing::create(&h.data_dir, PAIRING_CODE_TTL_SECS, Utc::now()).unwrap();
    let pair_req = PairRequest {
        pairing_code: code.clone(),
        device_name: "phone".into(),
        device_pubkey: pubkey.clone(),
        signature: testkit::sign(&sk, &pairing::pair_message(&code)),
    };
    let (st, body) = call(&h.app, "POST", "/v1/pair", None, json(&pair_req)).await;
    assert_eq!(st, StatusCode::OK);
    let paired: PairResponse = serde_json::from_slice(&body).unwrap();

    // 4) 登录：挑战 → 签名 → 换令牌
    let (st, body) = call(
        &h.app,
        "POST",
        "/v1/auth/challenge",
        None,
        json(&AuthChallengeRequest {
            device_id: paired.device_id,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let chal: AuthChallengeResponse = serde_json::from_slice(&body).unwrap();

    let verify_req = AuthVerifyRequest {
        device_id: paired.device_id,
        signature: testkit::sign(&sk, &challenge::auth_message(&chal.nonce, &h.fingerprint)),
    };
    let (st, body) = call(&h.app, "POST", "/v1/auth/verify", None, json(&verify_req)).await;
    assert_eq!(st, StatusCode::OK);
    let token = serde_json::from_slice::<AuthVerifyResponse>(&body)
        .unwrap()
        .token;
    let bearer = token.as_str().to_owned();

    // 5) 带令牌：名单初始为空
    let (st, body) = call(&h.app, "GET", "/v1/allowlist", Some(&bearer), None).await;
    assert_eq!(st, StatusCode::OK);
    let list: Allowlist = serde_json::from_slice(&body).unwrap();
    assert!(list.entries.is_empty());

    // 6) 放行一个目标 → 落到 mock 内核
    let allow_req = AllowRequest {
        target: "203.0.113.0/24".parse().unwrap(),
        note: "office".into(),
        expires_at: None,
    };
    let (st, _) = call(&h.app, "POST", "/v1/allowlist", Some(&bearer), json(&allow_req)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h.backend.set.lock().unwrap().len(), 1);

    // 7) 名单可读到该条
    let (_, body) = call(&h.app, "GET", "/v1/allowlist", Some(&bearer), None).await;
    let list: Allowlist = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.entries.len(), 1);
    assert_eq!(list.entries[0].target, "203.0.113.0/24".parse().unwrap());

    // 8) 撤销 → mock 内核清空
    let revoke = RevokeRequest::Target("203.0.113.0/24".parse().unwrap());
    let (st, _) = call(&h.app, "DELETE", "/v1/allowlist", Some(&bearer), json(&revoke)).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert!(h.backend.set.lock().unwrap().is_empty());

    // 9) 设备可列出
    let (st, body) = call(&h.app, "GET", "/v1/devices", Some(&bearer), None).await;
    assert_eq!(st, StatusCode::OK);
    let devices: Vec<Device> = serde_json::from_slice(&body).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "phone");

    let _ = std::fs::remove_dir_all(&h.data_dir);
}

#[tokio::test]
async fn whoami_reports_observed_peer_ip() {
    let h = harness();
    let (sk, pubkey) = testkit::keypair(7);
    let bearer = pair_and_login(&h, &sk, &pubkey).await;

    // oneshot 不经真实 socket，手动注入 ConnectInfo 模拟对端地址。
    let addr: std::net::SocketAddr = "203.0.113.9:54321".parse().unwrap();
    let req = Request::builder()
        .method("GET")
        .uri("/v1/whoami")
        .header("authorization", format!("Bearer {bearer}"))
        .extension(axum::extract::ConnectInfo(addr))
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let who: WhoamiResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(who.ip, addr.ip());

    // 未鉴权应被拒
    let req = Request::builder()
        .method("GET")
        .uri("/v1/whoami")
        .extension(axum::extract::ConnectInfo(addr))
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let _ = std::fs::remove_dir_all(&h.data_dir);
}

#[tokio::test]
async fn rcgen_cert_builds_valid_rustls_config() {
    // oneshot 测试绕过了 TLS；这里验证自签证书/私钥能被 rustls 接受（catch 密钥格式问题）。
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = std::env::temp_dir().join(format!("ipgate-tlscfg-{}", to_hex(&random_bytes::<8>())));
    let id = tls::load_or_generate(&dir).unwrap();
    let cfg = axum_server::tls_rustls::RustlsConfig::from_pem(
        id.cert_pem.into_bytes(),
        id.key_pem.into_bytes(),
    )
    .await;
    assert!(cfg.is_ok(), "rustls 应接受 rcgen 生成的证书/私钥");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn forged_token_is_rejected() {
    let h = harness();
    // 用别的密钥签发的令牌（错 secret）应被拒
    let forged = crate::auth::token::issue(DeviceId::new(), Utc::now() + chrono::Duration::hours(1), &[1u8; 32]);
    let (st, _) = call(&h.app, "GET", "/v1/allowlist", Some(forged.as_str()), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(&h.data_dir);
}

/// 访问密钥门开启时：无/错密钥 → 连 `/healthz`、`/v1/pair` 都是裸 404（端口「变暗」）；
/// 正确密钥 → 正常放行。门挡在路由/JSON 解析之前。
#[tokio::test]
async fn access_gate_darkens_port_without_key() {
    let h = harness_cfg(true);

    let get_with = |key: Option<&str>| {
        let mut b = Request::builder().method("GET").uri("/healthz");
        if let Some(k) = key {
            b = b.header("x-ipgate-key", k);
        }
        b.body(Body::empty()).unwrap()
    };

    // 无密钥 → 404（不是 200 "ok"，扫描器看不到 ipgate）
    let resp = h.app.clone().oneshot(get_with(None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 错密钥 → 404
    let resp = h.app.clone().oneshot(get_with(Some("deadbeef"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 连 /v1/pair 也变暗：无密钥时哪怕发垃圾 body 也只得 404（根本到不了 JSON 解析）
    let (st, _) = call(&h.app, "POST", "/v1/pair", None, Some(b"garbage".to_vec())).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // 正确密钥 → 放行
    let resp = h
        .app
        .clone()
        .oneshot(get_with(Some(&h.access_key)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(&h.data_dir);
}
