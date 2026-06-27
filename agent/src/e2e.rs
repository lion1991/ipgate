//! 端到端测试（ADR 0007）：起 `serve_on` 于临时 loopback 端口，用真实 TCP + Noise
//! initiator 跑通握手 / 配对 / 鉴权 / JSON-RPC / serde。nft 后端用内存 mock。

use crate::api::{serve_on, AppState, RateLimiter};
use crate::auth::{pairing, AuthState};
use crate::config::AgentConfig;
use crate::nft::{NatBackend, NftBackend, ResolvedForward};
use crate::noise::{self, NoiseConn};
use crate::store::Store;
use crate::util::{random_bytes, to_hex};

use chrono::Utc;
use ipgate_proto::*;
use ipnet::IpNet;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};

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
            .map(|t| KernelElement { target: *t, expires_at: None })
            .collect())
    }
    fn flush(&self) -> anyhow::Result<()> {
        self.set.lock().unwrap().clear();
        Ok(())
    }
}

/// 内存版转发后端。
#[derive(Default)]
struct MockNat {
    applied: Mutex<Vec<ResolvedForward>>,
}

impl NatBackend for MockNat {
    fn apply_nat(&self, forwards: &[ResolvedForward]) -> anyhow::Result<()> {
        *self.applied.lock().unwrap() = forwards.to_vec();
        Ok(())
    }
    fn flush_nat(&self) -> anyhow::Result<()> {
        self.applied.lock().unwrap().clear();
        Ok(())
    }
}

struct Server {
    addr: std::net::SocketAddr,
    backend: Arc<MockNft>,
    data_dir: std::path::PathBuf,
    server_pub: Vec<u8>,
    psk: [u8; 32],
}

/// 起一个跑在临时 loopback 端口上的 agent。
async fn spawn() -> Server {
    let data_dir = std::env::temp_dir().join(format!("ipgate-e2e-{}", to_hex(&random_bytes::<8>())));
    let cfg = AgentConfig { data_dir: data_dir.clone(), ..AgentConfig::default() };
    let backend = Arc::new(MockNft::default());
    let store = Arc::new(Mutex::new(Store::load(&cfg.store_path()).unwrap()));
    let auth = AuthState::load_or_generate(&data_dir).unwrap();
    let psk = noise::derive_psk(&auth.access_key);
    let identity = noise::NoiseIdentity::load_or_generate(&data_dir).unwrap();
    let server_pub = identity.public().to_vec();
    let state = AppState {
        cfg: Arc::new(cfg),
        store,
        backend: backend.clone(),
        nat: Arc::new(MockNat::default()),
        dnat: Arc::new(crate::dnat::DnatAdapter::new(crate::dnat::DnatAdapterConfig::default())),
        rate: Arc::new(RateLimiter::new(120, std::time::Duration::from_secs(60))),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_on(state, identity, psk, listener).await;
    });
    Server { addr, backend, data_dir, server_pub, psk }
}

/// 生成一对设备密钥（private, public）。
fn gen_device() -> (Vec<u8>, Vec<u8>) {
    let kp = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();
    (kp.private, kp.public)
}

struct Client {
    conn: NoiseConn<TcpStream>,
}

async fn connect_with(
    srv: &Server,
    device_private: &[u8],
    hello: HandshakeHello,
) -> anyhow::Result<Client> {
    let stream = TcpStream::connect(srv.addr).await?;
    let (conn, _ack) =
        noise::connect(stream, &srv.server_pub, device_private, &srv.psk, &hello).await?;
    Ok(Client { conn })
}

impl Client {
    async fn rpc(&mut self, req: RpcRequest) -> RpcResponse {
        self.conn.send(&serde_json::to_vec(&req).unwrap()).await.unwrap();
        serde_json::from_slice(&self.conn.recv().await.unwrap()).unwrap()
    }

    /// 期望成功并反序列化结果。
    async fn ok<T: serde::de::DeserializeOwned>(&mut self, req: RpcRequest) -> T {
        match self.rpc(req).await {
            RpcResponse::Ok(v) => serde_json::from_value(v).unwrap(),
            RpcResponse::Err(e) => panic!("期望 Ok，得到 Err：{e:?}"),
        }
    }
}

fn new_code(srv: &Server) -> PairingCode {
    pairing::create(&srv.data_dir, PAIRING_CODE_TTL_SECS, Utc::now()).unwrap()
}

#[tokio::test]
async fn pairing_then_allowlist_flow() {
    let srv = spawn().await;
    let (priv_, _pub) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("phone".into()) },
    )
    .await
    .unwrap();

    let list: Allowlist = cli.ok(RpcRequest::ListAllowlist).await;
    assert!(list.entries.is_empty());

    let entry: Entry = cli
        .ok(RpcRequest::Allow(AllowRequest {
            target: "203.0.113.0/24".parse().unwrap(),
            note: "office".into(),
            expires_at: None,
        }))
        .await;
    assert_eq!(entry.target, "203.0.113.0/24".parse().unwrap());
    assert_eq!(srv.backend.set.lock().unwrap().len(), 1);

    let list: Allowlist = cli.ok(RpcRequest::ListAllowlist).await;
    assert_eq!(list.entries.len(), 1);

    assert!(matches!(
        cli.rpc(RpcRequest::Revoke(RevokeRequest::Target("203.0.113.0/24".parse().unwrap())))
            .await,
        RpcResponse::Ok(_)
    ));
    assert!(srv.backend.set.lock().unwrap().is_empty());

    let devices: Vec<Device> = cli.ok(RpcRequest::ListDevices).await;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "phone");

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

#[tokio::test]
async fn known_device_reconnects_and_unpaired_rejected() {
    let srv = spawn().await;
    let (priv_, _pub) = gen_device();

    // 首连带配对码 → 入网。
    {
        let mut cli = connect_with(
            &srv,
            &priv_,
            HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("phone".into()) },
        )
        .await
        .unwrap();
        let _: Allowlist = cli.ok(RpcRequest::ListAllowlist).await;
    }

    // 同设备密钥、无配对码重连 → 成功（已在授权列表）。
    assert!(
        connect_with(&srv, &priv_, HandshakeHello::default()).await.is_ok(),
        "已配对设备应免配对码重连"
    );

    // 全新密钥、无配对码 → authorize 拒绝 → 不回 msg2 → 客户端握手失败。
    let (priv2, _) = gen_device();
    assert!(
        connect_with(&srv, &priv2, HandshakeHello::default()).await.is_err(),
        "未配对且无配对码应被拒"
    );

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

#[tokio::test]
async fn wrong_pairing_code_rejected() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let res = connect_with(
        &srv,
        &priv_,
        HandshakeHello {
            pairing_code: Some(PairingCode::from("deadbeefdeadbeef")),
            device_name: Some("x".into()),
        },
    )
    .await;
    assert!(res.is_err(), "无效配对码应被拒（握手不完成）");
    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

#[tokio::test]
async fn forward_crud_flow() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();

    let list: UnifiedForwardList = cli.ok(RpcRequest::ListForwards).await;
    assert!(list.forwards.is_empty());
    assert_eq!(list.revision, 0);

    // 端口区间长度不一致 → BadRequest
    let bad = AddForwardRequest {
        proto: ForwardProto::Tcp,
        iface: Some("eth0".into()),
        listen: PortRange { start: 8000, end: 8010 },
        dest_host: "10.0.0.9".into(),
        dest_port: PortRange { start: 9000, end: 9005 },
        source: ForwardSource::Auto,
        note: String::new(),
    };
    match cli.rpc(RpcRequest::AddForward(bad)).await {
        RpcResponse::Err(e) => assert_eq!(e.code, ErrorCode::BadRequest),
        RpcResponse::Ok(_) => panic!("应 BadRequest"),
    }

    // 合法新增
    let req = AddForwardRequest {
        proto: ForwardProto::Both,
        iface: Some("eth0".into()),
        listen: PortRange::single(443),
        dest_host: "10.0.0.9".into(),
        dest_port: PortRange::single(8443),
        source: ForwardSource::Auto,
        note: "web".into(),
    };
    let view: ForwardView = cli.ok(RpcRequest::AddForward(req)).await;
    assert_eq!(view.rule.dest_host, "10.0.0.9");
    assert_eq!(view.rule.proto, ForwardProto::Both);
    let id = view.rule.id;

    let list: UnifiedForwardList = cli.ok(RpcRequest::ListForwards).await;
    assert_eq!(list.forwards.len(), 1);
    assert_eq!(list.revision, 1);
    assert_eq!(list.forwards[0].id, Some(id));
    assert_eq!(list.forwards[0].origin, ForwardOrigin::Ipgate);
    assert!(!list.forwards[0].conflict);

    // 删除不存在 → NotFound
    match cli.rpc(RpcRequest::RemoveForward(ForwardId::new())).await {
        RpcResponse::Err(e) => assert_eq!(e.code, ErrorCode::NotFound),
        _ => panic!("应 NotFound"),
    }
    // 删除该条 → Ok，列表回空
    assert!(matches!(cli.rpc(RpcRequest::RemoveForward(id)).await, RpcResponse::Ok(_)));
    let list: UnifiedForwardList = cli.ok(RpcRequest::ListForwards).await;
    assert!(list.forwards.is_empty());

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

#[tokio::test]
async fn ssh_exposure_toggle_flow() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();

    // 默认：对所有人开放。
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert!(!s.ssh_allowlist_only);
    assert_eq!(s.ssh_port, 22);

    // 名单为空时开启「仅名单」→ 被自锁防护拒绝。
    match cli.rpc(RpcRequest::SetSshExposure { allowlist_only: true }).await {
        RpcResponse::Err(e) => assert_eq!(e.code, ErrorCode::BadRequest),
        RpcResponse::Ok(_) => panic!("名单为空应拒绝开启仅名单"),
    }

    // 放行一个 IP 后再开启 → 成功。
    let _: Entry = cli
        .ok(RpcRequest::Allow(AllowRequest {
            target: "203.0.113.7/32".parse().unwrap(),
            note: "me".into(),
            expires_at: None,
        }))
        .await;
    let s: AgentSettings = cli.ok(RpcRequest::SetSshExposure { allowlist_only: true }).await;
    assert!(s.ssh_allowlist_only);

    // 持久化生效：重读为开。
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert!(s.ssh_allowlist_only);

    // 关回开放（任何时候都允许，不受名单约束）。
    let s: AgentSettings = cli.ok(RpcRequest::SetSshExposure { allowlist_only: false }).await;
    assert!(!s.ssh_allowlist_only);

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

#[tokio::test]
async fn whoami_reports_peer_ip() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: None },
    )
    .await
    .unwrap();
    let who: WhoamiResponse = cli.ok(RpcRequest::Whoami).await;
    assert!(who.ip.is_loopback(), "本测试经 loopback 连接");
    let _ = std::fs::remove_dir_all(&srv.data_dir);
}
