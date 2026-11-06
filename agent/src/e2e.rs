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
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};

/// 内存版 nft 后端。
#[derive(Default)]
struct MockNft {
    set: Mutex<Vec<IpNet>>,
    /// 最近一次整表 apply 的配置（断言开关是否真的落到「内核」）。
    applied_cfg: Mutex<Option<RulesetConfig>>,
    /// 模拟老内核/老 nft 不认转发名单门的表达式。
    reject_gate: std::sync::atomic::AtomicBool,
    /// 模拟老内核/老 nft 不认敲门规则（`@th` 载荷匹配 / 动态 set）。
    reject_knock: std::sync::atomic::AtomicBool,
    /// 模拟与门无关的 nft 故障：任何整表 apply 都失败（内核保持旧表）。
    fail_apply: std::sync::atomic::AtomicBool,
}

impl NftBackend for MockNft {
    fn apply(&self, cfg: &RulesetConfig, entries: &[Entry]) -> anyhow::Result<()> {
        if self.fail_apply.load(std::sync::atomic::Ordering::SeqCst) {
            anyhow::bail!("Error: Could not process rule: No buffer space available");
        }
        if cfg.forward_allowlist_only && self.reject_gate.load(std::sync::atomic::Ordering::SeqCst) {
            anyhow::bail!("Error: syntax error, unexpected status");
        }
        if cfg.knock().is_some() && self.reject_knock.load(std::sync::atomic::Ordering::SeqCst) {
            anyhow::bail!("Error: syntax error, unexpected @");
        }
        *self.set.lock().unwrap() = entries.iter().map(|e| e.target).collect();
        *self.applied_cfg.lock().unwrap() = Some(cfg.clone());
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
    spawn_with(AgentConfig::default(), None).await
}

/// `state_json`：预置的 state.json（模拟升级前的旧部署）。
async fn spawn_with(base: AgentConfig, state_json: Option<&str>) -> Server {
    let data_dir = std::env::temp_dir().join(format!("ipgate-e2e-{}", to_hex(&random_bytes::<8>())));
    let cfg = AgentConfig { data_dir: data_dir.clone(), ..base }.with_knock().unwrap();
    if let Some(json) = state_json {
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(cfg.store_path(), json).unwrap();
    }
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
        live: Arc::new(crate::nft::Live::default()),
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
async fn forward_update_flow() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();

    let req = |listen: u16, dest: &str, note: &str| AddForwardRequest {
        proto: ForwardProto::Tcp,
        iface: Some("eth0".into()),
        listen: PortRange::single(listen),
        dest_host: dest.into(),
        dest_port: PortRange::single(8443),
        source: ForwardSource::Auto,
        note: note.into(),
    };
    let a: ForwardView = cli.ok(RpcRequest::AddForward(req(443, "10.0.0.9", "web"))).await;
    let b: ForwardView = cli.ok(RpcRequest::AddForward(req(80, "10.0.0.9", ""))).await;

    // 原地修改：id 不变，字段更新
    let edited: ForwardView = cli
        .ok(RpcRequest::UpdateForward { id: a.rule.id, rule: req(8443, "10.0.0.10", "web2") })
        .await;
    assert_eq!(edited.rule.id, a.rule.id);
    assert_eq!(edited.rule.created_at, a.rule.created_at);
    let list: UnifiedForwardList = cli.ok(RpcRequest::ListForwards).await;
    assert_eq!(list.forwards.len(), 2);
    assert_eq!(list.revision, 3);
    let row = list.forwards.iter().find(|f| f.id == Some(a.rule.id)).unwrap();
    assert_eq!((row.listen, row.dest_host.as_str(), row.note.as_str()), (PortRange::single(8443), "10.0.0.10", "web2"));

    // 改到另一条已占用的端口 → Conflict，原规则不动
    match cli.rpc(RpcRequest::UpdateForward { id: a.rule.id, rule: req(80, "10.0.0.10", "") }).await {
        RpcResponse::Err(e) => assert_eq!(e.code, ErrorCode::Conflict),
        RpcResponse::Ok(_) => panic!("应 Conflict"),
    }
    // 不存在 → NotFound；非法入参 → BadRequest
    match cli.rpc(RpcRequest::UpdateForward { id: ForwardId::new(), rule: req(9000, "10.0.0.9", "") }).await {
        RpcResponse::Err(e) => assert_eq!(e.code, ErrorCode::NotFound),
        RpcResponse::Ok(_) => panic!("应 NotFound"),
    }
    match cli.rpc(RpcRequest::UpdateForward { id: b.rule.id, rule: req(80, "127.0.0.1", "") }).await {
        RpcResponse::Err(e) => assert_eq!(e.code, ErrorCode::BadRequest),
        RpcResponse::Ok(_) => panic!("应 BadRequest"),
    }
    let list: UnifiedForwardList = cli.ok(RpcRequest::ListForwards).await;
    assert_eq!(list.revision, 3);

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
    // 敲门随「仅名单」一起落地（ADR 0012），端口由 access key 派生、与 agent 自己算的一致。
    let knock = crate::auth::derive_knock(&AuthState::load_or_generate(&srv.data_dir).unwrap().access_key);
    assert_eq!((s.ssh_knock_port, s.ssh_knock_active), (Some(knock.port), Some(true)));
    assert_eq!(applied_knock(&srv), Some(knock));

    // 持久化生效：重读为开。
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert!(s.ssh_allowlist_only);

    // 关回开放（任何时候都允许，不受名单约束）；敲门不再渲染。
    let s: AgentSettings = cli.ok(RpcRequest::SetSshExposure { allowlist_only: false }).await;
    assert!(!s.ssh_allowlist_only);
    assert_eq!(s.ssh_knock_active, Some(false));
    assert_eq!(applied_knock(&srv), None);

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

/// 最近一次整表 apply 实际渲染的敲门参数（`None` = 没有敲门规则）。
fn applied_knock(srv: &Server) -> Option<SshKnock> {
    srv.backend.applied_cfg.lock().unwrap().as_ref().unwrap().knock().cloned()
}

/// 内核不认敲门时开启「仅名单」：报错、恢复原 ruleset、不改设置——没有敲门的「仅名单」
/// 会把常换网络的设备挡在外（ADR 0012 决策 7）。
#[tokio::test]
async fn ssh_allowlist_only_refused_when_kernel_rejects_knock() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();
    let _: Entry = cli
        .ok(RpcRequest::Allow(AllowRequest {
            target: "203.0.113.7/32".parse().unwrap(),
            note: "me".into(),
            expires_at: None,
        }))
        .await;
    srv.backend.reject_knock.store(true, Ordering::SeqCst);

    expect_nft_failure(&mut cli, RpcRequest::SetSshExposure { allowlist_only: true }).await;
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert!(!s.ssh_allowlist_only);
    assert_eq!(s.ssh_knock_active, Some(false));
    let applied = srv.backend.applied_cfg.lock().unwrap().clone().unwrap();
    assert!(!applied.ssh_allowlist_only, "内核须恢复为 SSH 对全网开放");

    // 内核支持后再开 → 生效。
    srv.backend.reject_knock.store(false, Ordering::SeqCst);
    let s: AgentSettings = cli.ok(RpcRequest::SetSshExposure { allowlist_only: true }).await;
    assert_eq!((s.ssh_allowlist_only, s.ssh_knock_active), (true, Some(true)));

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

/// 已开「仅名单」后内核不再认敲门（如换了内核）：其他整表重建照常完成，保留「仅名单」
/// （不悄悄放开 SSH），上报敲门未生效。
#[tokio::test]
async fn knock_lost_on_rebuild_keeps_allowlist_only() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();
    let _: Entry = cli
        .ok(RpcRequest::Allow(AllowRequest {
            target: "203.0.113.7/32".parse().unwrap(),
            note: "me".into(),
            expires_at: None,
        }))
        .await;
    let _: AgentSettings = cli.ok(RpcRequest::SetSshExposure { allowlist_only: true }).await;
    srv.backend.reject_knock.store(true, Ordering::SeqCst);

    let s: AgentSettings = cli.ok(RpcRequest::SetForwardExposure { allowlist_only: true }).await;
    assert_eq!((s.ssh_allowlist_only, s.ssh_knock_active), (true, Some(false)));
    assert_eq!(s.forward_gate_active, Some(true));
    let applied = srv.backend.applied_cfg.lock().unwrap().clone().unwrap();
    assert!(applied.ssh_allowlist_only && applied.knock().is_none());

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

fn applied_gate(srv: &Server) -> bool {
    srv.backend.applied_cfg.lock().unwrap().as_ref().unwrap().forward_allowlist_only
}

#[tokio::test]
async fn forward_exposure_toggle_flow() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();

    // 默认：门关（转发对全网开放）。
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert_eq!(s.forward_allowlist_only, Some(false));
    assert_eq!(s.forward_gate_active, Some(false));

    // 开门：名单为空也允许（管理走 SSH input 链，不会自锁）。
    let s: AgentSettings = cli.ok(RpcRequest::SetForwardExposure { allowlist_only: true }).await;
    assert_eq!(s.forward_allowlist_only, Some(true));
    assert_eq!(s.forward_gate_active, Some(true));
    assert!(applied_gate(&srv));

    // 切 SSH 暴露会整表重建：门必须随之保留，不能被冲掉。
    let _: Entry = cli
        .ok(RpcRequest::Allow(AllowRequest {
            target: "203.0.113.7/32".parse().unwrap(),
            note: "me".into(),
            expires_at: None,
        }))
        .await;
    let _: AgentSettings = cli.ok(RpcRequest::SetSshExposure { allowlist_only: true }).await;
    assert!(applied_gate(&srv));

    // 关门。
    let s: AgentSettings = cli.ok(RpcRequest::SetForwardExposure { allowlist_only: false }).await;
    assert_eq!(s.forward_allowlist_only, Some(false));
    assert_eq!(s.forward_gate_active, Some(false));
    assert!(!applied_gate(&srv));

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

#[tokio::test]
async fn forward_exposure_rejected_when_kernel_lacks_support() {
    let srv = spawn().await;
    srv.backend.reject_gate.store(true, std::sync::atomic::Ordering::SeqCst);
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();

    let e = expect_nft_failure(&mut cli, RpcRequest::SetForwardExposure { allowlist_only: true }).await;
    assert!(e.contains("syntax error"), "应附上 nft 原始错误，便于区分「不支持」与临时故障：{e}");
    // 失败不落盘：设置仍是关，「内核」仍是无门 ruleset。
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert_eq!(s.forward_allowlist_only, Some(false));
    assert_eq!(s.forward_gate_active, Some(false));
    assert!(!applied_gate(&srv));

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

async fn expect_nft_failure(cli: &mut Client, req: RpcRequest) -> String {
    match cli.rpc(req).await {
        RpcResponse::Err(e) => {
            assert_eq!(e.code, ErrorCode::NftFailure);
            e.message
        }
        RpcResponse::Ok(v) => panic!("期望 NftFailure，得到 Ok：{v}"),
    }
}

/// nft 整表 apply 失败（与门无关）时内核保持旧表，开关也不能落盘——否则「设置」与内核分叉，
/// 且下次重启才突然生效。开、关两个方向都要成立。
#[tokio::test]
async fn forward_exposure_apply_failure_leaves_setting_unchanged() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();
    let off = Ordering::SeqCst;

    srv.backend.fail_apply.store(true, off);
    expect_nft_failure(&mut cli, RpcRequest::SetForwardExposure { allowlist_only: true }).await;
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert_eq!((s.forward_allowlist_only, s.forward_gate_active), (Some(false), Some(false)));

    srv.backend.fail_apply.store(false, off);
    let _: AgentSettings = cli.ok(RpcRequest::SetForwardExposure { allowlist_only: true }).await;
    srv.backend.fail_apply.store(true, off);
    expect_nft_failure(&mut cli, RpcRequest::SetForwardExposure { allowlist_only: false }).await;
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert_eq!((s.forward_allowlist_only, s.forward_gate_active), (Some(true), Some(true)));
    assert!(applied_gate(&srv), "关门失败时内核仍带门，设置不能显示为已关");

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

/// 门曾生效、后因内核不再支持而回退（意图开、实际未生效）：重试开启仍失败时保留意图，
/// 客户端继续显示「已开启但未生效」；内核恢复支持后重试即生效。
#[tokio::test]
async fn forward_gate_retry_keeps_intent_until_kernel_accepts() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();
    let off = Ordering::SeqCst;

    let _: AgentSettings = cli.ok(RpcRequest::SetForwardExposure { allowlist_only: true }).await;
    srv.backend.reject_gate.store(true, off);
    // 任意整表重建（这里是切 SSH 暴露）遇到门被拒 → 退回无门，SSH 开关照常生效。
    let s: AgentSettings = cli.ok(RpcRequest::SetSshExposure { allowlist_only: false }).await;
    assert_eq!((s.forward_allowlist_only, s.forward_gate_active), (Some(true), Some(false)));

    expect_nft_failure(&mut cli, RpcRequest::SetForwardExposure { allowlist_only: true }).await;
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert_eq!((s.forward_allowlist_only, s.forward_gate_active), (Some(true), Some(false)));
    assert!(!applied_gate(&srv));

    srv.backend.reject_gate.store(false, off);
    let s: AgentSettings = cli.ok(RpcRequest::SetForwardExposure { allowlist_only: true }).await;
    assert_eq!((s.forward_allowlist_only, s.forward_gate_active), (Some(true), Some(true)));
    assert!(applied_gate(&srv));

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

/// P1 修复：撤销设备会立刻断掉它的**在途** Noise 连接（原先只改 store，连接照用）。
#[tokio::test]
async fn revoke_device_closes_live_connection() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("phone".into()) },
    )
    .await
    .unwrap();

    // 拿到本设备 id。
    let devices: Vec<Device> = cli.ok(RpcRequest::ListDevices).await;
    let id = devices[0].id;

    // 自撤销：这条请求本身仍被处理（循环顶部复验时设备尚在）。
    assert!(matches!(cli.rpc(RpcRequest::RevokeDevice(id)).await, RpcResponse::Ok(_)));

    // 下一条请求：循环顶部复验发现设备已撤销 → agent 关连接，客户端 recv 拿到 EOF/错误。
    cli.conn
        .send(&serde_json::to_vec(&RpcRequest::ListAllowlist).unwrap())
        .await
        .unwrap();
    assert!(cli.conn.recv().await.is_err(), "撤销后在途连接应被 agent 关闭");

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

fn applied_public(srv: &Server) -> (Vec<PortRange>, Vec<PortRange>) {
    let cfg = srv.backend.applied_cfg.lock().unwrap().clone().unwrap();
    (cfg.public_tcp, cfg.public_udp)
}

fn public_req(proto: ForwardProto, start: u16, end: u16, note: &str) -> RpcRequest {
    RpcRequest::AddPublicPort(PublicPortRequest {
        proto,
        ports: PortRange { start, end },
        note: note.into(),
    })
}

async fn expect_code(cli: &mut Client, req: RpcRequest, code: ErrorCode) -> String {
    match cli.rpc(req).await {
        RpcResponse::Err(e) => {
            assert_eq!(e.code, code, "{}", e.message);
            e.message
        }
        RpcResponse::Ok(v) => panic!("应失败，实际成功：{v}"),
    }
}

#[tokio::test]
async fn public_ports_flow() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();

    let l: Vec<PublicPort> = cli.ok(RpcRequest::ListPublicPorts).await;
    assert!(l.is_empty());

    let l: Vec<PublicPort> = cli.ok(public_req(ForwardProto::Tcp, 443, 443, " web ")).await;
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].note, "web");
    assert!(!l[0].from_config);
    assert_eq!(applied_public(&srv).0, vec![PortRange::single(443)]);

    // 同端口再加 = 改备注，不重复。
    let l: Vec<PublicPort> = cli.ok(public_req(ForwardProto::Tcp, 443, 443, "https")).await;
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].note, "https");

    let _: Vec<PublicPort> = cli.ok(public_req(ForwardProto::Both, 25565, 25565, "mc")).await;
    assert_eq!(applied_public(&srv), (
        vec![PortRange::single(443), PortRange::single(25565)],
        vec![PortRange::single(25565)],
    ));

    let l: Vec<PublicPort> = cli
        .ok(RpcRequest::RemovePublicPort { proto: ForwardProto::Tcp, ports: PortRange::single(443) })
        .await;
    assert_eq!(l.len(), 1);
    assert_eq!(applied_public(&srv).0, vec![PortRange::single(25565)]);
    expect_code(
        &mut cli,
        RpcRequest::RemovePublicPort { proto: ForwardProto::Tcp, ports: PortRange::single(443) },
        ErrorCode::NotFound,
    )
    .await;
    expect_code(&mut cli, public_req(ForwardProto::Tcp, 0, 10, ""), ErrorCode::BadRequest).await;
    expect_code(&mut cli, public_req(ForwardProto::Tcp, 90, 80, ""), ErrorCode::BadRequest).await;

    // 内核落地失败：存储不变。
    srv.backend.fail_apply.store(true, Ordering::SeqCst);
    expect_code(&mut cli, public_req(ForwardProto::Udp, 53, 53, ""), ErrorCode::NftFailure).await;
    srv.backend.fail_apply.store(false, Ordering::SeqCst);
    let l: Vec<PublicPort> = cli.ok(RpcRequest::ListPublicPorts).await;
    assert_eq!(l.len(), 1);

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

#[tokio::test]
async fn public_ports_never_override_ssh_allowlist_only() {
    let srv = spawn().await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();
    let _: Entry = cli
        .ok(RpcRequest::Allow(AllowRequest {
            target: "203.0.113.7/32".parse().unwrap(),
            note: "me".into(),
            expires_at: None,
        }))
        .await;

    // SSH 仅名单时：覆盖 22 的 TCP 公开端口被拒；UDP 不影响 SSH，允许。
    let _: AgentSettings = cli.ok(RpcRequest::SetSshExposure { allowlist_only: true }).await;
    let msg = expect_code(&mut cli, public_req(ForwardProto::Both, 20, 30, ""), ErrorCode::BadRequest).await;
    assert!(msg.contains("安全"), "{msg}");
    let _: Vec<PublicPort> = cli.ok(public_req(ForwardProto::Udp, 22, 22, "")).await;

    // SSH 对全网开放时可以加 22；之后再开「仅名单」被拒（否则开关显示开、实际仍全网可连）。
    let _: AgentSettings = cli.ok(RpcRequest::SetSshExposure { allowlist_only: false }).await;
    let _: Vec<PublicPort> = cli.ok(public_req(ForwardProto::Tcp, 22, 22, "")).await;
    expect_code(&mut cli, RpcRequest::SetSshExposure { allowlist_only: true }, ErrorCode::BadRequest).await;
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert!(!s.ssh_allowlist_only);

    let _ = std::fs::remove_dir_all(&srv.data_dir);
}

#[tokio::test]
async fn legacy_config_ssh_overlap_does_not_block_unrelated_public_ports() {
    // 旧部署：config.json 公开 1-1024（含 22）且已开 SSH 仅名单——升级前两者可共存。
    let srv = spawn_with(
        AgentConfig { public_tcp: vec![PortRange { start: 1, end: 1024 }], ..AgentConfig::default() },
        Some(r#"{"entries":[],"devices":[],"revision":0,"ssh_allowlist_only":true}"#),
    )
    .await;
    let (priv_, _) = gen_device();
    let mut cli = connect_with(
        &srv,
        &priv_,
        HandshakeHello { pairing_code: Some(new_code(&srv)), device_name: Some("x".into()) },
    )
    .await
    .unwrap();
    let s: AgentSettings = cli.ok(RpcRequest::GetSettings).await;
    assert!(s.ssh_allowlist_only);
    let l: Vec<PublicPort> = cli.ok(RpcRequest::ListPublicPorts).await;
    assert!(l[0].from_config);
    let _: Vec<PublicPort> = cli.ok(public_req(ForwardProto::Tcp, 8080, 8080, "")).await;
    // 新增的覆盖 22 照样拒。
    expect_code(&mut cli, public_req(ForwardProto::Tcp, 22, 22, ""), ErrorCode::BadRequest).await;
    let _ = std::fs::remove_dir_all(&srv.data_dir);
}
