//! Noise_IKpsk0 over TCP（ADR 0007）：取代 0003 的 TLS 传输层。
//!
//! agent 是 responder，只在 loopback 监听；客户端经 SSH 隧道连入。`psk0` 把由
//! 128-bit access key 派生的 32B PSK 在 msg1 之前混入握手——不持 PSK 者连合法
//! msg1 都造不出，本方静默拒绝（不回包＝不可探测）。握手用 `IK`：客户端预先知道
//! agent 静态公钥（＝指纹钉扎），其自身静态公钥在 msg1 中加密送达（＝设备身份）。
//!
//! 握手成功后用「u16 长度前缀分帧 + 每帧 AEAD」承载 JSON-RPC（见 `proto::rpc`）。
//! 逻辑消息可超过单帧上限：发端加 4B 大端长度头后分块，收端累积到长度为止。

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use ipgate_proto::{
    HandshakeAck, HandshakeHello, NoisePublicKey, NOISE_MAX_FRAME, NOISE_PATTERN, NOISE_PROLOGUE,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 静态密钥持久化文件（`data_dir/noise_static.key`，0600，内容 = priv32‖pub32）。
const STATIC_FILE: &str = "noise_static.key";

/// 单条逻辑消息（解密后）字节上限。`RpcRequest` 实际只有几 KB；设 1 MiB 已极宽松，
/// 用来挡住 4B 长度头声明上 GiB、再灌帧把堆撑爆 OOM 杀掉 root 守护进程的 DoS（P1 修复）。
const NOISE_MAX_MSG: usize = 1 << 20;

fn params() -> Result<snow::params::NoiseParams> {
    NOISE_PATTERN.parse().context("Noise 模式串非法")
}

/// 由 access key 派生定长 32B PSK（psk0 要求 32 字节）。两端用相同算法导出。
pub fn derive_psk(access_key: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ipgate-noise-psk-v1");
    h.update(access_key.as_bytes());
    h.finalize().into()
}

/// agent 的 Noise 长期静态身份（X25519）。私钥 0600 持久化。
pub struct NoiseIdentity {
    private: Vec<u8>,
    public: Vec<u8>,
}

impl NoiseIdentity {
    /// 载入或首次生成静态密钥对。文件 = priv(32)‖pub(32)。
    pub fn load_or_generate(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(STATIC_FILE);
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.len() == 64 {
                return Ok(Self {
                    private: bytes[..32].to_vec(),
                    public: bytes[32..].to_vec(),
                });
            }
            // 长度不符＝损坏：重建（旧部署无此文件，正常走生成分支）。
        }
        let kp = snow::Builder::new(params()?)
            .generate_keypair()
            .map_err(|e| anyhow::anyhow!("生成 Noise 静态密钥失败：{e}"))?;
        let mut blob = Vec::with_capacity(64);
        blob.extend_from_slice(&kp.private);
        blob.extend_from_slice(&kp.public);
        crate::util::write_private(&path, &blob).context("写入 noise_static.key 失败")?;
        Ok(Self {
            private: kp.private,
            public: kp.public,
        })
    }

    /// 静态公钥的线上表示（base64 无填充）——写进二维码、供客户端钉死。
    pub fn public_b64(&self) -> NoisePublicKey {
        NoisePublicKey::from(STANDARD_NO_PAD.encode(&self.public))
    }

    /// 静态公钥原始字节（e2e 用，作为 initiator 的 remote_public_key）。
    #[cfg(test)]
    pub(crate) fn public(&self) -> &[u8] {
        &self.public
    }
}

/// 测试用 initiator：模拟客户端的「连入」侧（生产客户端在 client crate 另有实现）。
#[cfg(test)]
pub(crate) async fn connect<S>(
    mut stream: S,
    server_static: &[u8],
    device_private: &[u8],
    psk: &[u8; 32],
    hello: &HandshakeHello,
) -> Result<(NoiseConn<S>, HandshakeAck)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = snow::Builder::new(params()?)
        .local_private_key(device_private)
        .and_then(|b| b.remote_public_key(server_static))
        .and_then(|b| b.prologue(NOISE_PROLOGUE))
        .and_then(|b| b.psk(0, psk))
        .and_then(|b| b.build_initiator())
        .map_err(|e| anyhow::anyhow!("构建 Noise initiator 失败：{e}"))?;
    let mut buf = vec![0u8; 1024];
    let n = hs
        .write_message(&serde_json::to_vec(hello)?, &mut buf)
        .map_err(|e| anyhow::anyhow!("msg1 失败：{e}"))?;
    write_frame(&mut stream, &buf[..n]).await?;
    let frame = read_frame(&mut stream).await?;
    let mut out = vec![0u8; frame.len()];
    let n = hs
        .read_message(&frame, &mut out)
        .map_err(|e| anyhow::anyhow!("msg2 失败：{e}"))?;
    let ack: HandshakeAck = serde_json::from_slice(&out[..n])?;
    let transport = hs
        .into_transport_mode()
        .map_err(|e| anyhow::anyhow!("进入传输模式失败：{e}"))?;
    let peer = NoisePublicKey::from(STANDARD_NO_PAD.encode(server_static));
    Ok((NoiseConn { stream, transport, peer }, ack))
}

/// 已建立的 Noise 传输连接：长度前缀分帧 + AEAD 收发。
pub struct NoiseConn<S> {
    stream: S,
    transport: snow::TransportState,
    peer: NoisePublicKey,
}

impl<S: AsyncRead + AsyncWrite + Unpin> NoiseConn<S> {
    /// 对端（客户端）的 Noise 静态公钥——即设备身份。
    pub fn peer(&self) -> &NoisePublicKey {
        &self.peer
    }

    /// 收一条逻辑明文消息（累积多帧到 4B 长度头指示的长度为止）。
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let mut total: Option<usize> = None;
        loop {
            let frame = read_frame(&mut self.stream).await?;
            let mut buf = vec![0u8; frame.len()];
            let n = self
                .transport
                .read_message(&frame, &mut buf)
                .map_err(|e| anyhow::anyhow!("Noise 解密失败：{e}"))?;
            // 0 明文帧（如只含 16B AEAD tag）永不合法：send() 每条逻辑消息首帧必带 4B 长度头。
            // 不挡的话攻击者可一直灌这种帧，out 永不前进、卡在长度判定前空转（绕过长度上限）。
            if n == 0 {
                bail!("收到空明文 Noise 帧");
            }
            buf.truncate(n);
            out.extend_from_slice(&buf);
            if total.is_none() {
                if out.len() < 4 {
                    continue;
                }
                let len = u32::from_be_bytes(out[..4].try_into().unwrap()) as usize;
                if len > NOISE_MAX_MSG {
                    bail!("Noise 逻辑消息过大：{len} 字节 > 上限 {NOISE_MAX_MSG}");
                }
                out.drain(..4);
                total = Some(len);
            }
            if out.len() >= total.unwrap() {
                break;
            }
        }
        out.truncate(total.unwrap());
        Ok(out)
    }

    /// 发一条逻辑明文消息（加 4B 长度头 → 分块 → 每块一帧 AEAD）。
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut msg = Vec::with_capacity(4 + plaintext.len());
        msg.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        msg.extend_from_slice(plaintext);
        for chunk in msg.chunks(NOISE_MAX_FRAME) {
            let mut buf = vec![0u8; chunk.len() + 16];
            let n = self
                .transport
                .write_message(chunk, &mut buf)
                .map_err(|e| anyhow::anyhow!("Noise 加密失败：{e}"))?;
            write_frame(&mut self.stream, &buf[..n]).await?;
        }
        Ok(())
    }
}

/// 在已接受的连接上完成 responder 握手。
///
/// `authorize` 拿到对端静态公钥 + 客户端 hello，做**同步**鉴权决策（查授权列表 /
/// 消费配对码），返回要回给客户端的 [`HandshakeAck`]；返回 `Err` 则不发 msg2、
/// 直接关连接（对探测者静默）。
pub async fn accept<S, F>(
    mut stream: S,
    identity: &NoiseIdentity,
    psk: &[u8; 32],
    authorize: F,
) -> Result<NoiseConn<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&NoisePublicKey, HandshakeHello) -> Result<HandshakeAck>,
{
    let mut hs = snow::Builder::new(params()?)
        .local_private_key(&identity.private)
        .and_then(|b| b.prologue(NOISE_PROLOGUE))
        .and_then(|b| b.psk(0, psk))
        .and_then(|b| b.build_responder())
        .map_err(|e| anyhow::anyhow!("构建 Noise responder 失败：{e}"))?;

    // msg1：e, es, s, ss + 加密的 HandshakeHello。
    let frame = read_frame(&mut stream).await?;
    let mut payload = vec![0u8; frame.len()];
    let n = hs
        .read_message(&frame, &mut payload)
        .map_err(|e| anyhow::anyhow!("Noise msg1 解析失败（PSK/前言不符或非 ipgate 流量）：{e}"))?;
    payload.truncate(n);

    let remote = hs.get_remote_static().context("握手缺少对端静态公钥")?;
    let peer = NoisePublicKey::from(STANDARD_NO_PAD.encode(remote));
    let hello: HandshakeHello = if payload.is_empty() {
        HandshakeHello::default()
    } else {
        serde_json::from_slice(&payload).context("HandshakeHello 解析失败")?
    };

    // 同步鉴权决策（锁 store、消费配对码都在这里）。
    let ack = authorize(&peer, hello)?;

    // msg2：e, ee, se + 加密的 HandshakeAck。
    let ack_bytes = serde_json::to_vec(&ack)?;
    let mut buf = vec![0u8; ack_bytes.len() + 96];
    let n = hs
        .write_message(&ack_bytes, &mut buf)
        .map_err(|e| anyhow::anyhow!("Noise msg2 失败：{e}"))?;
    write_frame(&mut stream, &buf[..n]).await?;

    let transport = hs
        .into_transport_mode()
        .map_err(|e| anyhow::anyhow!("进入 Noise 传输模式失败：{e}"))?;
    Ok(NoiseConn {
        stream,
        transport,
        peer,
    })
}

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await.context("读 Noise 帧长失败")?;
    let n = u16::from_be_bytes(len) as usize;
    if n == 0 {
        bail!("收到空 Noise 帧");
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await.context("读 Noise 帧体失败")?;
    Ok(buf)
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> Result<()> {
    debug_assert!(data.len() <= u16::MAX as usize);
    s.write_all(&(data.len() as u16).to_be_bytes()).await?;
    s.write_all(data).await?;
    s.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipgate_proto::DeviceId;

    #[tokio::test]
    async fn handshake_pair_and_roundtrip() {
        let psk = derive_psk("test-access-key");
        let srv_kp = snow::Builder::new(params().unwrap()).generate_keypair().unwrap();
        let cli_kp = snow::Builder::new(params().unwrap()).generate_keypair().unwrap();
        let identity = NoiseIdentity {
            private: srv_kp.private.clone(),
            public: srv_kp.public.clone(),
        };
        let srv_pub = srv_kp.public.clone();
        let cli_pub_b64 = STANDARD_NO_PAD.encode(&cli_kp.public);

        let (cli_io, srv_io) = tokio::io::duplex(16 * 1024);

        // ---- 服务端：accept → recv → send ----
        let server = tokio::spawn(async move {
            let mut conn = accept(srv_io, &identity, &psk, |peer, hello| {
                assert_eq!(peer.as_str(), cli_pub_b64);
                assert_eq!(hello.device_name.as_deref(), Some("phone"));
                Ok(HandshakeAck {
                    device_id: DeviceId::new(),
                    paired: true,
                })
            })
            .await
            .unwrap();
            let msg = conn.recv().await.unwrap();
            assert_eq!(msg, b"ping");
            conn.send(b"pong").await.unwrap();
        });

        // ---- 客户端：手搓 initiator 走同样的分帧 ----
        let mut hs = snow::Builder::new(params().unwrap())
            .local_private_key(&cli_kp.private)
            .and_then(|b| b.remote_public_key(&srv_pub))
            .and_then(|b| b.prologue(NOISE_PROLOGUE))
            .and_then(|b| b.psk(0, &psk))
            .and_then(|b| b.build_initiator())
            .unwrap();
        let hello = HandshakeHello {
            pairing_code: None,
            device_name: Some("phone".into()),
        };
        let mut buf = vec![0u8; 1024];
        let mut cli_io = cli_io;
        let n = hs.write_message(&serde_json::to_vec(&hello).unwrap(), &mut buf).unwrap();
        write_frame(&mut cli_io, &buf[..n]).await.unwrap();
        let frame = read_frame(&mut cli_io).await.unwrap();
        let n = hs.read_message(&frame, &mut buf).unwrap();
        let ack: HandshakeAck = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(ack.paired);
        let transport = hs.into_transport_mode().unwrap();

        let mut conn = NoiseConn {
            stream: cli_io,
            transport,
            peer: NoisePublicKey::from(String::new()),
        };
        conn.send(b"ping").await.unwrap();
        assert_eq!(conn.recv().await.unwrap(), b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_psk_handshake_fails() {
        let srv_kp = snow::Builder::new(params().unwrap()).generate_keypair().unwrap();
        let cli_kp = snow::Builder::new(params().unwrap()).generate_keypair().unwrap();
        let identity = NoiseIdentity {
            private: srv_kp.private.clone(),
            public: srv_kp.public.clone(),
        };
        let srv_pub = srv_kp.public.clone();
        let (cli_io, srv_io) = tokio::io::duplex(16 * 1024);

        let server = tokio::spawn(async move {
            // 服务端用正确 PSK；客户端用错的 → msg1 解析必失败。
            accept(srv_io, &identity, &derive_psk("right"), |_p, _h| {
                Ok(HandshakeAck { device_id: DeviceId::new(), paired: false })
            })
            .await
        });

        let wrong = derive_psk("wrong");
        let mut hs = snow::Builder::new(params().unwrap())
            .local_private_key(&cli_kp.private)
            .and_then(|b| b.remote_public_key(&srv_pub))
            .and_then(|b| b.prologue(NOISE_PROLOGUE))
            .and_then(|b| b.psk(0, &wrong))
            .and_then(|b| b.build_initiator())
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let mut cli_io = cli_io;
        let n = hs.write_message(&[], &mut buf).unwrap();
        let _ = write_frame(&mut cli_io, &buf[..n]).await;
        assert!(server.await.unwrap().is_err(), "错误 PSK 应导致 responder 握手失败");
    }
}
