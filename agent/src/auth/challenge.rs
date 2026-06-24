//! 登录挑战：服务端下发单次 nonce，客户端签名后换令牌。
//!
//! 待签消息 = `域分隔 ‖ nonce ‖ 服务端SPKI指纹`。nonce 由服务端随机生成、单次、限时，
//! 已编码了新鲜度；指纹把签名**绑定到本服务端**，截获的签名无法重放到别处（ADR 0003）。

use crate::util::random_bytes;
use chrono::{DateTime, Duration, Utc};
use ipgate_proto::{DeviceId, Nonce, SpkiFingerprint, CHALLENGE_TTL_SECS};
use std::collections::HashMap;
use std::sync::Mutex;

use super::keys::B64;
use base64::Engine;

const DOMAIN: &[u8] = b"ipgate-auth-v1";

/// 构造待签消息。两端必须一致。
pub fn auth_message(nonce: &Nonce, fingerprint: &SpkiFingerprint) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOMAIN);
    m.push(0);
    m.extend_from_slice(nonce.as_str().as_bytes());
    m.push(0);
    m.extend_from_slice(fingerprint.as_str().as_bytes());
    m
}

/// 内存中的挑战存储（单次、限时）。
#[derive(Default)]
pub struct ChallengeStore {
    inner: Mutex<HashMap<DeviceId, (Nonce, DateTime<Utc>)>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 为设备签发新挑战，覆盖旧的；返回 nonce 及到期时间。
    pub fn issue(&self, device: DeviceId, now: DateTime<Utc>) -> (Nonce, DateTime<Utc>) {
        let nonce = Nonce::from(B64.encode(random_bytes::<32>()));
        let expires_at = now + Duration::seconds(CHALLENGE_TTL_SECS as i64);
        self.inner
            .lock()
            .unwrap()
            .insert(device, (nonce.clone(), expires_at));
        (nonce, expires_at)
    }

    /// 取出并消费设备的有效挑战；过期或不存在返回 `None`（单次）。
    pub fn take_valid(&self, device: DeviceId, now: DateTime<Utc>) -> Option<Nonce> {
        let (nonce, exp) = self.inner.lock().unwrap().remove(&device)?;
        (exp > now).then_some(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_then_take_is_single_use() {
        let store = ChallengeStore::new();
        let dev = DeviceId::new();
        let now = Utc::now();
        let (nonce, _) = store.issue(dev, now);
        assert_eq!(store.take_valid(dev, now), Some(nonce));
        // 第二次取不到（已消费）
        assert_eq!(store.take_valid(dev, now), None);
    }

    #[test]
    fn expired_challenge_rejected() {
        let store = ChallengeStore::new();
        let dev = DeviceId::new();
        let now = Utc::now();
        store.issue(dev, now);
        let later = now + Duration::seconds(CHALLENGE_TTL_SECS as i64 + 1);
        assert_eq!(store.take_valid(dev, later), None);
    }

    #[test]
    fn message_binds_nonce_and_fingerprint() {
        let n = Nonce::from("abc");
        let m1 = auth_message(&n, &SpkiFingerprint::from("AA:BB"));
        let m2 = auth_message(&n, &SpkiFingerprint::from("CC:DD"));
        assert_ne!(m1, m2, "不同指纹应得到不同待签消息");
    }
}
