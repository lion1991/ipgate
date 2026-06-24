//! 会话令牌：不透明字符串 = `device_id(16) ‖ expiry_be(8) ‖ HMAC-SHA256(32)`，base64。
//!
//! 不用 JWT（避开 alg 混淆等坑）。HMAC 密钥（agent secret）持久在 data_dir。

use super::keys::B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use ipgate_proto::{DeviceId, SessionToken};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const PAYLOAD_LEN: usize = 16 + 8;
const TAG_LEN: usize = 32;

fn append_tag(secret: &[u8], payload: &[u8], out: &mut Vec<u8>) {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC 接受任意长度密钥");
    mac.update(payload);
    out.extend_from_slice(&mac.finalize().into_bytes());
}

fn tag_ok(secret: &[u8], payload: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC 接受任意长度密钥");
    mac.update(payload);
    mac.verify_slice(tag).is_ok() // 常数时间比较
}

/// 签发令牌。
pub fn issue(device: DeviceId, expires_at: DateTime<Utc>, secret: &[u8]) -> SessionToken {
    let mut buf = Vec::with_capacity(PAYLOAD_LEN + TAG_LEN);
    buf.extend_from_slice(device.0.as_bytes());
    buf.extend_from_slice(&expires_at.timestamp().to_be_bytes());
    let payload = buf.clone();
    append_tag(secret, &payload, &mut buf);
    SessionToken::from(B64.encode(buf))
}

/// 校验令牌，成功返回设备 id；失败（篡改/过期/格式错）返回 `None`。
pub fn verify(token: &SessionToken, now: DateTime<Utc>, secret: &[u8]) -> Option<DeviceId> {
    let buf = B64.decode(token.as_str()).ok()?;
    if buf.len() != PAYLOAD_LEN + TAG_LEN {
        return None;
    }
    let (payload, tag) = buf.split_at(PAYLOAD_LEN);
    if !tag_ok(secret, payload, tag) {
        return None;
    }
    let exp = i64::from_be_bytes(payload[16..24].try_into().ok()?);
    if exp <= now.timestamp() {
        return None;
    }
    Some(DeviceId(Uuid::from_slice(&payload[0..16]).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn issue_then_verify_roundtrips() {
        let secret = [3u8; 32];
        let dev = DeviceId::new();
        let now = Utc::now();
        let tok = issue(dev, now + Duration::minutes(15), &secret);
        assert_eq!(verify(&tok, now, &secret), Some(dev));
    }

    #[test]
    fn rejects_expired_wrong_secret_and_tamper() {
        let secret = [3u8; 32];
        let dev = DeviceId::new();
        let now = Utc::now();

        let expired = issue(dev, now - Duration::seconds(1), &secret);
        assert_eq!(verify(&expired, now, &secret), None);

        let tok = issue(dev, now + Duration::minutes(15), &secret);
        assert_eq!(verify(&tok, now, &[9u8; 32]), None); // 错密钥

        let mut raw = B64.decode(tok.as_str()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff; // 篡改 tag
        assert_eq!(
            verify(&SessionToken::from(B64.encode(raw)), now, &secret),
            None
        );
    }
}
