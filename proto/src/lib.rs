//! ipgate 客户端与 agent 共享的协议类型 —— 单一可信源。
//!
//! 这里只放**类型与常量**，不含传输/落地实现。设计依据见仓库
//! `docs/adr/`：
//! - ADR 0001 整体架构（客户端 / agent / proto）
//! - ADR 0002 nftables 落地（全主机 default-drop、`inet ipgate` 表）
//! - ADR 0003 传输与鉴权（TLS+TOFU、Ed25519 设备密钥、配对码、会话令牌）

pub mod auth;
pub mod crypto;
pub mod entry;
pub mod error;
pub mod ids;
pub mod ruleset;

pub use auth::*;
pub use crypto::*;
pub use entry::*;
pub use error::*;
pub use ids::*;
pub use ruleset::*;

/// API 路径版本前缀（如 `/v1/allowlist`）。
pub const API_VERSION: &str = "v1";

/// 管理端口默认值（ADR 0003）。**永不**进受管名单（ADR 0002）。
pub const DEFAULT_MGMT_PORT: u16 = 19186;

/// nftables 表名（`inet` family）。
pub const NFT_TABLE: &str = "ipgate";
/// 放行名单 set 名（IPv4）。
pub const NFT_SET_ALLOW4: &str = "allow4";
/// 放行名单 set 名（IPv6）。
pub const NFT_SET_ALLOW6: &str = "allow6";
/// 对全世界开放的 TCP 端口 set 名。
pub const NFT_SET_PUBLIC_TCP: &str = "public_tcp";
/// 对全世界开放的 UDP 端口 set 名。
pub const NFT_SET_PUBLIC_UDP: &str = "public_udp";

/// 会话令牌默认有效期（秒）。
pub const SESSION_TOKEN_TTL_SECS: u64 = 15 * 60;
/// 配对码默认有效期（秒）。
pub const PAIRING_CODE_TTL_SECS: u64 = 10 * 60;
/// 登录挑战默认有效期（秒）。
pub const CHALLENGE_TTL_SECS: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn entry_json_roundtrip() {
        let e = Entry {
            id: EntryId::new(),
            target: "203.0.113.0/24".parse().unwrap(),
            note: "office".into(),
            expires_at: None,
            created_at: Utc::now(),
            created_by: DeviceId::new(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: Entry = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn revoke_request_tagged_roundtrip() {
        let r = RevokeRequest::Target("198.51.100.7/32".parse().unwrap());
        let s = serde_json::to_string(&r).unwrap();
        let back: RevokeRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn ipv6_cidr_parses() {
        let e: Entry = serde_json::from_str(
            r#"{"id":"00000000-0000-0000-0000-000000000000","target":"2001:db8::/32","created_at":"2026-06-23T00:00:00Z","created_by":"00000000-0000-0000-0000-000000000000"}"#,
        )
        .unwrap();
        assert!(e.target.addr().is_ipv6());
        assert_eq!(e.note, ""); // serde(default)
        assert!(e.expires_at.is_none());
    }

    #[test]
    fn default_mgmt_port_is_19186() {
        assert_eq!(DEFAULT_MGMT_PORT, 19186);
        assert_eq!(RulesetConfig::default().mgmt_port, 19186);
    }

    #[test]
    fn secret_debug_is_redacted() {
        let t = SessionToken::from("super-secret-token");
        assert!(!format!("{t:?}").contains("super-secret"));
    }
}
