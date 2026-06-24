//! 密码学相关的线上表示。
//!
//! proto **不**依赖任何具体密码学库（ed25519-dalek 等是 agent/client 的实现细节）。
//! 这里只承载编码后的字节串：公钥/签名/nonce 用 base64（标准，无填充），
//! 指纹用十六进制。解码与校验由两端各自完成。

use serde::{Deserialize, Serialize};

/// 普通（非机密）的字符串 newtype：可 Display、Debug 显示原值。
macro_rules! b64_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn as_str(&self) -> &str { &self.0 }
            pub fn into_inner(self) -> String { self.0 }
        }
        impl From<String> for $name { fn from(s: String) -> Self { Self(s) } }
        impl From<&str> for $name { fn from(s: &str) -> Self { Self(s.to_owned()) } }
        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "({:?})"), self.0)
            }
        }
    };
}

/// 机密字符串 newtype：Debug 脱敏、不实现 Display，避免误入日志。
macro_rules! secret_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn as_str(&self) -> &str { &self.0 }
            pub fn into_inner(self) -> String { self.0 }
        }
        impl From<String> for $name { fn from(s: String) -> Self { Self(s) } }
        impl From<&str> for $name { fn from(s: &str) -> Self { Self(s.to_owned()) } }
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

b64_newtype!(
    /// Ed25519 公钥；base64（标准，无填充），解码后 32 字节。
    PublicKey
);
b64_newtype!(
    /// Ed25519 签名；base64，解码后 64 字节。
    Signature
);
b64_newtype!(
    /// 服务端下发的一次性挑战随机数；base64。
    Nonce
);
b64_newtype!(
    /// 服务端证书 SPKI 的 SHA-256 指纹；十六进制（可含冒号分隔）。
    SpkiFingerprint
);

secret_newtype!(
    /// 配对码：短、单次、限时；由 agent 打印、用户手输。机密。
    PairingCode
);
secret_newtype!(
    /// 会话令牌：不透明（HMAC 或 PASETO v4）；客户端原样回传。机密。
    SessionToken
);
