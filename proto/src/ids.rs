//! 标识符 newtype。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! uuid_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// 生成一个新的随机 id（v4）。
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub fn into_inner(self) -> Uuid {
                self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

uuid_newtype!(
    /// 设备 id（配对入网时由 agent 分配）。
    DeviceId
);
uuid_newtype!(
    /// 放行名单条目 id。
    EntryId
);
uuid_newtype!(
    /// 端口转发规则 id。
    ForwardId
);
