//! 统一 API 错误类型。

use serde::{Deserialize, Serialize};

/// 统一 API 错误负载。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl core::fmt::Display for ApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{:?}] {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

/// 稳定的机器可读错误码（线上为 snake_case）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 鉴权失败（令牌缺失/无效/过期）。
    Unauthorized,
    /// 配对码无效 / 过期 / 已用。
    PairingInvalid,
    /// 设备未授权（不在 `authorized_keys`）。
    DeviceUnknown,
    /// 登录挑战无效 / 过期 / 签名不符。
    ChallengeInvalid,
    /// 请求参数非法（IP/CIDR/端口等）。
    BadRequest,
    /// 操作会挡住管理端口，被拒（ADR 0002/0003 不变量）。
    WouldLockOut,
    /// 限速 / 锁定中。
    RateLimited,
    /// 条目 / 设备不存在。
    NotFound,
    /// 内核 nft 操作失败。
    NftFailure,
    /// 服务端内部错误。
    Internal,
}
