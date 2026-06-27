//! 错误辅助（ADR 0007：JSON-RPC 不再有 HTTP 状态码，handler 直接返回 proto `ApiError`）。

use ipgate_proto::{ApiError, ErrorCode};

/// 内部错误统一记为 Internal。
pub fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, e.to_string())
}

pub type ApiResult<T> = Result<T, ApiError>;
