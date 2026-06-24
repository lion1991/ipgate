//! 把内部错误映射为 HTTP 响应（proto `ApiError` + 状态码）。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ipgate_proto::{ApiError, ErrorCode};

pub struct AppError(pub ApiError);

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self(ApiError::new(code, message))
    }
}

/// 内部错误统一记为 Internal。
pub fn internal(e: impl std::fmt::Display) -> AppError {
    AppError::new(ErrorCode::Internal, e.to_string())
}

fn status(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::Unauthorized
        | ErrorCode::DeviceUnknown
        | ErrorCode::PairingInvalid
        | ErrorCode::ChallengeInvalid => StatusCode::UNAUTHORIZED,
        ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
        ErrorCode::WouldLockOut => StatusCode::CONFLICT,
        ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::NftFailure | ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (status(self.0.code), Json(self.0)).into_response()
    }
}

pub type ApiResult<T> = Result<T, AppError>;
