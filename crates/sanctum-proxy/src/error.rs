//! Error types for the proxy crate.

/// Errors that can occur in the proxy.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Failed to bind the proxy listener.
    #[error("failed to bind proxy to {addr}: {source}")]
    Bind {
        /// The address we tried to bind to.
        addr: String,
        /// The underlying IO error.
        source: std::io::Error,
    },

    /// The listen address is not localhost.
    #[error("proxy must bind to localhost, got: {addr}")]
    NonLocalhostBind {
        /// The non-localhost address that was rejected.
        addr: String,
    },

    /// Failed to generate CA certificate.
    #[error("failed to generate CA certificate: {reason}")]
    CaGeneration {
        /// Description of what went wrong.
        reason: String,
    },

    /// Failed to read or write CA key file.
    #[error("CA key file error: {source}")]
    CaKeyFile {
        /// The underlying IO error.
        source: std::io::Error,
    },

    /// Failed to parse upstream response for usage extraction.
    #[error("failed to parse usage from response: {reason}")]
    UsageParse {
        /// Description of the parse failure.
        reason: String,
    },

    /// Budget enforcement blocked the request.
    #[error("request blocked: {reason}")]
    BudgetBlocked {
        /// Why the request was blocked.
        reason: String,
    },

    /// Model not in allowed list.
    #[error("model not allowed: {model} (provider: {provider})")]
    ModelNotAllowed {
        /// The model that was requested.
        model: String,
        /// The provider the model belongs to.
        provider: String,
    },

    /// Request or response body too large.
    #[error("payload too large: {reason}")]
    PayloadTooLarge {
        /// Description of what was too large.
        reason: String,
    },

    /// Path injection or SSRF attempt detected.
    #[error("invalid request path: {reason}")]
    InvalidPath {
        /// Description of the path validation failure.
        reason: String,
    },

    /// HTTP client error (e.g., upstream request failed).
    #[error("upstream request failed: {0}")]
    Upstream(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl ProxyError {
    /// Map this error to an HTTP status code.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::PayloadTooLarge { .. } => 413,
            Self::BudgetBlocked { .. } => 429,
            Self::ModelNotAllowed { .. } => 403,
            Self::InvalidPath { .. } => 400,
            Self::Upstream(_) => 502,
            Self::Bind { .. }
            | Self::NonLocalhostBind { .. }
            | Self::CaGeneration { .. }
            | Self::CaKeyFile { .. }
            | Self::UsageParse { .. }
            | Self::Io(_) => 500,
        }
    }
}
