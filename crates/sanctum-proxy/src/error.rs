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

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
