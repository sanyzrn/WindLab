//! Failure classification for the connectivity proof.
//!
//! Every error carries a class, the stage where it happened, and a sanitized
//! detail string. Details must never contain credentials or other secrets.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Invalid user-supplied configuration (host, port, URL, credential syntax).
    Config,
    /// Proxy hostname could not be resolved.
    Dns,
    /// TCP connection to the proxy failed.
    Tcp,
    /// TLS handshake with the proxy failed (trust chain, hostname, protocol).
    ProxyTls,
    /// Proxy authentication required, rejected, or forbidden (407/403).
    ProxyAuth,
    /// Unexpected or malformed CONNECT response, or connection closed.
    ProxyProtocol,
    /// TLS handshake with the destination through the tunnel failed.
    DestinationTls,
    /// Destination HTTP response was not a usable success.
    DestinationHttp,
    /// Destination responded, but the body is not a valid IP address.
    InvalidIp,
    /// Overall deadline exceeded.
    Timeout,
    /// User cancelled.
    Cancelled,
}

impl FailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::ProxyTls => "proxy-tls",
            Self::ProxyAuth => "proxy-auth",
            Self::ProxyProtocol => "proxy-protocol",
            Self::DestinationTls => "destination-tls",
            Self::DestinationHttp => "destination-http",
            Self::InvalidIp => "invalid-ip",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }

    /// Process exit code, stable for scripts and diagnostics.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Config => 2,
            Self::Dns => 3,
            Self::Tcp => 4,
            Self::ProxyTls => 5,
            Self::ProxyAuth => 6,
            Self::ProxyProtocol => 7,
            Self::DestinationTls => 8,
            Self::DestinationHttp => 9,
            Self::InvalidIp => 10,
            Self::Timeout => 11,
            Self::Cancelled => 12,
        }
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{class} at {stage}: {detail}")]
pub struct ProofError {
    pub class: FailureClass,
    pub stage: &'static str,
    pub detail: String,
}

impl ProofError {
    pub fn new(class: FailureClass, stage: &'static str, detail: impl Into<String>) -> Self {
        Self {
            class,
            stage,
            detail: detail.into(),
        }
    }

    pub fn config(detail: impl Into<String>) -> Self {
        Self::new(FailureClass::Config, "config", detail)
    }
}
