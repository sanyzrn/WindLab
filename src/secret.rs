//! Secret handling: redacted debug output, zeroized on drop, header-injection
//! validation. Secrets are never accepted via command-line arguments or
//! environment variables, and never appear in logs or error details.

use std::fmt;

use base64::Engine;
use zeroize::{Zeroize, Zeroizing};

use crate::error::ProofError;

/// A string that must not leak through logs, debug output, or error messages.
pub struct Secret(String);

impl Secret {
    /// Validates that the value cannot inject headers or break protocol lines.
    pub fn new(value: String) -> Result<Self, ProofError> {
        if value.chars().any(|c| c.is_control()) {
            return Err(ProofError::config("credential contains control characters"));
        }
        Ok(Self(value))
    }

    /// Explicit, deliberate access. Callers must not log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

pub struct ProxyCredentials {
    pub username: Secret,
    pub password: Secret,
}

impl ProxyCredentials {
    pub fn new(username: String, password: String) -> Result<Self, ProofError> {
        if username.contains(':') {
            return Err(ProofError::config("username must not contain ':'"));
        }
        Ok(Self {
            username: Secret::new(username)?,
            password: Secret::new(password)?,
        })
    }

    /// HTTP Basic `Proxy-Authorization` header value. Built in memory only,
    /// zeroized on drop, and sent exclusively to the TLS-verified proxy,
    /// never to the destination.
    pub fn basic_header_value(&self) -> Zeroizing<String> {
        let raw = Zeroizing::new(format!(
            "{}:{}",
            self.username.expose(),
            self.password.expose()
        ));
        let encoded =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()));
        Zeroizing::new(format!("Basic {}", encoded.as_str()))
    }
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyCredentials([REDACTED])")
    }
}
