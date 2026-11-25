//! Configuration types and validation. No secrets live here.

use std::net::IpAddr;
use std::time::Duration;

use crate::error::ProofError;

#[derive(Debug, Clone)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

impl ProxyEndpoint {
    pub fn new(host: String, port: u16) -> Result<Self, ProofError> {
        validate_host(&host)?;
        if port == 0 {
            return Err(ProofError::config("proxy port must be 1-65535"));
        }
        Ok(Self { host, port })
    }

    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// HTTPS destination used to verify actual traffic through the tunnel.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

impl Target {
    /// Only `https://` targets are accepted: the destination leg must be
    /// end-to-end TLS. Plain HTTP would allow silent interception.
    pub fn parse(url: &str) -> Result<Self, ProofError> {
        let parsed = url::Url::parse(url)
            .map_err(|_| ProofError::config("target URL is not a valid URL"))?;
        if parsed.scheme() != "https" {
            return Err(ProofError::config("target URL must use https"));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ProofError::config("target URL must not embed credentials"));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| ProofError::config("target URL has no host"))?
            .to_string();
        validate_host(&host)?;
        let port = parsed.port().unwrap_or(443);
        let mut path_and_query = parsed.path().to_string();
        if path_and_query.is_empty() {
            path_and_query.push('/');
        }
        if let Some(q) = parsed.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }
        Ok(Self {
            host,
            port,
            path_and_query,
        })
    }

    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProofConfig {
    pub proxy: ProxyEndpoint,
    pub target: Target,
    pub timeout: Duration,
}

/// Accepts IP literals and DNS names only. Rejects control characters,
/// whitespace, and anything that could smuggle headers or userinfo.
pub fn validate_host(host: &str) -> Result<(), ProofError> {
    if host.is_empty() {
        return Err(ProofError::config("host must not be empty"));
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if host.len() > 253 || host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(ProofError::config("host contains invalid characters"));
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ProofError::config("host has an empty or oversized label"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ProofError::config("host label starts or ends with '-'"));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ProofError::config(
                "host contains characters outside [a-z0-9-.]",
            ));
        }
    }
    Ok(())
}
