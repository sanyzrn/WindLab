//! Configuration types and validation. No secrets live here.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use crate::error::ProofError;

/// Controls how HTTP Proxy Basic authentication is sent on `CONNECT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// Default: send unauthenticated `CONNECT` first, and only send
    /// `Proxy-Authorization` after a `407` response advertising `Basic`.
    #[default]
    Challenge,
    /// Opt-in: send `Proxy-Authorization` on the first `CONNECT` after
    /// strict TLS verification of the proxy. Useful for proxies that reject
    /// unauthenticated `CONNECT` without returning `407`.
    Preemptive,
}

#[derive(Debug, Clone)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

impl ProxyEndpoint {
    pub fn new(host: String, port: u16) -> Result<Self, ProofError> {
        let normalized = normalize_host(&host)?;
        if port == 0 {
            return Err(ProofError::config("proxy port must be 1-65535"));
        }
        Ok(Self {
            host: normalized,
            port,
        })
    }

    /// Authority in `host:port` form (with `[ipv6]:port` brackets for IPv6).
    pub fn authority(&self) -> String {
        format_authority(&self.host, self.port)
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
        let raw_host = parsed
            .host_str()
            .ok_or_else(|| ProofError::config("target URL has no host"))?;
        let host = normalize_host(raw_host)?;
        let port = parsed.port().unwrap_or(443);
        if port == 0 {
            return Err(ProofError::config("target port must be 1-65535"));
        }
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

    /// HTTP `Host` header value (omits default `:443`, brackets IPv6 literals).
    pub fn authority(&self) -> String {
        if self.port == 443 {
            format_host_for_uri(&self.host)
        } else {
            format_authority(&self.host, self.port)
        }
    }

    /// RFC 9110 section 9.3.6 authority-form target for `CONNECT` requests.
    /// Always includes `:port` (including `:443`) and brackets IPv6 literals.
    pub fn connect_authority(&self) -> String {
        format_authority(&self.host, self.port)
    }
}

#[derive(Debug, Clone)]
pub struct ProofConfig {
    pub proxy: ProxyEndpoint,
    pub target: Target,
    pub timeout: Duration,
}

/// Optional execution settings layered on top of [`ProofConfig`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProofOptions {
    pub auth_mode: AuthMode,
}

/// Formats a validated host for URI/Host header use (bracketing IPv6 literals).
pub fn format_host_for_uri(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Formats a validated host and port as `host:port` (or `[ipv6]:port`).
pub fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Strips optional `[...]` brackets around an IPv6 literal, validates the host,
/// and returns the normalized unbracketed host string.
fn normalize_host(host: &str) -> Result<String, ProofError> {
    let candidate = match host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        Some(inner) => {
            if inner.parse::<Ipv6Addr>().is_err() {
                return Err(ProofError::config(
                    "bracketed host must be a valid IPv6 literal",
                ));
            }
            inner
        }
        None => host,
    };
    validate_host(candidate)?;
    Ok(candidate.to_string())
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
