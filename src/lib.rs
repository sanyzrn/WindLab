//! WindLab phase-1 connectivity proof library.
//!
//! Proves one thing only: an HTTPS request to a target completes through an
//! explicitly configured, TLS-verified HTTP CONNECT proxy, and the response
//! body is a valid exit IP. It does not prove system-wide routing, UDP support,
//! or DNS protection, and it makes no OS network changes.

pub mod config;
pub mod error;
pub mod secret;
pub mod tunnel;
pub mod verify;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use rustls::RootCertStore;

use config::ProofConfig;
use error::{FailureClass, ProofError};
use secret::ProxyCredentials;

#[derive(Debug, Clone)]
pub struct StageTiming {
    pub name: &'static str,
    pub elapsed: Duration,
}

#[derive(Debug, Clone)]
pub struct ProofReport {
    pub proxy_authority: String,
    pub target_authority: String,
    pub exit_ip: IpAddr,
    pub stages: Vec<StageTiming>,
    pub total: Duration,
}

/// Runs the proof against the configured proxy. `roots` is the trust store
/// used for both TLS legs; production callers pass public WebPKI roots,
/// tests pass a fixture-only CA. There is no direct fallback: any failure
/// aborts with a classified error.
pub async fn run_proof(
    config: &ProofConfig,
    credentials: Option<&ProxyCredentials>,
    roots: RootCertStore,
) -> Result<ProofReport, ProofError> {
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + config.timeout;
    let mut stages = Vec::new();
    let tls_config = tunnel::client_tls_config(roots);

    let addrs = step(
        deadline,
        "dns",
        tunnel::resolve(&config.proxy.host, config.proxy.port),
        &mut stages,
    )
    .await?;
    let tcp = step(deadline, "tcp", tunnel::tcp_connect(&addrs), &mut stages).await?;
    let proxy_name = tunnel::server_name(&config.proxy.host)?;
    let proxy_tls = step(
        deadline,
        "proxy-tls",
        tunnel::tls_connect(
            tcp,
            proxy_name,
            tls_config.clone(),
            "proxy-tls",
            FailureClass::ProxyTls,
        ),
        &mut stages,
    )
    .await?;
    let tunnel_stream = step(
        deadline,
        "connect",
        tunnel::establish_connect(proxy_tls, &config.target.authority(), credentials),
        &mut stages,
    )
    .await?;
    let mut dest_tls = step(
        deadline,
        "destination-tls",
        verify::destination_tls(tunnel_stream, &config.target, tls_config),
        &mut stages,
    )
    .await?;
    let exit_ip = step(
        deadline,
        "http",
        verify::http_get_ip(&mut dest_tls, &config.target),
        &mut stages,
    )
    .await?;

    Ok(ProofReport {
        proxy_authority: config.proxy.authority(),
        target_authority: config.target.authority(),
        exit_ip,
        stages,
        total: started.elapsed(),
    })
}

async fn step<F, T>(
    deadline: tokio::time::Instant,
    name: &'static str,
    fut: F,
    stages: &mut Vec<StageTiming>,
) -> Result<T, ProofError>
where
    F: std::future::Future<Output = Result<T, ProofError>>,
{
    let started = Instant::now();
    match tokio::time::timeout_at(deadline, fut).await {
        Ok(result) => {
            stages.push(StageTiming {
                name,
                elapsed: started.elapsed(),
            });
            result
        }
        Err(_) => Err(ProofError::new(
            FailureClass::Timeout,
            name,
            format!("deadline exceeded during {name}"),
        )),
    }
}
