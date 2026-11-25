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

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rustls::RootCertStore;

use config::{AuthMode, ProofConfig, ProofOptions};
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
    pub proxy_addr: SocketAddr,
    pub target_authority: String,
    pub exit_ip: IpAddr,
    pub auth_reconnected: bool,
    pub stages: Vec<StageTiming>,
    pub total: Duration,
}

/// Runs the proof against the configured proxy using default options
/// (challenge-response Basic auth). `roots` is the trust store used for both
/// TLS legs; production callers pass public WebPKI roots, tests pass a
/// fixture-only CA. There is no direct fallback: any failure aborts with a
/// classified error.
pub async fn run_proof(
    config: &ProofConfig,
    credentials: Option<&ProxyCredentials>,
    roots: RootCertStore,
) -> Result<ProofReport, ProofError> {
    run_proof_with_options(config, credentials, roots, ProofOptions::default()).await
}

/// Runs the proof with explicit [`ProofOptions`] (for example opt-in
/// preemptive Basic auth).
pub async fn run_proof_with_options(
    config: &ProofConfig,
    credentials: Option<&ProxyCredentials>,
    roots: RootCertStore,
    options: ProofOptions,
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
    let proxy_addr = tcp.peer_addr().unwrap_or(addrs[0]);
    let proxy_name = tunnel::server_name(&config.proxy.host)?;
    let proxy_tls = step(
        deadline,
        "proxy-tls",
        tunnel::tls_connect(
            tcp,
            proxy_name.clone(),
            tls_config.clone(),
            "proxy-tls",
            FailureClass::ProxyTls,
        ),
        &mut stages,
    )
    .await?;

    let connect_authority = config.target.connect_authority();
    let mut auth_reconnected = false;

    let tunnel_stream = match (options.auth_mode, credentials) {
        (AuthMode::Preemptive, Some(creds)) => {
            step(
                deadline,
                "connect",
                tunnel::establish_connect_authenticated(proxy_tls, &connect_authority, creds),
                &mut stages,
            )
            .await?
        }
        _ => {
            let outcome = step(
                deadline,
                "connect",
                tunnel::establish_connect_with_reconnect(
                    proxy_tls,
                    &connect_authority,
                    credentials,
                ),
                &mut stages,
            )
            .await?;

            match outcome {
                tunnel::ConnectOutcome::Established(stream) => stream,
                tunnel::ConnectOutcome::RetryOnFreshConnection => {
                    let creds = credentials.ok_or_else(|| {
                        ProofError::new(
                            FailureClass::ProxyAuth,
                            "connect",
                            "proxy requires authentication (407) but no credentials were provided",
                        )
                    })?;
                    auth_reconnected = true;
                    let retry_tcp = step(
                        deadline,
                        "tcp-retry",
                        tunnel::tcp_connect(&[proxy_addr]),
                        &mut stages,
                    )
                    .await?;
                    let retry_tls = step(
                        deadline,
                        "proxy-tls-retry",
                        tunnel::tls_connect(
                            retry_tcp,
                            proxy_name,
                            tls_config.clone(),
                            "proxy-tls-retry",
                            FailureClass::ProxyTls,
                        ),
                        &mut stages,
                    )
                    .await?;
                    step(
                        deadline,
                        "connect-retry",
                        tunnel::establish_connect_authenticated(
                            retry_tls,
                            &connect_authority,
                            creds,
                        ),
                        &mut stages,
                    )
                    .await?
                }
            }
        }
    };

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
        proxy_addr,
        target_authority: config.target.authority(),
        exit_ip,
        auth_reconnected,
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
