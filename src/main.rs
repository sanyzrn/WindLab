//! windlab-proof: minimal CLI connectivity proof.
//!
//! Credentials are prompted interactively (password without echo). They are
//! never accepted as arguments or environment variables, never written to
//! disk, and never logged. This program changes no OS network settings.

use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use rustls::RootCertStore;
use windlab::config::{ProofConfig, ProxyEndpoint, Target};
use windlab::error::{FailureClass, ProofError};
use windlab::secret::ProxyCredentials;

#[derive(Parser)]
#[command(
    name = "windlab-proof",
    version,
    about = "Prove HTTPS connectivity through an explicit TLS-verified HTTP CONNECT proxy. No OS network changes, no direct fallback."
)]
struct Args {
    /// Proxy hostname (DNS name or IP).
    #[arg(long)]
    proxy_host: String,

    /// Proxy TLS port.
    #[arg(long, default_value_t = 443)]
    proxy_port: u16,

    /// HTTPS URL returning a bare IP address body.
    #[arg(long, default_value = "https://api.ipify.org/")]
    target_url: String,

    /// Overall deadline in seconds.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[fail] {err}");
            eprintln!("exit-code: {}", err.class.exit_code());
            ExitCode::from(err.class.exit_code() as u8)
        }
    }
}

fn run(args: Args) -> Result<(), ProofError> {
    if args.timeout_secs == 0 {
        return Err(ProofError::config("timeout must be at least 1 second"));
    }
    let proxy = ProxyEndpoint::new(args.proxy_host, args.proxy_port)?;
    let target = Target::parse(&args.target_url)?;
    let config = ProofConfig {
        proxy,
        target,
        timeout: Duration::from_secs(args.timeout_secs),
    };

    let credentials = prompt_credentials()?;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ProofError::config(format!("runtime init failed: {e}")))?;

    runtime.block_on(async {
        tokio::select! {
            result = windlab::run_proof(&config, credentials.as_ref(), roots) => {
                match result {
                    Ok(report) => {
                        for stage in &report.stages {
                            println!("[ok] {} {}ms", stage.name, stage.elapsed.as_millis());
                        }
                        println!("proxy: {} (TLS verified)", report.proxy_authority);
                        println!("target: {} (TLS verified)", report.target_authority);
                        println!("exit-ip: {}", report.exit_ip);
                        println!("total: {}ms", report.total.as_millis());
                        println!("note: proxy-only proof; no system routing, DNS, or UDP claim");
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                Err(ProofError::new(FailureClass::Cancelled, "cancelled", "interrupted by user"))
            }
        }
    })
}

/// Username via plain line input; password via no-echo prompt. Empty username
/// means the proxy is expected to require no authentication.
fn prompt_credentials() -> Result<Option<ProxyCredentials>, ProofError> {
    eprint!("Proxy username (empty = no auth): ");
    std::io::stderr().flush().ok();
    let mut username = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut username)
        .map_err(|e| ProofError::config(format!("cannot read username: {e}")))?;
    let username = username.trim().to_string();
    if username.is_empty() {
        return Ok(None);
    }
    let password = rpassword::prompt_password("Proxy password (not echoed): ")
        .map_err(|e| ProofError::config(format!("cannot read password: {e}")))?;
    Ok(Some(ProxyCredentials::new(username, password)?))
}
