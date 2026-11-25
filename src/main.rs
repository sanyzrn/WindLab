//! windlab-proof: minimal CLI connectivity proof.
//!
//! Credentials are prompted interactively (password without echo). They are
//! never accepted as arguments or environment variables, never written to
//! disk, and never logged. This program changes no OS network settings.

use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use rustls::RootCertStore;
use windlab::config::{AuthMode, ProofConfig, ProofOptions, ProxyEndpoint, Target};
use windlab::error::{FailureClass, ProofError};
use windlab::secret::ProxyCredentials;
use zeroize::Zeroize;

#[derive(Clone, Copy, ValueEnum)]
enum CliAuthMode {
    /// Send credentials only after a 407 Basic challenge (default).
    Challenge,
    /// Send Basic credentials on the first CONNECT after proxy TLS verification.
    Preemptive,
}

impl From<CliAuthMode> for AuthMode {
    fn from(mode: CliAuthMode) -> Self {
        match mode {
            CliAuthMode::Challenge => Self::Challenge,
            CliAuthMode::Preemptive => Self::Preemptive,
        }
    }
}

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

    /// Proxy authentication mode.
    #[arg(long, value_enum, default_value_t = CliAuthMode::Challenge)]
    auth_mode: CliAuthMode,

    /// Emit machine-readable JSON diagnostics (never includes credentials).
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let json = args.json;
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if json {
                println!(
                    "{{\"ok\":false,\"class\":\"{}\",\"stage\":\"{}\",\"detail\":\"{}\",\"exit_code\":{}}}",
                    err.class.as_str(),
                    err.stage,
                    json_escape(&err.detail),
                    err.class.exit_code()
                );
            } else {
                eprintln!("[fail] {err}");
                eprintln!("exit-code: {}", err.class.exit_code());
            }
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
    let options = ProofOptions {
        auth_mode: args.auth_mode.into(),
    };
    let json = args.json;

    let credentials = prompt_credentials()?;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ProofError::config(format!("runtime init failed: {e}")))?;

    runtime.block_on(async {
        tokio::select! {
            result = windlab::run_proof_with_options(
                &config,
                credentials.as_ref(),
                roots,
                options,
            ) => {
                match result {
                    Ok(report) => {
                        if json {
                            print_json_report(&report);
                        } else {
                            for stage in &report.stages {
                                println!("[ok] {} {}ms", stage.name, stage.elapsed.as_millis());
                            }
                            println!(
                                "proxy: {} [{}] (TLS verified)",
                                report.proxy_authority, report.proxy_addr
                            );
                            println!("target: {} (TLS verified)", report.target_authority);
                            println!("exit-ip: {}", report.exit_ip);
                            if report.auth_reconnected {
                                println!("auth-retry: reconnected fresh TLS session after 407");
                            }
                            println!("total: {}ms", report.total.as_millis());
                            println!("note: proxy-only proof; no system routing, DNS, or UDP claim");
                        }
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

fn print_json_report(report: &windlab::ProofReport) {
    let stages: Vec<String> = report
        .stages
        .iter()
        .map(|s| format!("{{\"name\":\"{}\",\"ms\":{}}}", s.name, s.elapsed.as_millis()))
        .collect();
    println!(
        "{{\"ok\":true,\"proxy\":\"{}\",\"proxy_addr\":\"{}\",\"target\":\"{}\",\"exit_ip\":\"{}\",\"auth_reconnected\":{},\"total_ms\":{},\"stages\":[{}]}}",
        json_escape(&report.proxy_authority),
        report.proxy_addr,
        json_escape(&report.target_authority),
        report.exit_ip,
        report.auth_reconnected,
        report.total.as_millis(),
        stages.join(",")
    );
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Username via plain line input; password via no-echo prompt. Empty username
/// means the proxy is expected to require no authentication.
fn prompt_credentials() -> Result<Option<ProxyCredentials>, ProofError> {
    eprint!("Proxy username (empty = no auth): ");
    std::io::stderr().flush().ok();
    let mut raw_username = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut raw_username)
        .map_err(|e| ProofError::config(format!("cannot read username: {e}")))?;
    let username = raw_username.trim().to_string();
    raw_username.zeroize();
    if username.is_empty() {
        return Ok(None);
    }
    let password = rpassword::prompt_password("Proxy password (not echoed): ")
        .map_err(|e| ProofError::config(format!("cannot read password: {e}")))?;
    Ok(Some(ProxyCredentials::new(username, password)?))
}
