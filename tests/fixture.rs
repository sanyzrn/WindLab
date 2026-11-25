//! Local-only fixture tests. All servers bind 127.0.0.1 with ephemeral ports;
//! all certificates are generated per test run and trusted ONLY by the
//! fixture client root store. The system trust store is never touched, no
//! external network is required, and no real credentials are used.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use windlab::config::{AuthMode, ProofConfig, ProofOptions, ProxyEndpoint, Target};
use windlab::error::FailureClass;
use windlab::secret::{ProxyCredentials, Secret};
use windlab::tunnel;

const TEST_USER: &str = "fixture-user";
const TEST_PASS: &str = "fixture-pass";
const EXIT_IP: &str = "203.0.113.7";

// ---------------------------------------------------------------------------
// Certificate fixtures
// ---------------------------------------------------------------------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca(name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).unwrap();
    Ca { cert, key }
}

fn make_leaf(
    ca: &Ca,
    dns_names: &[&str],
    ips: &[IpAddr],
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name.push(
        DnType::CommonName,
        dns_names.first().copied().unwrap_or("fixture"),
    );
    let mut sans: Vec<SanType> = dns_names
        .iter()
        .map(|n| SanType::DnsName((*n).try_into().unwrap()))
        .collect();
    sans.extend(ips.iter().map(|ip| SanType::IpAddress(*ip)));
    params.subject_alt_names = sans;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

fn server_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    )
}

fn client_roots(ca: &Ca) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert.der().clone()).unwrap();
    roots
}

// ---------------------------------------------------------------------------
// Server fixtures
// ---------------------------------------------------------------------------

async fn read_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.unwrap();
        assert!(
            n > 0,
            "fixture client closed before sending a full request head"
        );
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return buf;
        }
        assert!(buf.len() < 16384, "fixture request head too large");
    }
}

fn header_value(head: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(head).to_ascii_lowercase();
    text.lines().find_map(|line| {
        line.strip_prefix(&format!("{name}:"))
            .map(|v| v.trim().to_string())
    })
}

/// Destination HTTPS fixture. Fails the test if the client ever forwards
/// proxy credentials to the destination.
async fn spawn_destination(tls: Arc<ServerConfig>, status: u16, body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(tls).accept(stream).await.unwrap();
        let head = read_head(&mut tls).await;
        let status = if header_value(&head, "proxy-authorization").is_some() {
            500
        } else {
            status
        };
        let reason = if status == 200 { "OK" } else { "Error" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(response.as_bytes()).await.unwrap();
        tls.shutdown().await.unwrap();
    });
    addr
}

/// Destination HTTPS fixture with custom raw response bytes and optional
/// keep-alive hold (to verify client does not hang waiting for EOF).
async fn spawn_raw_destination(
    tls: Arc<ServerConfig>,
    raw_response: &'static [u8],
    hold_open: bool,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(tls).accept(stream).await.unwrap();
        let _head = read_head(&mut tls).await;
        tls.write_all(raw_response).await.unwrap();
        tls.flush().await.unwrap();
        if hold_open {
            tokio::time::sleep(Duration::from_secs(15)).await;
        } else {
            tls.shutdown().await.ok();
        }
    });
    addr
}

#[derive(Clone)]
enum ProxyBehavior {
    /// 407 challenge, then accepts only the exact expected Basic credentials.
    Challenge,
    /// 407 challenge with an HTML body + `Connection: close`, then closes TLS
    /// and expects the client to reconnect once with Basic credentials.
    ChallengeCloseWithBody,
    /// 407 challenge with a small `Content-Length` body on keep-alive.
    ChallengeKeepAliveBody,
    /// Requires Basic credentials on the very first CONNECT (preemptive mode).
    PreemptiveOnly,
    NoAuth,
    Always407,
    Forbidden,
    /// Completes TLS but never answers CONNECT (deadline test).
    Silent,
    /// Reads CONNECT then drops the connection.
    CloseAfterRequest,
}

async fn spawn_proxy(
    tls: Arc<ServerConfig>,
    behavior: ProxyBehavior,
    dest: SocketAddr,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_auth = ProxyCredentials::new(TEST_USER.into(), TEST_PASS.into())
        .unwrap()
        .basic_header_value()
        .to_ascii_lowercase();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = TlsAcceptor::from(tls.clone()).accept(stream).await.unwrap();
        let head = read_head(&mut tls_stream).await;
        match behavior {
            ProxyBehavior::Silent => {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            ProxyBehavior::CloseAfterRequest => {
                drop(tls_stream);
            }
            ProxyBehavior::Forbidden => {
                tls_stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
            ProxyBehavior::NoAuth => {
                tls_stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let mut upstream = TcpStream::connect(dest).await.unwrap();
                tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream)
                    .await
                    .ok();
            }
            ProxyBehavior::PreemptiveOnly => {
                let got = header_value(&head, "proxy-authorization");
                if got.as_deref() == Some(expected_auth.as_str()) {
                    tls_stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let mut upstream = TcpStream::connect(dest).await.unwrap();
                    tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream)
                        .await
                        .ok();
                } else {
                    tls_stream
                        .write_all(b"HTTP/1.1 403 Preemptive auth required\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                }
            }
            ProxyBehavior::ChallengeCloseWithBody => {
                if header_value(&head, "proxy-authorization").is_some() {
                    tls_stream
                        .write_all(b"HTTP/1.1 500 Preemptive auth rejected\r\n\r\n")
                        .await
                        .unwrap();
                    return;
                }
                let body = b"<html><body>407 Auth Required</body></html>";
                let resp = format!(
                    "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"fixture\"\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                tls_stream.write_all(resp.as_bytes()).await.unwrap();
                tls_stream.write_all(body).await.unwrap();
                tls_stream.shutdown().await.ok();
                drop(tls_stream);

                // Accept the single fresh TLS reconnect with credentials.
                let (stream2, _) = listener.accept().await.unwrap();
                let mut tls2 = TlsAcceptor::from(tls).accept(stream2).await.unwrap();
                let head2 = read_head(&mut tls2).await;
                let got = header_value(&head2, "proxy-authorization");
                if got.as_deref() == Some(expected_auth.as_str()) {
                    tls2.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let mut upstream = TcpStream::connect(dest).await.unwrap();
                    tokio::io::copy_bidirectional(&mut tls2, &mut upstream)
                        .await
                        .ok();
                } else {
                    tls2.write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"fixture\"\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await
                    .unwrap();
                }
            }
            ProxyBehavior::ChallengeKeepAliveBody => {
                if header_value(&head, "proxy-authorization").is_some() {
                    tls_stream
                        .write_all(b"HTTP/1.1 500 Preemptive auth rejected\r\n\r\n")
                        .await
                        .unwrap();
                    return;
                }
                let body = b"auth required";
                let resp = format!(
                    "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"fixture\"\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                tls_stream.write_all(resp.as_bytes()).await.unwrap();
                tls_stream.write_all(body).await.unwrap();
                let head2 = read_head(&mut tls_stream).await;
                let got = header_value(&head2, "proxy-authorization");
                if got.as_deref() == Some(expected_auth.as_str()) {
                    tls_stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let mut upstream = TcpStream::connect(dest).await.unwrap();
                    tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream)
                        .await
                        .ok();
                } else {
                    tls_stream
                        .write_all(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"fixture\"\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await
                        .unwrap();
                }
            }
            ProxyBehavior::Challenge | ProxyBehavior::Always407 => {
                // The first CONNECT must not carry credentials preemptively.
                if header_value(&head, "proxy-authorization").is_some() {
                    tls_stream
                        .write_all(b"HTTP/1.1 500 Preemptive auth rejected\r\n\r\n")
                        .await
                        .unwrap();
                    return;
                }
                tls_stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"fixture\"\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await
                    .unwrap();
                let head2 = read_head(&mut tls_stream).await;
                let got = header_value(&head2, "proxy-authorization");
                let ok = matches!(behavior, ProxyBehavior::Challenge)
                    && got.as_deref() == Some(expected_auth.as_str());
                if ok {
                    tls_stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let mut upstream = TcpStream::connect(dest).await.unwrap();
                    tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream)
                        .await
                        .ok();
                } else {
                    tls_stream
                        .write_all(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"fixture\"\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await
                        .unwrap();
                }
            }
        }
    });
    addr
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

fn config(proxy_port: u16, dest_port: u16, timeout: Duration) -> ProofConfig {
    ProofConfig {
        proxy: ProxyEndpoint::new("localhost".into(), proxy_port).unwrap(),
        target: Target::parse(&format!("https://localhost:{dest_port}/")).unwrap(),
        timeout,
    }
}

fn creds() -> ProxyCredentials {
    ProxyCredentials::new(TEST_USER.into(), TEST_PASS.into()).unwrap()
}

struct HappyFixture {
    proxy_port: u16,
    dest_port: u16,
    roots: RootCertStore,
}

async fn happy_fixture(behavior: ProxyBehavior) -> HappyFixture {
    let ca = make_ca("WindLab Fixture CA");
    let (cert, key) = make_leaf(&ca, &["localhost"], &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let tls = server_config(cert, key);
    let dest = spawn_destination(tls.clone(), 200, EXIT_IP).await;
    let proxy = spawn_proxy(tls, behavior, dest).await;
    HappyFixture {
        proxy_port: proxy.port(),
        dest_port: dest.port(),
        roots: client_roots(&ca),
    }
}

// ---------------------------------------------------------------------------
// Success paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_with_challenge_auth() {
    let f = happy_fixture(ProxyBehavior::Challenge).await;
    let report = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        Some(&creds()),
        f.roots,
    )
    .await
    .unwrap();
    assert_eq!(report.exit_ip, EXIT_IP.parse::<IpAddr>().unwrap());
    assert!(!report.auth_reconnected);
    let names: Vec<&str> = report.stages.iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        vec![
            "dns",
            "tcp",
            "proxy-tls",
            "connect",
            "destination-tls",
            "http"
        ]
    );
}

#[tokio::test]
async fn happy_path_without_auth() {
    let f = happy_fixture(ProxyBehavior::NoAuth).await;
    let report = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        None,
        f.roots,
    )
    .await
    .unwrap();
    assert_eq!(report.exit_ip, EXIT_IP.parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn proxy_407_with_connection_close_and_body_reconnects_once() {
    let f = happy_fixture(ProxyBehavior::ChallengeCloseWithBody).await;
    let report = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        Some(&creds()),
        f.roots,
    )
    .await
    .unwrap();
    assert_eq!(report.exit_ip, EXIT_IP.parse::<IpAddr>().unwrap());
    assert!(report.auth_reconnected);
}

#[tokio::test]
async fn proxy_407_with_keepalive_body_drains_and_reuses_connection() {
    let f = happy_fixture(ProxyBehavior::ChallengeKeepAliveBody).await;
    let report = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        Some(&creds()),
        f.roots,
    )
    .await
    .unwrap();
    assert_eq!(report.exit_ip, EXIT_IP.parse::<IpAddr>().unwrap());
    assert!(!report.auth_reconnected);
}

#[tokio::test]
async fn preemptive_auth_mode_sends_credentials_on_first_connect() {
    let f = happy_fixture(ProxyBehavior::PreemptiveOnly).await;
    let report = windlab::run_proof_with_options(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        Some(&creds()),
        f.roots,
        ProofOptions {
            auth_mode: AuthMode::Preemptive,
        },
    )
    .await
    .unwrap();
    assert_eq!(report.exit_ip, EXIT_IP.parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn ambient_proxy_environment_is_ignored() {
    // The proof must connect only to the configured proxy. Ambient proxy
    // variables point at a dead endpoint; success proves they are not used.
    std::env::set_var("HTTP_PROXY", "http://127.0.0.1:1");
    std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:1");
    std::env::set_var("ALL_PROXY", "http://127.0.0.1:1");
    let f = happy_fixture(ProxyBehavior::Challenge).await;
    let report = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        Some(&creds()),
        f.roots,
    )
    .await
    .unwrap();
    assert_eq!(report.exit_ip, EXIT_IP.parse::<IpAddr>().unwrap());
}

// ---------------------------------------------------------------------------
// Authentication failures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_password_is_rejected() {
    let f = happy_fixture(ProxyBehavior::Challenge).await;
    let bad = ProxyCredentials::new(TEST_USER.into(), "wrong-pass".into()).unwrap();
    let err = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        Some(&bad),
        f.roots,
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::ProxyAuth);
    assert!(!err.to_string().contains("wrong-pass"));
}

#[tokio::test]
async fn missing_credentials_on_407_is_explicit() {
    let f = happy_fixture(ProxyBehavior::Challenge).await;
    let err = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        None,
        f.roots,
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::ProxyAuth);
}

#[tokio::test]
async fn repeated_407_is_rejected() {
    let f = happy_fixture(ProxyBehavior::Always407).await;
    let err = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        Some(&creds()),
        f.roots,
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::ProxyAuth);
}

#[tokio::test]
async fn forbidden_403_is_auth_class() {
    let f = happy_fixture(ProxyBehavior::Forbidden).await;
    let err = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        Some(&creds()),
        f.roots,
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::ProxyAuth);
}

// ---------------------------------------------------------------------------
// TLS failures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn untrusted_proxy_certificate_fails() {
    let ca = make_ca("Trusted CA");
    let stranger = make_ca("Untrusted CA");
    let (cert, key) = make_leaf(
        &stranger,
        &["localhost"],
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
    );
    let tls = server_config(cert, key);
    let dest = spawn_destination(tls.clone(), 200, EXIT_IP).await;
    let proxy = spawn_proxy(tls, ProxyBehavior::NoAuth, dest).await;
    let err = windlab::run_proof(
        &config(proxy.port(), dest.port(), Duration::from_secs(10)),
        None,
        client_roots(&ca),
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::ProxyTls);
}

#[tokio::test]
async fn wrong_proxy_hostname_fails() {
    let ca = make_ca("WindLab Fixture CA");
    let (cert, key) = make_leaf(&ca, &["other.example"], &[]);
    let tls = server_config(cert, key);
    let dest = spawn_destination(tls.clone(), 200, EXIT_IP).await;
    let proxy = spawn_proxy(tls, ProxyBehavior::NoAuth, dest).await;
    let err = windlab::run_proof(
        &config(proxy.port(), dest.port(), Duration::from_secs(10)),
        None,
        client_roots(&ca),
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::ProxyTls);
}

#[tokio::test]
async fn untrusted_destination_certificate_fails() {
    let ca = make_ca("WindLab Fixture CA");
    let stranger = make_ca("Untrusted Destination CA");
    let (pcert, pkey) = make_leaf(&ca, &["localhost"], &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let (dcert, dkey) = make_leaf(
        &stranger,
        &["localhost"],
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
    );
    let dest = spawn_destination(server_config(dcert, dkey), 200, EXIT_IP).await;
    let proxy = spawn_proxy(server_config(pcert, pkey), ProxyBehavior::NoAuth, dest).await;
    let err = windlab::run_proof(
        &config(proxy.port(), dest.port(), Duration::from_secs(10)),
        None,
        client_roots(&ca),
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::DestinationTls);
}

#[tokio::test]
async fn wrong_destination_hostname_fails() {
    let ca = make_ca("WindLab Fixture CA");
    let (pcert, pkey) = make_leaf(&ca, &["localhost"], &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let (dcert, dkey) = make_leaf(&ca, &["other.example"], &[]);
    let dest = spawn_destination(server_config(dcert, dkey), 200, EXIT_IP).await;
    let proxy = spawn_proxy(server_config(pcert, pkey), ProxyBehavior::NoAuth, dest).await;
    let err = windlab::run_proof(
        &config(proxy.port(), dest.port(), Duration::from_secs(10)),
        None,
        client_roots(&ca),
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::DestinationTls);
}

// ---------------------------------------------------------------------------
// Protocol / lifecycle failures & HTTP framing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn silent_proxy_hits_deadline() {
    let f = happy_fixture(ProxyBehavior::Silent).await;
    let err = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(3)),
        None,
        f.roots,
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::Timeout);
    assert_eq!(err.stage, "connect");
}

#[tokio::test]
async fn proxy_disconnect_after_connect_is_explicit() {
    let f = happy_fixture(ProxyBehavior::CloseAfterRequest).await;
    let err = windlab::run_proof(
        &config(f.proxy_port, f.dest_port, Duration::from_secs(10)),
        None,
        f.roots,
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::ProxyProtocol);
}

#[tokio::test]
async fn buffered_bytes_after_connect_response_are_preserved() {
    // Raw TCP fixture coalesces the 200 response with early tunnel bytes.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _head = read_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\nEARLY")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut tunneled = tunnel::establish_connect(stream, "example.test:443", None)
        .await
        .unwrap();
    let mut buf = [0u8; 5];
    tunneled.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"EARLY");
}

#[tokio::test]
async fn destination_chunked_transfer_encoding_is_decoded() {
    let ca = make_ca("WindLab Fixture CA");
    let (cert, key) = make_leaf(&ca, &["localhost"], &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let tls = server_config(cert, key);
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n203.0\r\n6\r\n.113.7\r\n0\r\n\r\n";
    let dest = spawn_raw_destination(tls.clone(), raw, true).await;
    let proxy = spawn_proxy(tls, ProxyBehavior::NoAuth, dest).await;
    let report = windlab::run_proof(
        &config(proxy.port(), dest.port(), Duration::from_secs(5)),
        None,
        client_roots(&ca),
    )
    .await
    .unwrap();
    assert_eq!(report.exit_ip, EXIT_IP.parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn destination_keepalive_with_content_length_does_not_hang() {
    let ca = make_ca("WindLab Fixture CA");
    let (cert, key) = make_leaf(&ca, &["localhost"], &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let tls = server_config(cert, key);
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: keep-alive\r\n\r\n203.0.113.7";
    let dest = spawn_raw_destination(tls.clone(), raw, true).await;
    let proxy = spawn_proxy(tls, ProxyBehavior::NoAuth, dest).await;
    let report = windlab::run_proof(
        &config(proxy.port(), dest.port(), Duration::from_secs(5)),
        None,
        client_roots(&ca),
    )
    .await
    .unwrap();
    assert_eq!(report.exit_ip, EXIT_IP.parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn destination_non_200_is_explicit_failure() {
    let ca = make_ca("WindLab Fixture CA");
    let (cert, key) = make_leaf(&ca, &["localhost"], &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let tls = server_config(cert, key);
    let dest = spawn_destination(tls.clone(), 500, "error").await;
    let proxy = spawn_proxy(tls, ProxyBehavior::NoAuth, dest).await;
    let err = windlab::run_proof(
        &config(proxy.port(), dest.port(), Duration::from_secs(10)),
        None,
        client_roots(&ca),
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::DestinationHttp);
}

#[tokio::test]
async fn destination_non_ip_body_is_explicit_failure() {
    let ca = make_ca("WindLab Fixture CA");
    let (cert, key) = make_leaf(&ca, &["localhost"], &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let tls = server_config(cert, key);
    let dest = spawn_destination(tls.clone(), 200, "not-an-ip").await;
    let proxy = spawn_proxy(tls, ProxyBehavior::NoAuth, dest).await;
    let err = windlab::run_proof(
        &config(proxy.port(), dest.port(), Duration::from_secs(10)),
        None,
        client_roots(&ca),
    )
    .await
    .unwrap_err();
    assert_eq!(err.class, FailureClass::InvalidIp);
}

#[tokio::test]
async fn unresolvable_proxy_is_classified_not_success() {
    // .invalid is RFC 6761 guaranteed-nonexistent. Resolvers that hijack
    // NXDOMAIN may turn this into a TCP failure; either way it must fail.
    let cfg = ProofConfig {
        proxy: ProxyEndpoint::new("nonexistent.windlab-fixture.invalid".into(), 443).unwrap(),
        target: Target::parse("https://localhost/").unwrap(),
        timeout: Duration::from_secs(5),
    };
    let err = windlab::run_proof(&cfg, None, RootCertStore::empty())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err.class,
            FailureClass::Dns | FailureClass::Tcp | FailureClass::Timeout
        ),
        "unexpected class: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Validation and secret hygiene
// ---------------------------------------------------------------------------

#[test]
fn malformed_hosts_and_ports_are_rejected() {
    assert!(ProxyEndpoint::new("".into(), 443).is_err());
    assert!(ProxyEndpoint::new("bad host".into(), 443).is_err());
    assert!(ProxyEndpoint::new("host\r\nX: y".into(), 443).is_err());
    assert!(ProxyEndpoint::new("user@evil.example".into(), 443).is_err());
    assert!(ProxyEndpoint::new("-bad.example".into(), 443).is_err());
    assert!(ProxyEndpoint::new("ok.example".into(), 0).is_err());
    assert!(ProxyEndpoint::new("ok.example".into(), 443).is_ok());
    assert!(ProxyEndpoint::new("127.0.0.1".into(), 8443).is_ok());
}

#[test]
fn ipv6_literal_authority_and_connect_target_formatting() {
    let ep = ProxyEndpoint::new("2001:db8::1".into(), 443).unwrap();
    assert_eq!(ep.host, "2001:db8::1");
    assert_eq!(ep.authority(), "[2001:db8::1]:443");

    let ep_bracketed = ProxyEndpoint::new("[::1]".into(), 9443).unwrap();
    assert_eq!(ep_bracketed.host, "::1");
    assert_eq!(ep_bracketed.authority(), "[::1]:9443");

    let t = Target::parse("https://api.ipify.org/").unwrap();
    assert_eq!(t.authority(), "api.ipify.org");
    assert_eq!(t.connect_authority(), "api.ipify.org:443");

    let t_v6 = Target::parse("https://[2001:db8::1]/").unwrap();
    assert_eq!(t_v6.host, "2001:db8::1");
    assert_eq!(t_v6.authority(), "[2001:db8::1]");
    assert_eq!(t_v6.connect_authority(), "[2001:db8::1]:443");
}

#[test]
fn target_url_must_be_https_without_credentials() {
    assert!(Target::parse("http://api.ipify.org/").is_err());
    assert!(Target::parse("https://user:pass@api.ipify.org/").is_err());
    assert!(Target::parse("not a url").is_err());
    let t = Target::parse("https://api.ipify.org").unwrap();
    assert_eq!(t.port, 443);
    assert_eq!(t.path_and_query, "/");
}

#[test]
fn header_injection_in_credentials_is_rejected() {
    assert!(ProxyCredentials::new("user".into(), "pass\r\nX-Injected: 1".into()).is_err());
    assert!(ProxyCredentials::new("user\r\n".into(), "pass".into()).is_err());
    assert!(ProxyCredentials::new("user\0".into(), "pass".into()).is_err());
    assert!(ProxyCredentials::new("user:name".into(), "pass".into()).is_err());
}

#[test]
fn secrets_are_redacted_in_debug_and_errors() {
    let secret = Secret::new("super-secret-value".into()).unwrap();
    assert!(!format!("{secret:?}").contains("super-secret-value"));
    let creds = ProxyCredentials::new(TEST_USER.into(), TEST_PASS.into()).unwrap();
    let debug = format!("{creds:?}");
    assert!(!debug.contains(TEST_PASS));
    assert!(!debug.contains(TEST_USER));
}
