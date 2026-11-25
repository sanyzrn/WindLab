//! Transport: DNS/TCP classification, TLS to the proxy, HTTP CONNECT with
//! challenge-response Basic auth (including bounded 1x reconnect when a proxy
//! closes after 407), and preservation of bytes buffered after the CONNECT
//! response.
//!
//! Ambient proxy environment variables (HTTP_PROXY etc.) are deliberately
//! never read: the proof connects only to the explicitly configured proxy.
//! There is no direct-traffic fallback.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::error::{FailureClass, ProofError};
use crate::secret::ProxyCredentials;

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_407_DRAIN_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const PER_ADDR_TCP_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, ProofError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ProofError::new(FailureClass::Dns, "dns", format!("resolve failed: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(ProofError::new(
            FailureClass::Dns,
            "dns",
            "resolve returned no addresses",
        ));
    }
    Ok(interleave_address_families(addrs))
}

/// Interleaves IPv4 and IPv6 addresses (preferring IPv4 first) so a blackholed
/// address family cannot exhaust the deadline before trying the other family.
fn interleave_address_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in addrs {
        if addr.is_ipv4() {
            v4.push(addr);
        } else {
            v6.push(addr);
        }
    }
    let mut out = Vec::with_capacity(v4.len() + v6.len());
    let mut i4 = v4.into_iter();
    let mut i6 = v6.into_iter();
    loop {
        match (i4.next(), i6.next()) {
            (Some(a), Some(b)) => {
                out.push(a);
                out.push(b);
            }
            (Some(a), None) => out.push(a),
            (None, Some(b)) => out.push(b),
            (None, None) => break,
        }
    }
    out
}

pub async fn tcp_connect(addrs: &[SocketAddr]) -> Result<TcpStream, ProofError> {
    let mut last = String::from("no addresses");
    for addr in addrs {
        match tokio::time::timeout(PER_ADDR_TCP_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => last = format!("connect to {addr} failed: {e}"),
            Err(_) => {
                last = format!(
                    "connect to {addr} timed out after {}s",
                    PER_ADDR_TCP_TIMEOUT.as_secs()
                );
            }
        }
    }
    Err(ProofError::new(FailureClass::Tcp, "tcp", last))
}

/// Client TLS configuration with strict certificate and hostname validation.
/// Advertises `http/1.1` via ALPN to match the HTTP/1.1 wire protocol used for
/// both CONNECT and destination verification. The root store is injected so
/// tests can trust a fixture-only CA without touching the system trust store.
pub fn client_tls_config(roots: RootCertStore) -> Arc<ClientConfig> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports safe default versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

pub fn server_name(host: &str) -> Result<ServerName<'static>, ProofError> {
    ServerName::try_from(host.to_string())
        .map_err(|_| ProofError::config("host is not a valid TLS server name"))
}

pub async fn tls_connect<S>(
    stream: S,
    name: ServerName<'static>,
    config: Arc<ClientConfig>,
    stage: &'static str,
    class: FailureClass,
) -> Result<TlsStream<S>, ProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    TlsConnector::from(config)
        .connect(name, stream)
        .await
        .map_err(|e| ProofError::new(class, stage, sanitize_tls_error(&e)))
}

/// rustls errors can embed certificate material but never our credentials.
/// Keep the message single-line, bounded, and free of peer data dumps.
fn sanitize_tls_error(e: &io::Error) -> String {
    let cleaned: String = e
        .to_string()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect();
    format!("TLS handshake failed: {cleaned}")
}

/// A stream with bytes that were already read from the inner stream prepended.
/// Preserves any destination bytes that arrived coalesced with the CONNECT
/// response.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Reads one final HTTP response head (skipping any `1xx` interim heads),
/// returning `(status, headers, leftover bytes)`. Header names are lowercased.
/// Bounded to prevent memory exhaustion.
pub async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), ProofError> {
    read_response_for(stream, "connect", FailureClass::ProxyProtocol).await
}

/// Shared bounded HTTP response-head reader for both proxy CONNECT and
/// destination HTTP verification.
pub async fn read_response_for<S: AsyncRead + Unpin>(
    stream: &mut S,
    stage: &'static str,
    class: FailureClass,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), ProofError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let head_end = loop {
            if let Some(idx) = find_header_end(&buf) {
                break idx;
            }
            if buf.len() >= MAX_RESPONSE_HEADER_BYTES {
                return Err(ProofError::new(
                    class,
                    stage,
                    "HTTP response head exceeds 16 KiB",
                ));
            }
            let n = stream.read(&mut chunk).await.map_err(|e| {
                ProofError::new(class, stage, format!("read failed: {e}"))
            })?;
            if n == 0 {
                return Err(ProofError::new(
                    class,
                    stage,
                    "peer closed connection before completing HTTP response",
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
        };

        if head_end + 4 > MAX_RESPONSE_HEADER_BYTES {
            return Err(ProofError::new(
                class,
                stage,
                "HTTP response head exceeds 16 KiB",
            ));
        }
        let mut headers = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
        let mut resp = httparse::Response::new(&mut headers);
        let parsed = resp
            .parse(&buf[..head_end + 4])
            .map_err(|e| ProofError::new(class, stage, format!("malformed HTTP response: {e}")))?;
        if !parsed.is_complete() {
            return Err(ProofError::new(class, stage, "incomplete HTTP response"));
        }
        let status = resp.code.unwrap_or(0);
        let leftover = buf[head_end + 4..].to_vec();

        if (100..200).contains(&status) && status != 101 {
            buf = leftover;
            continue;
        }

        let headers = resp
            .headers
            .iter()
            .map(|h| {
                (
                    h.name.to_ascii_lowercase(),
                    String::from_utf8_lossy(h.value).trim().to_string(),
                )
            })
            .collect();
        return Ok((status, headers, leftover));
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Checks RFC 9110 section 11.4 `Proxy-Authenticate` headers for a `Basic`
/// auth-scheme token (case-insensitive) without falsely matching parameter
/// values like `Digest realm="basic"` or schemes like `X-Basic`.
pub fn has_basic_proxy_auth_challenge(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name == "proxy-authenticate")
        .any(|(_, value)| challenge_list_has_basic(value))
}

fn challenge_list_has_basic(header_value: &str) -> bool {
    // Split on commas outside quoted strings, then inspect the leading token
    // of each challenge (ignoring key=value auth-param continuations).
    let mut in_quotes = false;
    let mut escaped = false;
    let mut start = 0usize;
    let bytes = header_value.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if in_quotes => escaped = true,
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                if segment_starts_with_basic(&header_value[start..i]) {
                    return true;
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    segment_starts_with_basic(&header_value[start..])
}

fn segment_starts_with_basic(segment: &str) -> bool {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return false;
    }
    let token = trimmed.split_ascii_whitespace().next().unwrap_or("");
    if token.contains('=') {
        return false;
    }
    token.eq_ignore_ascii_case("basic")
}

fn headers_request_close(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        (name == "connection" || name == "proxy-connection")
            && value
                .split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("close"))
    })
}

fn parse_content_length(headers: &[(String, String)]) -> Result<Option<usize>, ()> {
    let mut value_out: Option<usize> = None;
    for (name, value) in headers {
        if name == "content-length" {
            for part in value.split(',') {
                let parsed = part.trim().parse::<usize>().map_err(|_| ())?;
                match value_out {
                    Some(prev) if prev != parsed => return Err(()),
                    None => value_out = Some(parsed),
                    _ => {}
                }
            }
        }
    }
    Ok(value_out)
}

fn has_transfer_encoding(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, _)| name == "transfer-encoding")
}

/// Outcome of the initial `CONNECT` exchange on a TLS-verified proxy stream.
pub enum ConnectOutcome<S> {
    /// Tunnel established cleanly; caller may start destination TLS.
    Established(PrefixedStream<S>),
    /// Proxy issued a valid `407` Basic challenge and closed (or sent an
    /// undrainable body / `Connection: close`). Caller should open one fresh
    /// TCP+TLS connection to the proxy and send authenticated `CONNECT`.
    RetryOnFreshConnection,
}

/// Sends a single `CONNECT` request (optionally with `Proxy-Authorization`)
/// and validates the response. Used for preemptive auth and for the bounded 1x
/// fresh-connection retry after a `407` challenge.
pub async fn establish_connect_authenticated<S>(
    mut stream: S,
    authority: &str,
    credentials: &ProxyCredentials,
) -> Result<PrefixedStream<S>, ProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_connect_request(&mut stream, authority, Some(credentials)).await?;
    let (status, _headers, leftover) = read_response(&mut stream).await?;
    match status {
        200..=299 => Ok(PrefixedStream::new(leftover, stream)),
        407 => Err(ProofError::new(
            FailureClass::ProxyAuth,
            "connect",
            "proxy rejected credentials (407)",
        )),
        403 => Err(ProofError::new(
            FailureClass::ProxyAuth,
            "connect",
            "proxy forbade the tunnel (403)",
        )),
        other => Err(ProofError::new(
            FailureClass::ProxyProtocol,
            "connect",
            format!("unexpected CONNECT status after auth: {other}"),
        )),
    }
}

/// Performs HTTP CONNECT with challenge-response Basic authentication,
/// returning [`ConnectOutcome::RetryOnFreshConnection`] when a proxy sends a
/// valid `407` Basic challenge that cannot safely reuse the existing stream
/// (for example `Connection: close`, a chunked/oversized 407 error page, or
/// connection reset on the in-band retry).
pub async fn establish_connect_with_reconnect<S>(
    mut stream: S,
    authority: &str,
    credentials: Option<&ProxyCredentials>,
) -> Result<ConnectOutcome<S>, ProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_connect_request(&mut stream, authority, None).await?;
    let (status, headers, leftover) = read_response(&mut stream).await?;

    match status {
        200..=299 => Ok(ConnectOutcome::Established(PrefixedStream::new(
            leftover, stream,
        ))),
        407 => {
            let creds = credentials.ok_or_else(|| {
                ProofError::new(
                    FailureClass::ProxyAuth,
                    "connect",
                    "proxy requires authentication (407) but no credentials were provided",
                )
            })?;
            if !has_basic_proxy_auth_challenge(&headers) {
                return Err(ProofError::new(
                    FailureClass::ProxyAuth,
                    "connect",
                    "proxy offered no Basic authentication scheme",
                ));
            }

            if headers_request_close(&headers) || has_transfer_encoding(&headers) {
                return Ok(ConnectOutcome::RetryOnFreshConnection);
            }

            match parse_content_length(&headers) {
                Ok(Some(len)) if len > MAX_407_DRAIN_BYTES => {
                    return Ok(ConnectOutcome::RetryOnFreshConnection);
                }
                Ok(Some(len)) if len > 0 => {
                    if leftover.len() > len {
                        return Ok(ConnectOutcome::RetryOnFreshConnection);
                    }
                    let remaining = len - leftover.len();
                    if drain_exact(&mut stream, remaining).await.is_err() {
                        return Ok(ConnectOutcome::RetryOnFreshConnection);
                    }
                }
                Ok(None) => return Ok(ConnectOutcome::RetryOnFreshConnection),
                Ok(Some(_)) => {
                    if !leftover.is_empty() {
                        return Ok(ConnectOutcome::RetryOnFreshConnection);
                    }
                }
                Err(()) => return Ok(ConnectOutcome::RetryOnFreshConnection),
            }

            if write_connect_request(&mut stream, authority, Some(creds))
                .await
                .is_err()
            {
                return Ok(ConnectOutcome::RetryOnFreshConnection);
            }

            let (status, _headers, leftover) = match read_response(&mut stream).await {
                Ok(resp) => resp,
                Err(_) => return Ok(ConnectOutcome::RetryOnFreshConnection),
            };
            match status {
                200..=299 => Ok(ConnectOutcome::Established(PrefixedStream::new(
                    leftover, stream,
                ))),
                407 => Err(ProofError::new(
                    FailureClass::ProxyAuth,
                    "connect",
                    "proxy rejected credentials (407)",
                )),
                403 => Err(ProofError::new(
                    FailureClass::ProxyAuth,
                    "connect",
                    "proxy forbade the tunnel (403)",
                )),
                other => Err(ProofError::new(
                    FailureClass::ProxyProtocol,
                    "connect",
                    format!("unexpected CONNECT status after auth: {other}"),
                )),
            }
        }
        403 => Err(ProofError::new(
            FailureClass::ProxyAuth,
            "connect",
            "proxy forbade the tunnel (403)",
        )),
        other => Err(ProofError::new(
            FailureClass::ProxyProtocol,
            "connect",
            format!("unexpected CONNECT status: {other}"),
        )),
    }
}

/// Performs HTTP CONNECT with challenge-response Basic authentication on a
/// single stream: first request carries no credentials; on 407 with a Basic
/// challenge the request is retried once with `Proxy-Authorization`.
/// Credentials are only ever sent to the already TLS-verified proxy.
pub async fn establish_connect<S>(
    stream: S,
    authority: &str,
    credentials: Option<&ProxyCredentials>,
) -> Result<PrefixedStream<S>, ProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match establish_connect_with_reconnect(stream, authority, credentials).await? {
        ConnectOutcome::Established(tunneled) => Ok(tunneled),
        ConnectOutcome::RetryOnFreshConnection => Err(ProofError::new(
            FailureClass::ProxyProtocol,
            "connect",
            "proxy closed or sent an undrainable 407 response; fresh connection required",
        )),
    }
}

async fn write_connect_request<S>(
    stream: &mut S,
    authority: &str,
    credentials: Option<&ProxyCredentials>,
) -> Result<(), ProofError>
where
    S: AsyncWrite + Unpin,
{
    let request = match credentials {
        Some(creds) => {
            let auth = creds.basic_header_value();
            Zeroizing::new(format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {}\r\n\r\n",
                auth.as_str()
            ))
        }
        None => Zeroizing::new(format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        )),
    };
    stream.write_all(request.as_bytes()).await.map_err(|e| {
        ProofError::new(
            FailureClass::ProxyProtocol,
            "connect",
            format!("write failed: {e}"),
        )
    })?;
    stream.flush().await.map_err(|e| {
        ProofError::new(
            FailureClass::ProxyProtocol,
            "connect",
            format!("flush failed: {e}"),
        )
    })?;
    Ok(())
}

async fn drain_exact<S: AsyncRead + Unpin>(stream: &mut S, mut remaining: usize) -> io::Result<()> {
    let mut discard = [0u8; 1024];
    while remaining > 0 {
        let to_read = remaining.min(discard.len());
        let n = stream.read(&mut discard[..to_read]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof while draining 407 body",
            ));
        }
        remaining -= n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn response_parser_preserves_leftover_bytes() {
        let input = b"HTTP/1.1 200 Connection established\r\nX-Test: yes\r\n\r\nEARLYBYTES";
        let mut cursor = std::io::Cursor::new(input.to_vec());
        let (status, headers, leftover) = read_response(&mut cursor).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers, vec![("x-test".to_string(), "yes".to_string())]);
        assert_eq!(leftover, b"EARLYBYTES");
    }

    #[tokio::test]
    async fn response_parser_skips_1xx_interim_response() {
        let input = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\nOK";
        let mut cursor = std::io::Cursor::new(input.to_vec());
        let (status, _headers, leftover) = read_response(&mut cursor).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(leftover, b"OK");
    }

    #[tokio::test]
    async fn response_parser_rejects_garbage() {
        let mut cursor = std::io::Cursor::new(b"NOT-HTTP\r\n\r\n".to_vec());
        let err = read_response(&mut cursor).await.unwrap_err();
        assert_eq!(err.class, FailureClass::ProxyProtocol);
    }

    #[tokio::test]
    async fn response_parser_rejects_oversized_head() {
        let mut data = b"HTTP/1.1 200 OK\r\n".to_vec();
        data.extend(std::iter::repeat_n(b'a', MAX_RESPONSE_HEADER_BYTES + 1024));
        let mut cursor = std::io::Cursor::new(data);
        let err = read_response(&mut cursor).await.unwrap_err();
        assert_eq!(err.class, FailureClass::ProxyProtocol);
    }

    #[tokio::test]
    async fn response_parser_reports_closed_connection() {
        let mut cursor = std::io::Cursor::new(b"HTTP/1.1 200".to_vec());
        let err = read_response(&mut cursor).await.unwrap_err();
        assert_eq!(err.class, FailureClass::ProxyProtocol);
    }

    #[tokio::test]
    async fn prefixed_stream_drains_prefix_then_inner() {
        let inner = std::io::Cursor::new(b"INNER".to_vec());
        let mut stream = PrefixedStream::new(b"PREFIX".to_vec(), inner);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"PREFIXINNER");
    }

    #[test]
    fn basic_proxy_authenticate_parsing_is_strict() {
        let h = |v: &str| vec![("proxy-authenticate".to_string(), v.to_string())];
        assert!(has_basic_proxy_auth_challenge(&h(
            "Basic realm=\"Windscribe\""
        )));
        assert!(has_basic_proxy_auth_challenge(&h("basic")));
        assert!(has_basic_proxy_auth_challenge(&h(
            "Digest realm=\"x\", Basic realm=\"y\""
        )));
        assert!(!has_basic_proxy_auth_challenge(&h(
            "Digest realm=\"basic\""
        )));
        assert!(!has_basic_proxy_auth_challenge(&h("X-Basic realm=\"foo\"")));
        assert!(!has_basic_proxy_auth_challenge(&h("Bearer realm=\"foo\"")));
    }

    #[test]
    fn address_families_are_interleaved_v4_first() {
        let addrs: Vec<SocketAddr> = vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
        ];
        let ordered = interleave_address_families(addrs);
        assert!(ordered[0].is_ipv4());
        assert!(ordered[1].is_ipv6());
        assert!(ordered[2].is_ipv4());
        assert!(ordered[3].is_ipv6());
    }
}
