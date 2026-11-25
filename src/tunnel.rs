//! Transport: DNS/TCP classification, TLS to the proxy, HTTP CONNECT with
//! challenge-response Basic auth, and preservation of bytes buffered after
//! the CONNECT response.
//!
//! Ambient proxy environment variables (HTTP_PROXY etc.) are deliberately
//! never read: the proof connects only to the explicitly configured proxy.
//! There is no direct-traffic fallback.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::{FailureClass, ProofError};
use crate::secret::ProxyCredentials;

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

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
    Ok(addrs)
}

pub async fn tcp_connect(addrs: &[SocketAddr]) -> Result<TcpStream, ProofError> {
    let mut last = String::from("no addresses");
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => last = format!("connect to {addr} failed: {e}"),
        }
    }
    Err(ProofError::new(FailureClass::Tcp, "tcp", last))
}

/// Client TLS configuration with strict certificate and hostname validation.
/// The root store is injected so tests can trust a fixture-only CA without
/// touching the system trust store.
pub fn client_tls_config(roots: RootCertStore) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports safe default versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
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
/// Keep the message bounded and free of peer data dumps.
fn sanitize_tls_error(e: &io::Error) -> String {
    let msg = e.to_string();
    let truncated: String = msg.chars().take(300).collect();
    format!("TLS handshake failed: {truncated}")
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

/// Reads one HTTP response head, returning (status, headers, leftover bytes).
/// Header names are lowercased. Bounded to prevent memory exhaustion.
pub async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), ProofError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(idx) = find_header_end(&buf) {
            break idx;
        }
        if buf.len() >= MAX_RESPONSE_HEADER_BYTES {
            return Err(ProofError::new(
                FailureClass::ProxyProtocol,
                "connect",
                "CONNECT response head exceeds 16 KiB",
            ));
        }
        let n = stream.read(&mut chunk).await.map_err(|e| {
            ProofError::new(
                FailureClass::ProxyProtocol,
                "connect",
                format!("read failed: {e}"),
            )
        })?;
        if n == 0 {
            return Err(ProofError::new(
                FailureClass::ProxyProtocol,
                "connect",
                "proxy closed connection before completing CONNECT response",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let parsed = resp.parse(&buf[..head_end + 4]).map_err(|e| {
        ProofError::new(
            FailureClass::ProxyProtocol,
            "connect",
            format!("malformed CONNECT response: {e}"),
        )
    })?;
    if !parsed.is_complete() {
        return Err(ProofError::new(
            FailureClass::ProxyProtocol,
            "connect",
            "incomplete CONNECT response",
        ));
    }
    let status = resp.code.unwrap_or(0);
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
    let leftover = buf[head_end + 4..].to_vec();
    Ok((status, headers, leftover))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Performs HTTP CONNECT with challenge-response Basic authentication:
/// first request carries no credentials; on 407 with a Basic challenge the
/// request is retried once with `Proxy-Authorization`. Credentials are only
/// ever sent to the already TLS-verified proxy.
pub async fn establish_connect<S>(
    mut stream: S,
    authority: &str,
    credentials: Option<&ProxyCredentials>,
) -> Result<PrefixedStream<S>, ProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(|e| {
        ProofError::new(
            FailureClass::ProxyProtocol,
            "connect",
            format!("write failed: {e}"),
        )
    })?;
    let (status, headers, leftover) = read_response(&mut stream).await?;

    match status {
        200 => Ok(PrefixedStream::new(leftover, stream)),
        407 => {
            if !leftover.is_empty() {
                return Err(ProofError::new(
                    FailureClass::ProxyProtocol,
                    "connect",
                    "407 response carried a body; cannot reuse connection",
                ));
            }
            let creds = credentials.ok_or_else(|| {
                ProofError::new(
                    FailureClass::ProxyAuth,
                    "connect",
                    "proxy requires authentication (407) but no credentials were provided",
                )
            })?;
            let scheme_ok = headers.iter().any(|(name, value)| {
                name == "proxy-authenticate" && value.to_ascii_lowercase().contains("basic")
            });
            if !scheme_ok {
                return Err(ProofError::new(
                    FailureClass::ProxyAuth,
                    "connect",
                    "proxy offered no Basic authentication scheme",
                ));
            }
            let request = format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {}\r\n\r\n",
                creds.basic_header_value()
            );
            stream.write_all(request.as_bytes()).await.map_err(|e| {
                ProofError::new(
                    FailureClass::ProxyProtocol,
                    "connect",
                    format!("write failed: {e}"),
                )
            })?;
            let (status, _headers, leftover) = read_response(&mut stream).await?;
            match status {
                200 => Ok(PrefixedStream::new(leftover, stream)),
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
}
