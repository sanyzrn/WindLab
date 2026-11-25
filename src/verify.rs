//! Destination verification through the established tunnel: end-to-end TLS
//! to the target, one HTTP GET, RFC 9112 body framing (`Content-Length`,
//! `Transfer-Encoding: chunked`, or EOF), and strict IP validation of the body.

use std::net::IpAddr;
use std::sync::Arc;

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::client::TlsStream;

use crate::config::Target;
use crate::error::{FailureClass, ProofError};
use crate::tunnel;

const MAX_BODY_BYTES: usize = 64 * 1024;

pub async fn destination_tls<S>(
    tunnel_stream: S,
    target: &Target,
    config: Arc<ClientConfig>,
) -> Result<TlsStream<S>, ProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = tunnel::server_name(&target.host)?;
    tunnel::tls_connect(
        tunnel_stream,
        name,
        config,
        "destination-tls",
        FailureClass::DestinationTls,
    )
    .await
}

/// Sends `GET` and expects a bare IP address body (e.g. api.ipify.org).
/// Supports `Content-Length`, `Transfer-Encoding: chunked`, and close-delimited
/// responses. Any non-200 status or non-IP body is an explicit failure, never
/// success.
pub async fn http_get_ip<S>(
    stream: &mut TlsStream<S>,
    target: &Target,
) -> Result<IpAddr, ProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: windlab-proof/0.1\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        target.path_and_query,
        target.authority()
    );
    stream.write_all(request.as_bytes()).await.map_err(|e| {
        ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            format!("write failed: {e}"),
        )
    })?;
    stream.flush().await.map_err(|e| {
        ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            format!("flush failed: {e}"),
        )
    })?;

    let (status, headers, leftover) =
        tunnel::read_response_for(stream, "http", FailureClass::DestinationHttp).await?;
    if status != 200 {
        return Err(ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            format!("destination returned status {status}"),
        ));
    }

    validate_content_encoding(&headers)?;

    let chunked = is_chunked(&headers)?;
    let length = parse_content_length(&headers)?;
    if chunked && length.is_some() {
        return Err(ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            "conflicting Transfer-Encoding and Content-Length",
        ));
    }
    let body_bytes = if chunked {
        read_chunked_body(stream, leftover).await?
    } else if let Some(len) = length {
        read_exact_body(stream, leftover, len).await?
    } else {
        read_eof_body(stream, leftover).await?
    };

    let body = String::from_utf8_lossy(&body_bytes);
    let body = body.trim();
    body.parse::<IpAddr>().map_err(|_| {
        ProofError::new(
            FailureClass::InvalidIp,
            "http",
            "destination body is not a bare IP address",
        )
    })
}

fn validate_content_encoding(headers: &[(String, String)]) -> Result<(), ProofError> {
    for (name, value) in headers {
        if name == "content-encoding" {
            let enc = value.trim();
            if !enc.is_empty() && !enc.eq_ignore_ascii_case("identity") {
                return Err(ProofError::new(
                    FailureClass::DestinationHttp,
                    "http",
                    format!("unsupported Content-Encoding: {enc}"),
                ));
            }
        }
    }
    Ok(())
}

fn is_chunked(headers: &[(String, String)]) -> Result<bool, ProofError> {
    let mut encodings = Vec::new();
    for (name, value) in headers {
        if name == "transfer-encoding" {
            for part in value.split(',') {
                let tok = part.trim().to_ascii_lowercase();
                if !tok.is_empty() {
                    encodings.push(tok);
                }
            }
        }
    }
    if encodings.is_empty() {
        return Ok(false);
    }
    if encodings.len() == 1 && encodings[0] == "chunked" {
        return Ok(true);
    }
    Err(ProofError::new(
        FailureClass::DestinationHttp,
        "http",
        "unsupported Transfer-Encoding",
    ))
}

fn parse_content_length(headers: &[(String, String)]) -> Result<Option<usize>, ProofError> {
    let mut out: Option<usize> = None;
    for (name, value) in headers {
        if name == "content-length" {
            for part in value.split(',') {
                let parsed = part.trim().parse::<usize>().map_err(|_| {
                    ProofError::new(
                        FailureClass::DestinationHttp,
                        "http",
                        "invalid Content-Length header",
                    )
                })?;
                match out {
                    Some(prev) if prev != parsed => {
                        return Err(ProofError::new(
                            FailureClass::DestinationHttp,
                            "http",
                            "conflicting Content-Length headers",
                        ));
                    }
                    None => out = Some(parsed),
                    _ => {}
                }
            }
        }
    }
    if matches!(out, Some(len) if len > MAX_BODY_BYTES) {
        return Err(ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            "response exceeds 64 KiB limit",
        ));
    }
    Ok(out)
}

async fn read_exact_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut buf: Vec<u8>,
    expected_len: usize,
) -> Result<Vec<u8>, ProofError> {
    if buf.len() >= expected_len {
        buf.truncate(expected_len);
        return Ok(buf);
    }
    let mut chunk = [0u8; 1024];
    while buf.len() < expected_len {
        let need = (expected_len - buf.len()).min(chunk.len());
        let n = stream.read(&mut chunk[..need]).await.map_err(|e| {
            ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                format!("read failed: {e}"),
            )
        })?;
        if n == 0 {
            return Err(ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "destination closed connection before Content-Length bytes arrived",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

async fn read_eof_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut buf: Vec<u8>,
) -> Result<Vec<u8>, ProofError> {
    if buf.len() > MAX_BODY_BYTES {
        return Err(ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            "response exceeds 64 KiB limit",
        ));
    }
    let remaining = (MAX_BODY_BYTES - buf.len()) as u64 + 1;
    let mut limited = stream.take(remaining);
    limited.read_to_end(&mut buf).await.map_err(|e| {
        ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            format!("read failed: {e}"),
        )
    })?;
    if buf.len() > MAX_BODY_BYTES {
        return Err(ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            "response exceeds 64 KiB limit",
        ));
    }
    Ok(buf)
}

async fn read_chunked_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut raw: Vec<u8>,
) -> Result<Vec<u8>, ProofError> {
    let mut decoded = Vec::new();
    let mut pos = 0usize;

    loop {
        let line_end = read_until_crlf(stream, &mut raw, pos).await?;
        let line = std::str::from_utf8(&raw[pos..line_end]).map_err(|_| {
            ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "invalid UTF-8 in chunk size line",
            )
        })?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16).map_err(|_| {
            ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "invalid chunk size",
            )
        })?;
        pos = line_end + 2;

        if chunk_len == 0 {
            // Consume the complete bounded trailer section before reporting success.
            let trailer_start = pos;
            loop {
                let end = read_until_crlf(stream, &mut raw, pos).await?;
                if end.saturating_sub(trailer_start) > 16 * 1024 {
                    return Err(ProofError::new(
                        FailureClass::DestinationHttp,
                        "http",
                        "chunk trailers exceed limit",
                    ));
                }
                if end == pos {
                    return Ok(decoded);
                }
                if !raw[pos..end].contains(&b':') {
                    return Err(ProofError::new(
                        FailureClass::DestinationHttp,
                        "http",
                        "malformed chunk trailer",
                    ));
                }
                pos = end + 2;
            }
        }
        if decoded.len().saturating_add(chunk_len) > MAX_BODY_BYTES {
            return Err(ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "response exceeds 64 KiB limit",
            ));
        }

        ensure_buffered(stream, &mut raw, pos + chunk_len + 2).await?;
        if &raw[pos + chunk_len..pos + chunk_len + 2] != b"\r\n" {
            return Err(ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "malformed chunk terminator",
            ));
        }
        decoded.extend_from_slice(&raw[pos..pos + chunk_len]);
        pos += chunk_len + 2;
        // Discard consumed framing so many small chunks cannot grow memory unboundedly.
        if pos >= 4096 {
            raw.drain(..pos);
            pos = 0;
        }
    }
}

async fn read_until_crlf<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    start: usize,
) -> Result<usize, ProofError> {
    let mut tmp = [0u8; 512];
    loop {
        if let Some(rel) = buf[start..].windows(2).position(|w| w == b"\r\n") {
            if rel <= 1024 {
                return Ok(start + rel);
            }
            return Err(ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "chunk size line exceeds limit",
            ));
        }
        if buf.len().saturating_sub(start) > 1024 {
            return Err(ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "chunk size line exceeds limit",
            ));
        }
        let n = stream.read(&mut tmp).await.map_err(|e| {
            ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                format!("read failed: {e}"),
            )
        })?;
        if n == 0 {
            return Err(ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "unexpected EOF in chunked response",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn ensure_buffered<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    target_len: usize,
) -> Result<(), ProofError> {
    let mut tmp = [0u8; 1024];
    while buf.len() < target_len {
        let need = (target_len - buf.len()).min(tmp.len());
        let n = stream.read(&mut tmp[..need]).await.map_err(|e| {
            ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                format!("read failed: {e}"),
            )
        })?;
        if n == 0 {
            return Err(ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "unexpected EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chunked_requires_complete_trailers() {
        let mut empty = tokio::io::empty();
        assert!(read_chunked_body(&mut empty, b"1\r\na\r\n0\r\n".to_vec())
            .await
            .is_err());
        let result = read_chunked_body(&mut empty, b"1\r\na\r\n0\r\nX-Test: ok\r\n\r\n".to_vec())
            .await
            .unwrap();
        assert_eq!(result, b"a");
    }
}
