//! Destination verification through the established tunnel: end-to-end TLS
//! to the target, one HTTP GET, and strict IP validation of the body.

use std::net::IpAddr;
use std::sync::Arc;

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::client::TlsStream;

use crate::config::Target;
use crate::error::{FailureClass, ProofError};
use crate::tunnel;

const MAX_BODY_BYTES: u64 = 64 * 1024;

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
/// Any non-200 status or non-IP body is an explicit failure, never success.
pub async fn http_get_ip<S>(
    stream: &mut TlsStream<S>,
    target: &Target,
) -> Result<IpAddr, ProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: windlab-proof/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
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

    let mut buf = Vec::new();
    let mut limited = stream.take(MAX_BODY_BYTES + 1);
    limited.read_to_end(&mut buf).await.map_err(|e| {
        ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            format!("read failed: {e}"),
        )
    })?;
    if buf.len() as u64 > MAX_BODY_BYTES {
        return Err(ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            "response exceeds 64 KiB limit",
        ));
    }

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let head_len = match resp.parse(&buf) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => {
            return Err(ProofError::new(
                FailureClass::DestinationHttp,
                "http",
                "malformed or incomplete HTTP response",
            ))
        }
    };
    let status = resp.code.unwrap_or(0);
    if status != 200 {
        return Err(ProofError::new(
            FailureClass::DestinationHttp,
            "http",
            format!("destination returned status {status}"),
        ));
    }
    let body = String::from_utf8_lossy(&buf[head_len..]);
    let body = body.trim();
    body.parse::<IpAddr>().map_err(|_| {
        ProofError::new(
            FailureClass::InvalidIp,
            "http",
            "destination body is not a bare IP address",
        )
    })
}
