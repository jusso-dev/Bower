//! HTTP/1.1 listener with Kestrel-equivalent bounds: 30 s request-header timeout,
//! no `Server` header, graceful drain on shutdown (bounded by the host shutdown
//! timeout).

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use reqwest::Url;
use tokio::net::TcpListener;
use tracing::warn;

use crate::error::HostError;
use crate::shutdown::ShutdownToken;

/// Kestrel `RequestHeadersTimeout`.
pub const REQUEST_HEADERS_TIMEOUT: Duration = Duration::from_secs(30);
/// Kestrel `MaxRequestHeaderCount`.
const MAXIMUM_REQUEST_HEADERS: usize = 100;
/// Bounds the request line plus headers (Kestrel: 8 KiB line, 32 KiB headers); larger
/// heads get 431.
const MAXIMUM_HEADER_BUFFER_BYTES: usize = 64 * 1024;
/// .NET `HostOptions.ShutdownTimeout`.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Socket addresses for `BOWER_LISTEN_URL` (Kestrel `UseUrls` semantics: `localhost`
/// binds both loopbacks, a host name binds every interface).
pub fn listen_addresses(listen_url: &str) -> Result<Vec<SocketAddr>, HostError> {
    let url = Url::parse(listen_url).map_err(|_| {
        HostError::new(
            "InvalidOperationException",
            "BOWER_LISTEN_URL must be an absolute HTTP(S) URL.",
        )
    })?;
    if url.scheme() == "https" {
        return Err(HostError::new(
            "InvalidOperationException",
            "HTTPS listeners are not supported by the Rust collector; terminate TLS in front of it.",
        ));
    }
    let port = url.port_or_known_default().unwrap_or(80);
    let host = url.host_str().unwrap_or_default();
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(vec![
            SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        ]);
    }
    match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        Ok(address) => Ok(vec![SocketAddr::new(address, port)]),
        Err(_) => Ok(vec![SocketAddr::from(([0, 0, 0, 0], port))]),
    }
}

/// Binds every address; at least one must succeed (Kestrel tolerates a missing IPv6
/// loopback for `localhost`).
pub async fn bind(addresses: &[SocketAddr]) -> Result<Vec<TcpListener>, HostError> {
    let mut listeners = Vec::new();
    let mut last_error = None;
    for address in addresses {
        match TcpListener::bind(address).await {
            Ok(listener) => listeners.push(listener),
            Err(error) => last_error = Some((address, error)),
        }
    }
    if listeners.is_empty() {
        let (address, error) = last_error.expect("at least one address");
        return Err(HostError::new(
            "IOException",
            format!(
                "Failed to bind to address http://{address}: {}.",
                error.kind()
            ),
        ));
    }
    Ok(listeners)
}

/// Serves until `shutdown`, then stops accepting and drains open connections for at
/// most [`SHUTDOWN_TIMEOUT`].
pub async fn serve(listeners: Vec<TcpListener>, app: Router, shutdown: ShutdownToken) {
    let graceful = GracefulShutdown::new();
    let (connections, mut receiver) = tokio::sync::mpsc::channel::<tokio::net::TcpStream>(64);
    let mut acceptors = Vec::new();
    for listener in listeners {
        let connections = connections.clone();
        let shutdown = shutdown.clone();
        acceptors.push(tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    () = shutdown.cancelled() => return,
                };
                match accepted {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        if connections.send(stream).await.is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        // EMFILE and friends: back off instead of spinning.
                        warn!(error_kind = %error.kind(), "Accept failed.");
                        if !shutdown.sleep(Duration::from_millis(100)).await {
                            return;
                        }
                    }
                }
            }
        }));
    }
    drop(connections);

    loop {
        let stream = tokio::select! {
            stream = receiver.recv() => stream,
            () = shutdown.cancelled() => None,
        };
        let Some(stream) = stream else { break };
        let service = TowerToHyperService::new(app.clone());
        let connection = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(REQUEST_HEADERS_TIMEOUT)
            .max_headers(MAXIMUM_REQUEST_HEADERS)
            .max_buf_size(MAXIMUM_HEADER_BUFFER_BYTES)
            .serve_connection(TokioIo::new(stream), service);
        let watched = graceful.watch(connection);
        tokio::spawn(async move {
            let _ = watched.await;
        });
    }

    for acceptor in acceptors {
        acceptor.abort();
    }
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, graceful.shutdown()).await;
}

/// `--healthcheck`: GET /health on the local listener; success only on HTTP 200.
pub fn healthcheck(listen_url: &str) -> bool {
    use std::io::{Read, Write};

    let Ok(addresses) = listen_addresses(listen_url) else {
        return false;
    };
    let Some(address) = addresses.first() else {
        return false;
    };
    let target = if address.ip().is_unspecified() {
        SocketAddr::new(
            if address.is_ipv4() {
                std::net::Ipv4Addr::LOCALHOST.into()
            } else {
                std::net::Ipv6Addr::LOCALHOST.into()
            },
            address.port(),
        )
    } else {
        *address
    };
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&target, Duration::from_secs(3))
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let request = format!("GET /health HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 64];
    let mut read = 0;
    while read < 12 {
        match stream.read(&mut head[read..]) {
            Ok(0) | Err(_) => break,
            Ok(count) => read += count,
        }
    }
    head[..read].starts_with(b"HTTP/1.1 200")
}
