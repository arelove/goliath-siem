//! The `receiver` role: records sent over the network, into each source's
//! raw topic.
//!
//! See `docs/adr/0018-collection.md`. Routes:
//!
//! - `POST /ingest/{source}`: a batch of the source's records in its own
//!   framing, such as JSON lines, optionally gzip-encoded, with the source's
//!   bearer token. Answered `200` only once the batch is in the pipe; `503`
//!   with `Retry-After` if the topic stayed full for 10 seconds.
//! - `GET /health`: whether the receiver is up; needs no token.
//!
//! With a certificate, the routes are served over HTTPS only.
//!
//! A batch becomes one raw record, stamped with when it was received, as a
//! file the collector takes does.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use goliath_pipe::Sender;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::RunError;
use crate::metrics::{Metrics, Received};
use crate::tls::TlsListener;

/// Bytes a request body may hold, as sent.
pub(crate) const MAX_BODY: usize = 16 << 20;
/// Bytes a gzip-encoded body may hold once decoded, so that a small body
/// cannot expand without bound.
pub(crate) const MAX_DECODED: usize = 64 << 20;
/// How long a request waits on a full topic before it is refused.
const WAIT: Duration = Duration::from_secs(10);
/// Seconds a refused sender is asked to wait before trying again.
const RETRY_AFTER: &str = "5";

/// A source the receiver takes records for: its token, and its raw topic.
pub(crate) struct Source<S> {
    pub(crate) token: String,
    pub(crate) raw: S,
}

struct Shared<S> {
    sources: BTreeMap<String, Source<S>>,
    metrics: Metrics,
}

/// The receiver, bound to its address and ready to serve.
pub(crate) struct Server {
    listener: Listener,
    app: Router,
}

enum Listener {
    Plain(TcpListener),
    Tls(TlsListener),
}

impl Server {
    /// Binds `listen`, so that a port in use fails at start, serving HTTPS
    /// if `tls` is given.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Io`] if the address cannot be bound.
    pub(crate) async fn bind<S: Sender + Send + Sync + 'static>(
        listen: SocketAddr,
        tls: Option<TlsAcceptor>,
        sources: BTreeMap<String, Source<S>>,
        metrics: Metrics,
    ) -> Result<Self, RunError> {
        let failed =
            |error: std::io::Error| RunError::Io(format!("listening on {listen}: {error}"));
        let listener = TcpListener::bind(listen).await.map_err(failed)?;
        let listener = match tls {
            Some(acceptor) => Listener::Tls(TlsListener::new(listener, acceptor).map_err(failed)?),
            None => Listener::Plain(listener),
        };
        Ok(Self {
            listener,
            app: app(Shared { sources, metrics }),
        })
    }

    /// Serves until `stop` is set, then finishes the requests in flight.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Io`] if serving fails.
    pub(crate) async fn serve(self, mut stop: watch::Receiver<bool>) -> Result<(), RunError> {
        let stopped = async move {
            while !*stop.borrow_and_update() {
                if stop.changed().await.is_err() {
                    break;
                }
            }
        };
        let served = match self.listener {
            Listener::Plain(listener) => {
                let address = listener
                    .local_addr()
                    .map_err(|error| RunError::Io(error.to_string()))?;
                info!(%address, "receiver listening");
                axum::serve(listener, self.app)
                    .with_graceful_shutdown(stopped)
                    .await
            }
            Listener::Tls(listener) => {
                info!(address = %listener.address(), "receiver listening with TLS");
                axum::serve(listener, self.app)
                    .with_graceful_shutdown(stopped)
                    .await
            }
        };
        served.map_err(|error| RunError::Io(format!("serving the receiver: {error}")))
    }
}

fn app<S: Sender + Send + Sync + 'static>(shared: Shared<S>) -> Router {
    Router::new()
        .route("/ingest/{source}", post(ingest::<S>))
        .route(
            "/health",
            get(|| async { axum::Json(json!({ "status": "ok" })) }),
        )
        .fallback(|| async { answer(StatusCode::NOT_FOUND, "no such route") })
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(Arc::new(shared))
}

/// A JSON answer: `{"error": "..."}`, or `{"status": "..."}` for success.
fn answer(status: StatusCode, message: &str) -> Response {
    let key = if status.is_success() {
        "status"
    } else {
        "error"
    };
    (status, axum::Json(json!({ key: message }))).into_response()
}

async fn ingest<S: Sender + Send + Sync + 'static>(
    State(shared): State<Arc<Shared<S>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(source) = shared.sources.get(&name) else {
        return answer(
            StatusCode::NOT_FOUND,
            "no source by that name takes records over HTTP",
        );
    };
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !bool::from(given.as_bytes().ct_eq(source.token.as_bytes())) {
        shared.metrics.received(&name, Received::Unauthorized, 0);
        return answer(
            StatusCode::UNAUTHORIZED,
            "the source's bearer token is needed",
        );
    }
    let bytes = match decode(&headers, &body) {
        Ok(bytes) => bytes,
        Err((status, message)) => {
            shared.metrics.received(&name, Received::Refused, 0);
            return answer(status, message);
        }
    };
    if bytes.is_empty() {
        shared.metrics.received(&name, Received::Refused, 0);
        return answer(StatusCode::BAD_REQUEST, "the body holds no records");
    }
    let size = bytes.len();
    let record = crate::raw::stamp(crate::raw::now(), &bytes);
    let started = std::time::Instant::now();
    match tokio::time::timeout(WAIT, source.raw.send(vec![record])).await {
        Ok(Ok(())) => {
            shared.metrics.waited(started.elapsed());
            shared.metrics.received(&name, Received::Taken, size);
            answer(StatusCode::OK, "taken")
        }
        Ok(Err(error)) => {
            warn!(source = name, %error, "the raw topic refused a batch");
            shared.metrics.received(&name, Received::Failed, 0);
            answer(
                StatusCode::SERVICE_UNAVAILABLE,
                "the pipe could not take the batch",
            )
            .with_retry()
        }
        Err(_) => {
            shared.metrics.waited(started.elapsed());
            shared.metrics.received(&name, Received::Busy, 0);
            answer(
                StatusCode::SERVICE_UNAVAILABLE,
                "the platform is behind; send the batch again later",
            )
            .with_retry()
        }
    }
}

trait WithRetry {
    fn with_retry(self) -> Self;
}

impl WithRetry for Response {
    fn with_retry(mut self) -> Self {
        self.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER));
        self
    }
}

/// The body as sent, or decoded from gzip, within [`MAX_DECODED`].
fn decode(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, (StatusCode, &'static str)> {
    let encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map_or("identity", str::trim);
    match encoding {
        "identity" | "" => Ok(body.to_vec()),
        "gzip" => {
            let mut decoded = Vec::new();
            let limit = u64::try_from(MAX_DECODED).unwrap_or(u64::MAX) + 1;
            flate2::read::MultiGzDecoder::new(body)
                .take(limit)
                .read_to_end(&mut decoded)
                .map_err(|_| (StatusCode::BAD_REQUEST, "the body is not valid gzip"))?;
            if decoded.len() > MAX_DECODED {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "the body decodes to more than 64 MiB",
                ));
            }
            Ok(decoded)
        }
        _ => Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "only gzip content encoding is taken",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::num::NonZeroUsize;

    use axum::body::Body;
    use axum::http::Request;
    use goliath_pipe::{MemoryTopic, Receiver};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn receiver(capacity: usize) -> (Router, MemoryTopic) {
        let topic = MemoryTopic::new(NonZeroUsize::new(capacity).unwrap());
        let mut sources = BTreeMap::new();
        sources.insert(
            "falco".to_owned(),
            Source {
                token: TOKEN.to_owned(),
                raw: topic.sender(),
            },
        );
        let app = app(Shared {
            sources,
            metrics: Metrics::new(),
        });
        (app, topic)
    }

    fn post(path: &str, token: Option<&str>, body: Vec<u8>, gzip: bool) -> Request<Body> {
        let mut request = Request::post(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if gzip {
            request = request.header("content-encoding", "gzip");
        }
        request.body(Body::from(body)).unwrap()
    }

    async fn call(
        app: Router,
        request: Request<Body>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or_default(),
        )
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn a_batch_is_in_the_raw_topic_when_it_is_answered() {
        let (app, topic) = receiver(10);
        let mut reader = topic.subscribe("normalizer");
        let lines = b"{\"a\":1}\n{\"a\":2}\n".to_vec();
        let (status, _, body) = call(
            app.clone(),
            post("/ingest/falco", Some(TOKEN), lines.clone(), false),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, _, _) =
            call(app, post("/ingest/falco", Some(TOKEN), gzip(&lines), true)).await;
        assert_eq!(status, StatusCode::OK);

        let delivered = reader.receive(10, Duration::from_millis(10)).await.unwrap();
        assert_eq!(delivered.len(), 2);
        for delivery in delivered {
            let (received, bytes) = crate::raw::read(&delivery.payload);
            assert!(received.is_some(), "stamped with when it was received");
            assert_eq!(bytes, lines.as_slice());
        }
    }

    #[tokio::test]
    async fn a_sender_without_its_token_or_for_another_source_is_refused() {
        let (app, topic) = receiver(10);
        let mut reader = topic.subscribe("normalizer");
        let body = b"{}\n".to_vec();
        let wrong = "f".repeat(TOKEN.len());
        for (path, token, expected) in [
            ("/ingest/falco", None, StatusCode::UNAUTHORIZED),
            (
                "/ingest/falco",
                Some(wrong.as_str()),
                StatusCode::UNAUTHORIZED,
            ),
            ("/ingest/sysmon", Some(TOKEN), StatusCode::NOT_FOUND),
        ] {
            let (status, _, answer) =
                call(app.clone(), post(path, token, body.clone(), false)).await;
            assert_eq!(status, expected, "{path}");
            assert!(answer["error"].is_string());
        }
        assert!(
            reader
                .receive(10, Duration::from_millis(10))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn bodies_that_are_empty_too_large_or_badly_encoded_are_refused() {
        let (app, _topic) = receiver(10);
        let cases = [
            (
                post("/ingest/falco", Some(TOKEN), Vec::new(), false),
                StatusCode::BAD_REQUEST,
            ),
            (
                post("/ingest/falco", Some(TOKEN), b"not gzip".to_vec(), true),
                StatusCode::BAD_REQUEST,
            ),
            (
                post(
                    "/ingest/falco",
                    Some(TOKEN),
                    vec![b'x'; MAX_BODY + 1],
                    false,
                ),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                post(
                    "/ingest/falco",
                    Some(TOKEN),
                    gzip(&vec![b'x'; MAX_DECODED + 1]),
                    true,
                ),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ];
        for (request, expected) in cases {
            let (status, _, _) = call(app.clone(), request).await;
            assert_eq!(status, expected);
        }
        let mut brotli = post("/ingest/falco", Some(TOKEN), b"x".to_vec(), false);
        brotli
            .headers_mut()
            .insert("content-encoding", HeaderValue::from_static("br"));
        let (status, _, _) = call(app, brotli).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_topic_asks_the_sender_to_come_back_and_takes_nothing_twice() {
        let (app, topic) = receiver(1);
        let mut reader = topic.subscribe("normalizer");
        let body = b"{}\n".to_vec();
        let (status, _, _) = call(
            app.clone(),
            post("/ingest/falco", Some(TOKEN), body.clone(), false),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // The topic holds one record its reader has not acknowledged.
        let (status, headers, _) = call(app, post("/ingest/falco", Some(TOKEN), body, false)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(headers.get(header::RETRY_AFTER).unwrap(), RETRY_AFTER);
        assert_eq!(
            reader
                .receive(10, Duration::from_millis(10))
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn with_a_certificate_it_serves_https_only() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};

        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let tls = crate::config::TlsConfig {
            certificate: directory.path().join("cert.pem"),
            key: directory.path().join("key.pem"),
        };
        std::fs::write(&tls.certificate, issued.cert.pem()).unwrap();
        std::fs::write(&tls.key, issued.signing_key.serialize_pem()).unwrap();
        let acceptor = crate::tls::acceptor(&tls, &[b"http/1.1"]).unwrap();

        let topic = MemoryTopic::new(NonZeroUsize::new(10).unwrap());
        let mut reader = topic.subscribe("normalizer");
        let mut sources = BTreeMap::new();
        sources.insert(
            "falco".to_owned(),
            Source {
                token: TOKEN.to_owned(),
                raw: topic.sender(),
            },
        );
        let server = Server::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            Some(acceptor),
            sources,
            Metrics::new(),
        )
        .await
        .unwrap();
        let Listener::Tls(listener) = &server.listener else {
            panic!("not listening with TLS");
        };
        let address = listener.address();
        let (stop, stopped) = watch::channel(false);
        let serving = tokio::spawn(server.serve(stopped));

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(issued.cert.der().to_vec()))
            .unwrap();
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let body = "{\"a\":1}\n";
        let request = format!(
            "POST /ingest/falco HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {TOKEN}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap_or_default();
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        let delivered = reader.receive(10, Duration::from_millis(10)).await.unwrap();
        assert_eq!(crate::raw::read(&delivered[0].payload).1, body.as_bytes());

        // Plain HTTP to the same port gets no answer.
        let mut plain = tokio::net::TcpStream::connect(address).await.unwrap();
        plain.write_all(request.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        let _ = plain.read_to_end(&mut answer).await;
        assert!(!answer.starts_with(b"HTTP/1.1 200"));

        stop.send(true).unwrap();
        serving.await.unwrap().unwrap();
    }
}
