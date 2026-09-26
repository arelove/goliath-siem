//! The `api` role: searches over the stored events, over HTTP.
//!
//! See `docs/adr/0016-event-search.md`. Routes, all JSON:
//!
//! - `POST /api/v1/search`: a search; one page of events, newest first.
//! - `GET /api/v1/events/{at}`: one event, by the `at` a search returned,
//!   with its normalization issues.
//! - `GET /api/v1/schema/classes`: the OCSF classes.
//! - `GET /api/v1/schema/classes/{uid}/paths`: the paths a search can name
//!   in a class, with what each holds, for the interface to complete.
//! - `GET /api/v1/health`: whether the service is up; needs no token.
//!
//! With a token configured, every other API request must carry it as
//! `Authorization: Bearer <token>`. The built interface, if configured, is
//! served at `/` on the same origin, so no cross-origin access is enabled.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use goliath_ocsf::schema::{self, Attribute, Base};
use goliath_search::{Cursor, Limits, Search};
use goliath_store::{Found, SearchLimits, Store, StoreError};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{error, info};

use crate::RunError;
use crate::config::ApiConfig;

/// Bytes a request body may hold.
const MAX_BODY: usize = 64 * 1024;

/// Levels of objects the schema paths descend through, so that recursive
/// objects such as `process.parent_process` end.
const MAX_DEPTH: usize = 4;

/// What every request shares.
struct Shared {
    store: Store,
    token: Option<String>,
    limits: Limits,
    query: SearchLimits,
}

/// The API, bound to its address and ready to serve.
pub(crate) struct Server {
    listener: TcpListener,
    app: Router,
}

impl Server {
    /// Binds the configured address, so that a port in use fails at start.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if the token cannot be read, and
    /// [`RunError::Io`] if the address cannot be bound.
    pub(crate) async fn bind(config: &ApiConfig, store: Store) -> Result<Self, RunError> {
        let shared = Shared {
            store,
            token: config.token()?,
            limits: Limits {
                max_span_ms: i64::from(config.max_span_days.get()) * 24 * 60 * 60 * 1000,
                ..Limits::default()
            },
            query: SearchLimits::default(),
        };
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(|error| RunError::Io(format!("listening on {}: {error}", config.listen)))?;
        Ok(Self {
            listener,
            app: app(shared, config.ui.clone()),
        })
    }

    /// Serves until `stop` is set, then finishes the requests in flight.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Io`] if serving fails.
    pub(crate) async fn serve(self, mut stop: watch::Receiver<bool>) -> Result<(), RunError> {
        let address = self
            .listener
            .local_addr()
            .map_err(|error| RunError::Io(error.to_string()))?;
        info!(%address, "api listening");
        axum::serve(self.listener, self.app)
            .with_graceful_shutdown(async move {
                while !*stop.borrow_and_update() {
                    if stop.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
            .map_err(|error| RunError::Io(format!("serving the api: {error}")))
    }
}

fn app(shared: Shared, ui: Option<PathBuf>) -> Router {
    let shared = Arc::new(shared);
    let protected = Router::new()
        .route("/search", post(search))
        .route("/events/{at}", get(event))
        .route("/schema/classes", get(classes))
        .route("/schema/classes/{uid}/paths", get(paths))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&shared),
            authorize,
        ));
    let api = Router::new()
        .route(
            "/health",
            get(|| async { axum::Json(json!({ "status": "ok" })) }),
        )
        .merge(protected)
        .fallback(|| async { problem(StatusCode::NOT_FOUND, "no such route") })
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(shared);
    let router = Router::new().nest("/api/v1", api);
    let router = match ui {
        Some(ui) => {
            let index = ui.join("index.html");
            router.fallback_service(ServeDir::new(ui).fallback(ServeFile::new(index)))
        }
        None => router.fallback(|| async { problem(StatusCode::NOT_FOUND, "no such route") }),
    };
    [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
    ]
    .into_iter()
    .fold(router, |router, (name, value)| {
        router.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ))
    })
}

/// A JSON error: `{"error": "..."}`.
fn problem(status: StatusCode, message: impl Into<String>) -> Response {
    (status, axum::Json(json!({ "error": message.into() }))).into_response()
}

async fn authorize(State(shared): State<Arc<Shared>>, request: Request, next: Next) -> Response {
    if let Some(token) = &shared.token {
        let given = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        if !bool::from(given.as_bytes().ct_eq(token.as_bytes())) {
            return problem(StatusCode::UNAUTHORIZED, "a valid bearer token is needed");
        }
    }
    next.run(request).await
}

fn found(found: &Found) -> Value {
    json!({
        "at": found.at.to_string(),
        "class_uid": found.class_uid,
        "source": found.source,
        "kind": found.kind,
        "event": found.event,
    })
}

/// A failure of the store: a search that read too much is the searcher's to
/// narrow; anything else is logged in full and reported without detail.
fn store_failed(error: &StoreError) -> Response {
    let text = error.to_string();
    if ["TIMEOUT_EXCEEDED", "TOO_MANY_ROWS"]
        .iter()
        .any(|code| text.contains(code))
    {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "the search read too much; narrow the time range, or name a class or a filter",
        );
    }
    error!(%error, "search failed");
    problem(
        StatusCode::BAD_GATEWAY,
        "the event store could not answer; the server log has the details",
    )
}

async fn search(
    State(shared): State<Arc<Shared>>,
    body: Result<axum::Json<Search>, JsonRejection>,
) -> Response {
    let search = match body {
        Ok(axum::Json(search)) => search,
        Err(rejection) => return problem(rejection.status(), rejection.body_text()),
    };
    let checked = match search.check(&shared.limits) {
        Ok(checked) => checked,
        Err(error) => return problem(StatusCode::BAD_REQUEST, error.to_string()),
    };
    match shared.store.search(&checked, shared.query).await {
        Ok(page) => axum::Json(json!({
            "events": page.events.iter().map(found).collect::<Vec<_>>(),
            "next": page.next.map(|cursor| cursor.to_string()),
        }))
        .into_response(),
        Err(error) => store_failed(&error),
    }
}

async fn event(State(shared): State<Arc<Shared>>, Path(at): Path<String>) -> Response {
    let at: Cursor = match at.parse() {
        Ok(at) => at,
        Err(error) => return problem(StatusCode::BAD_REQUEST, error.to_string()),
    };
    match shared.store.event(at, shared.query).await {
        Ok(Some(stored)) => {
            let mut body = found(&stored.found);
            body["source_version"] = json!(stored.source_version);
            body["issues"] = stored
                .issues
                .iter()
                .map(|(target, source, reason)| {
                    json!({ "target": target, "source": source, "reason": reason })
                })
                .collect();
            axum::Json(body).into_response()
        }
        Ok(None) => problem(StatusCode::NOT_FOUND, "no event is stored there"),
        Err(error) => store_failed(&error),
    }
}

async fn classes() -> Response {
    let classes: Vec<Value> = schema::classes()
        .iter()
        .map(|class| json!({ "uid": class.uid(), "name": class.name() }))
        .collect();
    axum::Json(json!({ "version": goliath_ocsf::SCHEMA_VERSION, "classes": classes }))
        .into_response()
}

async fn paths(Path(uid): Path<u32>) -> Response {
    let Some(class) = schema::class(uid) else {
        return problem(
            StatusCode::NOT_FOUND,
            format!("OCSF {} has no class {uid}", goliath_ocsf::SCHEMA_VERSION),
        );
    };
    let mut found = Vec::new();
    walk("", class.attributes(), 0, &mut found);
    axum::Json(json!({ "class_uid": uid, "paths": found })).into_response()
}

/// Every path a search can name under `attributes`: lists are left out, as
/// searches cannot look into them yet, and free-form objects end the walk.
fn walk(prefix: &str, attributes: &[Attribute], depth: usize, found: &mut Vec<Value>) {
    for attribute in attributes {
        if attribute.is_array() {
            continue;
        }
        let path = format!("{prefix}{}", attribute.name());
        let holds = match attribute.base() {
            Base::String => "text",
            Base::Integer | Base::Long if attribute.type_name() == "timestamp_t" => "time",
            Base::Integer | Base::Long => "integer",
            Base::Float => "number",
            Base::Boolean => "boolean",
            Base::Object => match attribute.object() {
                Some(object) if !object.is_free_form() => "object",
                _ => "any",
            },
            _ => "any",
        };
        let values = attribute.enum_values();
        found.push(if values.is_empty() {
            json!({ "path": path, "holds": holds })
        } else {
            json!({ "path": path, "holds": holds, "values": values })
        });
        if holds == "object"
            && depth + 1 < MAX_DEPTH
            && let Some(object) = attribute.object()
        {
            walk(&format!("{path}."), object.attributes(), depth + 1, found);
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn test_app(token: Option<&str>) -> Router {
        // Nothing listens on port 9; a search that reaches the store fails.
        let store = Store::new("http://127.0.0.1:9", "goliath").unwrap();
        app(
            Shared {
                store,
                token: token.map(str::to_owned),
                limits: Limits::default(),
                query: SearchLimits::default(),
            },
            None,
        )
    }

    async fn call(
        app: Router,
        request: Request<Body>,
    ) -> (StatusCode, Value, axum::http::HeaderMap) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body, headers)
    }

    fn post_search(body: &str, token: Option<&str>) -> Request<Body> {
        let mut request =
            Request::post("/api/v1/search").header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request.body(Body::from(body.to_owned())).unwrap()
    }

    const VALID: &str =
        r#"{"from":"2026-09-25T00:00:00Z","to":"2026-09-26T00:00:00Z","classes":[1007]}"#;

    #[tokio::test]
    async fn requests_without_the_token_are_refused() {
        let (status, body, _) = call(test_app(Some(TOKEN)), post_search(VALID, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "a valid bearer token is needed");
        let wrong = "f".repeat(TOKEN.len());
        let (status, _, _) = call(test_app(Some(TOKEN)), post_search(VALID, Some(&wrong))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = call(
            test_app(Some(TOKEN)),
            Request::get("/api/v1/schema/classes")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Health needs none.
        let (status, body, _) = call(
            test_app(Some(TOKEN)),
            Request::get("/api/v1/health").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn a_search_the_schema_refuses_is_a_bad_request_with_the_reason() {
        let body = r#"{"from":"2026-09-25T00:00:00Z","to":"2026-09-26T00:00:00Z","classes":[1007],
            "filters":[{"path":"process.cmdline","op":"contains","value":"x"}]}"#;
        let (status, body, _) = call(test_app(Some(TOKEN)), post_search(body, Some(TOKEN))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"],
            "`process.cmdline`: object `process` has no attribute `cmdline`"
        );
        let (status, body, _) = call(test_app(None), post_search("{not json", None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("JSON"), "{body}");
        let (status, _, _) = call(
            test_app(None),
            post_search(&format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_BODY)), None),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, body, _) = call(
            test_app(None),
            Request::get("/api/v1/events/page-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"],
            "`page-2` is not a cursor from a previous page"
        );
    }

    #[tokio::test]
    async fn a_store_that_cannot_answer_is_reported_without_detail() {
        let (status, body, _) = call(test_app(None), post_search(VALID, None)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            body["error"],
            "the event store could not answer; the server log has the details"
        );
    }

    #[tokio::test]
    async fn the_schema_lists_what_a_search_can_name() {
        let (status, body, _) = call(
            test_app(None),
            Request::get("/api/v1/schema/classes")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body["classes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|class| class["uid"] == 1007 && class["name"] == "process_activity")
        );

        let (status, body, _) = call(
            test_app(None),
            Request::get("/api/v1/schema/classes/1007/paths")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let paths = body["paths"].as_array().unwrap();
        let holds = |path: &str| {
            paths
                .iter()
                .find(|entry| entry["path"] == path)
                .map(|entry| entry["holds"].clone())
        };
        assert_eq!(holds("process.cmd_line"), Some(json!("text")));
        assert_eq!(holds("time"), Some(json!("time")));
        assert_eq!(holds("process"), Some(json!("object")));
        assert_eq!(holds("unmapped"), Some(json!("any")));
        assert_eq!(holds("observables"), None);
        assert!(paths.len() < 20_000, "{}", paths.len());
        let severity = paths
            .iter()
            .find(|entry| entry["path"] == "severity_id")
            .unwrap();
        assert!(severity["values"].as_array().unwrap().contains(&json!(99)));

        let (status, _, _) = call(
            test_app(None),
            Request::get("/api/v1/schema/classes/9999/paths")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn responses_carry_security_headers() {
        let (_, _, headers) = call(
            test_app(None),
            Request::get("/api/v1/health").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["cache-control"], "no-store");
        assert!(
            headers["content-security-policy"]
                .to_str()
                .unwrap()
                .starts_with("default-src 'self'")
        );
        let (status, _, _) = call(
            test_app(None),
            Request::get("/nothing").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
