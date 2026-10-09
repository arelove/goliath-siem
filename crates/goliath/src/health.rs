//! What a process says of itself to whatever started it: the three probes
//! of `docs/adr/0023-platform-health.md`, served beside the metrics.
//!
//! - `/health/live`: the process answers. Nothing outside it can make this
//!   say no: a restart mends neither the store nor the pipe, and loses what
//!   the process holds.
//! - `/health/startup`: it finished starting, and what startup waits for,
//!   such as the feeds looked at once, is done.
//! - `/health/ready`: it started and is not shutting down.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

/// What the process knows of its own state, shared by its roles.
#[derive(Clone, Default)]
pub(crate) struct Health(Arc<Inner>);

#[derive(Default)]
struct Inner {
    /// Whether every role was started.
    started: AtomicBool,
    /// Whether the process is shutting down.
    stopping: AtomicBool,
    /// What startup still waits for.
    holds: Mutex<BTreeSet<&'static str>>,
}

/// Something startup waits for, until this is dropped.
pub(crate) struct Hold {
    health: Health,
    what: &'static str,
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.health.holds().remove(self.what);
    }
}

impl Health {
    fn holds(&self) -> std::sync::MutexGuard<'_, BTreeSet<&'static str>> {
        self.0.holds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes startup wait for `what`, until what is returned is dropped.
    pub(crate) fn hold(&self, what: &'static str) -> Hold {
        self.holds().insert(what);
        Hold {
            health: self.clone(),
            what,
        }
    }

    /// Every role was started.
    pub(crate) fn started(&self) {
        self.0.started.store(true, Ordering::Relaxed);
    }

    /// The process is shutting down, and takes no new work.
    pub(crate) fn stopping(&self) {
        self.0.stopping.store(true, Ordering::Relaxed);
    }

    /// What startup still waits for; empty once it finished.
    fn waiting(&self) -> Vec<&'static str> {
        let mut waiting = Vec::new();
        if !self.0.started.load(Ordering::Relaxed) {
            waiting.push("roles");
        }
        waiting.extend(self.holds().iter().copied());
        waiting
    }

    fn startup(&self) -> Response {
        answer(&self.waiting(), "starting")
    }

    fn ready(&self) -> Response {
        if self.0.stopping.load(Ordering::Relaxed) {
            return answer(&["shutdown"], "stopping");
        }
        self.startup()
    }

    /// The probes, to be served beside the metrics.
    pub(crate) fn probes(&self) -> Router {
        let (startup, ready) = (self.clone(), self.clone());
        Router::new()
            .route("/health/live", get(|| async { answer(&[], "") }))
            .route(
                "/health/startup",
                get(move || async move { startup.startup() }),
            )
            .route("/health/ready", get(move || async move { ready.ready() }))
    }
}

/// Yes with nothing waited for; otherwise no, with `status` and what for.
fn answer(waiting: &[&str], status: &str) -> Response {
    if waiting.is_empty() {
        (StatusCode::OK, axum::Json(json!({ "status": "ok" }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "status": status, "waiting_for": waiting })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    async fn ask(health: &Health, path: &str) -> (StatusCode, serde_json::Value) {
        let response = health
            .probes()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn startup_waits_for_the_roles_and_for_what_holds_it() {
        let health = Health::default();
        let feeds = health.hold("feeds");
        let (status, body) = ask(&health, "/health/startup").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            json!({ "status": "starting", "waiting_for": ["roles", "feeds"] })
        );

        health.started();
        let (status, body) = ask(&health, "/health/ready").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["waiting_for"], json!(["feeds"]));

        drop(feeds);
        for path in ["/health/startup", "/health/ready"] {
            let (status, body) = ask(&health, path).await;
            assert_eq!((status, body), (StatusCode::OK, json!({ "status": "ok" })));
        }
    }

    #[tokio::test]
    async fn a_process_that_shuts_down_is_not_ready_and_is_still_live() {
        let health = Health::default();
        health.started();
        health.stopping();
        let (status, body) = ask(&health, "/health/ready").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            json!({ "status": "stopping", "waiting_for": ["shutdown"] })
        );
        assert_eq!(ask(&health, "/health/startup").await.0, StatusCode::OK);
        assert_eq!(ask(&health, "/health/live").await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn live_says_yes_before_anything_started() {
        let health = Health::default();
        let _feeds = health.hold("feeds");
        let (status, body) = ask(&health, "/health/live").await;
        assert_eq!((status, body), (StatusCode::OK, json!({ "status": "ok" })));
    }
}
