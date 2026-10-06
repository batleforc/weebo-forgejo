//! Validating admission webhook (`POST /validate`) for the namespaced
//! kinds, enforcing `ForgejoNamespacePolicy` on CREATE/UPDATE. Served on
//! every replica (not only the leader): with `failurePolicy: Fail`, a
//! webhook that only ran on the leader would turn a failover into a
//! cluster-wide outage for these kinds.

use std::sync::LazyLock;

use api::{
    ForgejoAccessToken, ForgejoDeployKey, ForgejoOAuth2Application, ForgejoRepository,
    ForgejoWebhook,
};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use domain::error::ReasonCode;
use kube::Client;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use serde::de::DeserializeOwned;

use crate::admission::{Governed, policies};

static DECISIONS: LazyLock<Counter<u64>> = LazyLock::new(|| {
    opentelemetry::global::meter("weebo-forgejo-operator")
        .u64_counter("weebo_forgejo_webhook_decisions_total")
        .with_description("Admission decisions, by kind and result")
        .build()
});

#[derive(Clone)]
pub struct WebhookState {
    pub client: Client,
}

pub fn router(state: WebhookState) -> Router {
    Router::new()
        .route("/validate", post(validate))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

async fn validate(
    State(state): State<WebhookState>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let Ok(req): Result<AdmissionRequest<DynamicObject>, _> = review.try_into() else {
        return Json(AdmissionResponse::invalid("AdmissionReview without a request").into_review());
    };
    let kind = req.kind.kind.clone();
    let decision = decide(&state.client, &req).await;
    DECISIONS.add(
        1,
        &[
            KeyValue::new("kind", kind),
            KeyValue::new("result", if decision.is_ok() { "allow" } else { "deny" }),
        ],
    );
    Json(match decision {
        Ok(()) => AdmissionResponse::from(&req).into_review(),
        Err(message) => {
            let mut response = AdmissionResponse::from(&req).deny(message);
            response.result.code = 403;
            response.result.reason = ReasonCode::NamespaceNotAllowed.as_str().to_string();
            response.into_review()
        }
    })
}

/// `Err` carries the denial message. Anything this webhook can't
/// understand fails closed.
async fn decide(client: &Client, req: &AdmissionRequest<DynamicObject>) -> Result<(), String> {
    let namespace = req.namespace.clone().unwrap_or_default();
    let Some(object) = req.object.as_ref() else {
        return Err("request carries no object".into());
    };
    let refs = match req.kind.kind.as_str() {
        "ForgejoRepository" => references::<ForgejoRepository>(object),
        "ForgejoWebhook" => references::<ForgejoWebhook>(object),
        "ForgejoDeployKey" => references::<ForgejoDeployKey>(object),
        "ForgejoOAuth2Application" => references::<ForgejoOAuth2Application>(object),
        "ForgejoAccessToken" => references::<ForgejoAccessToken>(object),
        other => return Err(format!("kind {other} is not handled by this webhook")),
    }?;
    let (kind, organizations, users) = refs;
    let policies = policies(client).await.map_err(|e| {
        tracing::error!(error = %e, "listing ForgejoNamespacePolicy failed");
        "ForgejoNamespacePolicy lookup failed".to_string()
    })?;
    let request = domain::allow_list::Request {
        namespace: &namespace,
        kind,
        organizations: &organizations,
        users: &users,
    };
    application::use_cases::admission::check(&request, &policies).map_err(|f| f.message)
}

type Refs = (domain::allow_list::Kind, Vec<String>, Vec<String>);

fn references<K: Governed + DeserializeOwned>(object: &DynamicObject) -> Result<Refs, String> {
    let value = serde_json::to_value(object).map_err(|e| e.to_string())?;
    let typed: K =
        serde_json::from_value(value).map_err(|e| format!("object does not match the CRD: {e}"))?;
    let (orgs, users) = typed.references();
    Ok((
        application::use_cases::admission::kind_of(K::KIND),
        orgs,
        users,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unreachable_client() -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Client::try_from(kube::Config::new("http://127.0.0.1:1".parse().unwrap())).unwrap()
    }

    fn review(kind: &str, object: serde_json::Value) -> AdmissionReview<DynamicObject> {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "11111111-1111-1111-1111-111111111111",
                "namespace": "team-a",
                "kind": {"group": "forgejo.weebo.io", "version": "v1alpha1", "kind": kind},
                "resource": {"group": "forgejo.weebo.io", "version": "v1alpha1", "resource": "x"},
                "operation": "CREATE",
                "userInfo": {},
                "object": object,
            }
        }))
        .unwrap()
    }

    async fn run(review: AdmissionReview<DynamicObject>) -> AdmissionResponse {
        let state = WebhookState {
            client: unreachable_client(),
        };
        validate(State(state), Json(review))
            .await
            .0
            .response
            .unwrap()
    }

    #[tokio::test]
    async fn unknown_kinds_fail_closed() {
        let response = run(review(
            "ForgejoTeam",
            serde_json::json!({"metadata": {"name": "x"}}),
        ))
        .await;
        assert!(!response.allowed);
        assert_eq!(response.result.reason, "NamespaceNotAllowed");
    }

    #[tokio::test]
    async fn malformed_objects_fail_closed() {
        let response = run(review(
            "ForgejoAccessToken",
            serde_json::json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
                "metadata": {"name": "x"}, "spec": {"scopes": "not-a-list"},
            }),
        ))
        .await;
        assert!(!response.allowed);
    }

    #[tokio::test]
    async fn an_unreachable_apiserver_fails_closed() {
        let response = run(review(
            "ForgejoAccessToken",
            serde_json::json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
                "metadata": {"name": "x"},
                "spec": {"userRef": {"name": "ci-bot"}, "scopes": ["read:user"]},
            }),
        ))
        .await;
        assert!(!response.allowed);
        assert!(response.result.message.contains("lookup failed"));
    }
}
