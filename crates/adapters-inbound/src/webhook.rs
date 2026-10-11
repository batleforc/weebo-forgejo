//! Validating admission webhook (`POST /validate`) for the namespaced
//! kinds, enforcing `ForgejoNamespacePolicy` on CREATE/UPDATE. Served on
//! every replica (not only the leader): with `failurePolicy: Fail`, a
//! webhook that only ran on the leader would turn a failover into a
//! cluster-wide outage for these kinds.

use std::sync::Arc;

use api::namespace_policy::NamespaceRule;
use api::{
    ForgejoAccessToken, ForgejoDeployKey, ForgejoOAuth2Application, ForgejoRepository,
    ForgejoWebhook,
};
use application::ports::{PolicySource, ReferenceReader};
use application::use_cases::admission::{Governed, enforce};
use axum::Router;
use domain::error::ReasonCode;
use kube::core::DynamicObject;
use serde::de::DeserializeOwned;
use weebo_kit_runtime::Health;
use weebo_kit_runtime::admission::{Admission, Denial, typed};

#[derive(Clone)]
pub struct WebhookState {
    pub policies: Arc<dyn PolicySource<NamespaceRule>>,
    /// The referenced `ForgejoUser`s (site-admin credentials rule).
    pub refs: Arc<dyn ReferenceReader>,
}

/// `POST /validate` (the kit's: a `DELETE` or an `UPDATE` leaving `spec`
/// alone always passes — the reconcilers still re-check the policy before
/// any Forgejo call), plus the probes: `/readyz` (and its alias
/// `/healthz`) and `/livez`. Decisions are counted as
/// `weebo_forgejo_webhook_decisions_total`.
pub fn router(state: WebhookState, health: Arc<Health>) -> Router {
    weebo_kit_runtime::admission::router(
        Arc::new(state),
        health,
        "weebo-forgejo-operator",
        "weebo_forgejo",
    )
}

#[async_trait::async_trait]
impl Admission for WebhookState {
    type Reason = ReasonCode;

    /// Anything this webhook can't understand fails closed.
    async fn admit(
        &self,
        kind: &str,
        namespace: &str,
        object: &DynamicObject,
    ) -> Result<(), Denial<ReasonCode>> {
        let (policies, refs) = (self.policies.as_ref(), self.refs.as_ref());
        let decision = match kind {
            "ForgejoRepository" => {
                check::<ForgejoRepository>(policies, refs, namespace, object).await
            }
            "ForgejoWebhook" => check::<ForgejoWebhook>(policies, refs, namespace, object).await,
            "ForgejoDeployKey" => {
                check::<ForgejoDeployKey>(policies, refs, namespace, object).await
            }
            "ForgejoOAuth2Application" => {
                check::<ForgejoOAuth2Application>(policies, refs, namespace, object).await
            }
            "ForgejoAccessToken" => {
                check::<ForgejoAccessToken>(policies, refs, namespace, object).await
            }
            other => Err(format!("kind {other} is not handled by this webhook")),
        };
        decision.map_err(|message| Denial::new(ReasonCode::NamespaceNotAllowed, message))
    }

    fn undecidable(&self) -> ReasonCode {
        ReasonCode::NamespaceNotAllowed
    }
}

/// The reconcilers' own admission checks (`enforce`), on the typed object.
async fn check<K: Governed + DeserializeOwned>(
    policies: &dyn PolicySource<NamespaceRule>,
    refs: &dyn ReferenceReader,
    namespace: &str,
    object: &DynamicObject,
) -> Result<(), String> {
    let typed: K = typed(object)?;
    match enforce(policies, refs, namespace, &typed).await {
        Ok(decision) => decision.map_err(|f| f.message),
        Err(e) => {
            tracing::error!(error = %e, "admission lookup failed");
            Err("ForgejoNamespacePolicy lookup failed".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use kube::core::admission::{AdmissionResponse, AdmissionReview};

    use super::*;

    /// No policy lookup can succeed, as with an unreachable apiserver.
    fn unreachable_cluster() -> Arc<application::test_support::FakeCluster> {
        let cluster = application::test_support::FakeCluster::default();
        cluster.fail_with("connection refused");
        Arc::new(cluster)
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
        let cluster = unreachable_cluster();
        let state = WebhookState {
            policies: cluster.clone(),
            refs: cluster,
        };
        weebo_kit_runtime::admission::handle(&state, review)
            .await
            .response
            .unwrap()
    }

    fn update(
        kind: &str,
        old: serde_json::Value,
        new: serde_json::Value,
    ) -> AdmissionReview<DynamicObject> {
        let mut review = serde_json::to_value(review(kind, new)).unwrap();
        review["request"]["operation"] = "UPDATE".into();
        review["request"]["oldObject"] = old;
        serde_json::from_value(review).unwrap()
    }

    fn token(user: &str, extra_meta: serde_json::Value) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
            "metadata": {"name": "x", "finalizers": ["forgejo.weebo.io/finalizer"]},
            "spec": {"userRef": {"name": user}, "scopes": ["read:user"]},
        });
        for (k, v) in extra_meta.as_object().unwrap() {
            obj["metadata"][k] = v.clone();
        }
        obj
    }

    /// The finalizer removal on a CR being deleted is an UPDATE: it must go
    /// through even when no policy lookup is possible (here, an unreachable
    /// apiserver — the same holds for a namespace that lost its policy).
    #[tokio::test]
    async fn updates_leaving_the_spec_alone_are_allowed() {
        let deleting = serde_json::json!({"deletionTimestamp": "2026-01-01T00:00:00Z"});
        let mut released = token("ci-bot", deleting.clone());
        released["metadata"]["finalizers"] = serde_json::json!([]);
        let response = run(update(
            "ForgejoAccessToken",
            token("ci-bot", deleting),
            released,
        ))
        .await;
        assert!(response.allowed, "{:?}", response.result);
    }

    #[tokio::test]
    async fn updates_changing_the_spec_are_still_checked() {
        let response = run(update(
            "ForgejoAccessToken",
            token("ci-bot", serde_json::json!({})),
            token("site-admin", serde_json::json!({})),
        ))
        .await;
        assert!(!response.allowed);
        assert!(response.result.message.contains("lookup failed"));
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
