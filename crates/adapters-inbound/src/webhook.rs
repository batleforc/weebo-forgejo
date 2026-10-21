//! Validating admission webhook (`POST /validate`) for every governed
//! kind, enforcing `ForgejoNamespacePolicy` on CREATE/UPDATE. Served on
//! every replica (not only the leader): with `failurePolicy: Fail`, a
//! webhook that only ran on the leader would turn a failover into a
//! cluster-wide outage for these kinds. A CR bound to a
//! `ForgejoLocalInstance` isn't governed by the policies (its namespace's
//! own token bounds it). The explicit Vault paths of a CR's `secretTargets`
//! are checked against its instance's `pathPrefix` and `pathGrants`, like
//! the secret stores do. Plus `/scope`, the kit's `ScopeGuard`.

use std::sync::Arc;

use api::namespace_policy::NamespaceRule;
use api::{
    ForgejoAccessToken, ForgejoDeployKey, ForgejoOAuth2Application, ForgejoOrganization,
    ForgejoRepository, ForgejoTeam, ForgejoUser, ForgejoUserKey, ForgejoWebhook,
};
use application::ports::{
    InstanceDirectory, InstanceError, InstanceVault, InstanceVaults, PolicySource, ReferenceReader,
};
use application::use_cases::admission::{Governed, enforce_on};
use axum::Router;
use domain::error::ReasonCode;
use kube::core::DynamicObject;
use serde::de::DeserializeOwned;
use weebo_kit_api::SecretTarget;
use weebo_kit_runtime::admission::{
    Admission, Denial, ScopeGuard, VaultPaths, check_vault_targets, scope_router, typed,
};
use weebo_kit_runtime::{Health, WatchScope};

use crate::controller::HasInstanceRef;

#[derive(Clone)]
pub struct WebhookState {
    pub policies: Arc<dyn PolicySource<NamespaceRule>>,
    /// The referenced `ForgejoUser`s (site-admin credentials rule).
    pub refs: Arc<dyn ReferenceReader>,
    /// Resolves the reviewed CR's instance; `None`: every CR is governed
    /// by the policies.
    pub instances: Option<Arc<dyn InstanceDirectory>>,
    /// The resolved instance's Vault connection; `None`: Vault paths are
    /// only checked by the reconcilers.
    pub vaults: Option<Arc<dyn InstanceVaults>>,
}

/// `POST /validate` (the kit's: a `DELETE` or an `UPDATE` leaving `spec`
/// alone always passes — the reconcilers still re-check the policy before
/// any Forgejo call), plus the probes: `/readyz` (and its alias
/// `/healthz`) and `/livez`, and `POST /scope` (no CR leaves `scope`'s
/// label selector by accident). Decisions are counted as
/// `weebo_forgejo_webhook_decisions_total`.
pub fn router(state: WebhookState, health: Arc<Health>, scope: WatchScope) -> Router {
    let guard = ScopeGuard {
        scope,
        finalizer: api::FINALIZER,
        annotations: api::ANNOTATIONS,
        reason: ReasonCode::LeavesWatchScope,
    };
    weebo_kit_runtime::admission::router(
        Arc::new(state),
        health,
        "weebo-forgejo-operator",
        "weebo_forgejo",
    )
    .merge(scope_router(Arc::new(guard)))
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
        match kind {
            "ForgejoUser" => self.check::<ForgejoUser>(namespace, object).await,
            "ForgejoUserKey" => self.check::<ForgejoUserKey>(namespace, object).await,
            "ForgejoOrganization" => self.check::<ForgejoOrganization>(namespace, object).await,
            "ForgejoTeam" => self.check::<ForgejoTeam>(namespace, object).await,
            "ForgejoRepository" => self.check::<ForgejoRepository>(namespace, object).await,
            "ForgejoWebhook" => self.check::<ForgejoWebhook>(namespace, object).await,
            "ForgejoDeployKey" => self.check::<ForgejoDeployKey>(namespace, object).await,
            "ForgejoOAuth2Application" => {
                self.check::<ForgejoOAuth2Application>(namespace, object)
                    .await
            }
            "ForgejoAccessToken" => self.check::<ForgejoAccessToken>(namespace, object).await,
            other => Err(Denial::new(
                ReasonCode::NamespaceNotAllowed,
                format!("kind {other} is not handled by this webhook"),
            )),
        }
    }

    fn undecidable(&self) -> ReasonCode {
        ReasonCode::NamespaceNotAllowed
    }
}

impl WebhookState {
    /// The reconcilers' own admission checks (`enforce_on`), on the typed
    /// object, bound to its instance — one that can't be resolved counts
    /// as governed: the policies decide.
    async fn check<K: Governed + HasInstanceRef + DeserializeOwned>(
        &self,
        namespace: &str,
        object: &DynamicObject,
    ) -> Result<(), Denial<ReasonCode>> {
        let not_allowed = |message: String| Denial::new(ReasonCode::NamespaceNotAllowed, message);
        let typed: K = typed(object).map_err(|e| not_allowed(e.to_string()))?;
        let instance = match &self.instances {
            Some(directory) => {
                let recorded = typed.forgejo_status().and_then(|s| s.instance.as_ref());
                match directory
                    .resolve(Some(namespace), typed.instance_ref(), recorded)
                    .await
                {
                    Ok(instance) => Some(instance),
                    // No such instance: the reconcile reports it.
                    Err(InstanceError::Resolve(_)) => None,
                    // Fail open: the Vault path rule is enforced again by
                    // the secret store on every write of the reconcile.
                    Err(e @ InstanceError::Kubernetes(_)) => {
                        tracing::warn!(
                            error = %e,
                            "instance unresolved, admitted without the Vault path check"
                        );
                        None
                    }
                }
            }
            None => None,
        };
        let (policies, refs) = (self.policies.as_ref(), self.refs.as_ref());
        match enforce_on(policies, refs, namespace, &typed, instance.as_ref()).await {
            Ok(decision) => decision.map_err(|f| not_allowed(f.message))?,
            Err(e) => {
                tracing::error!(error = %e, "admission lookup failed");
                return Err(not_allowed(
                    "ForgejoNamespacePolicy lookup failed".to_string(),
                ));
            }
        }
        match (&self.vaults, instance) {
            (Some(vaults), Some(instance)) => {
                check_vault_paths(
                    vaults.as_ref(),
                    &instance,
                    namespace,
                    typed.secret_targets(),
                )
                .await
            }
            // Not resolved: the reconcile reports why (InstanceNotFound…).
            _ => Ok(()),
        }
    }
}

/// The stores' Vault path rule, on `targets` of a CR in `namespace` bound
/// to `instance`: refused with the store's message. An instance gone since
/// the resolution, or unreadable, is left to the reconcile.
async fn check_vault_paths(
    vaults: &dyn InstanceVaults,
    instance: &application::ports::BoundInstance,
    namespace: &str,
    targets: &[SecretTarget],
) -> Result<(), Denial<ReasonCode>> {
    if !targets
        .iter()
        .any(|t| t.backend == api::instance::SecretStoreBackend::Vault)
    {
        return Ok(());
    }
    let vault = match vaults.vault_of(instance).await {
        Ok(InstanceVault::Vault(vault)) => vault,
        Ok(InstanceVault::None) => {
            return check_vault_targets(targets, Some(namespace), None)
                .map_err(|m| Denial::new(ReasonCode::SecretTargetFailed, m));
        }
        Ok(InstanceVault::NotFound) => return Ok(()),
        Err(e) => {
            tracing::warn!(error = %e, "reading the instance's Vault settings failed");
            return Ok(());
        }
    };
    let paths = VaultPaths {
        path_prefix: &vault.path_prefix,
        path_grants: &vault.path_grants,
    };
    check_vault_targets(targets, Some(namespace), Some(paths))
        .map_err(|m| Denial::new(ReasonCode::SecretTargetFailed, m))
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
            instances: None,
            vaults: None,
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
            "ForgejoInstance",
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

    struct Vaults(InstanceVault);

    #[async_trait::async_trait]
    impl InstanceVaults for Vaults {
        async fn vault_of(
            &self,
            _: &application::ports::BoundInstance,
        ) -> Result<InstanceVault, String> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn vault_targets_need_the_instances_vault() {
        let bound = application::ports::BoundInstance::cluster("main");
        let vault: SecretTarget = serde_json::from_value(
            serde_json::json!({"backend": "vault", "name": "app", "path": "argocd/auth"}),
        )
        .unwrap();
        let kubernetes: SecretTarget =
            serde_json::from_value(serde_json::json!({"name": "app"})).unwrap();
        let bound = &bound;
        let check = |v: InstanceVault, t: SecretTarget| async move {
            check_vault_paths(&Vaults(v), bound, "ci", &[t]).await
        };
        let denial = check(InstanceVault::None, vault.clone()).await.unwrap_err();
        assert_eq!(denial.reason, ReasonCode::SecretTargetFailed);
        assert!(
            denial.message.contains("no Vault connection"),
            "{}",
            denial.message
        );
        assert!(check(InstanceVault::None, kubernetes).await.is_ok());
        assert!(check(InstanceVault::NotFound, vault.clone()).await.is_ok());
        let spec: api::instance::VaultSecretStoreSpec = serde_json::from_value(serde_json::json!({
            "address": "https://vault:8200", "mount": "secret", "kubernetesAuthRole": "forgejo",
        }))
        .unwrap();
        let denial = check(InstanceVault::Vault(Box::new(spec)), vault)
            .await
            .unwrap_err();
        assert!(
            denial.message.contains("no pathGrants entry"),
            "{}",
            denial.message
        );
    }
}
