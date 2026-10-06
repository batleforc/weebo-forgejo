//! `SecretStore` writing Kubernetes `Secret`s. Server-side apply with a
//! dedicated field manager and **no ownerReference**: an emitted Secret
//! often lives in another namespace than its (possibly cluster-scoped) CR,
//! so it is deleted explicitly by the CR's finalizer instead of by GC.

use std::collections::BTreeMap;

use api::common::SecretTarget;
use application::ports::{SecretStore, SecretStoreError};
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::{Api, DeleteParams, Patch, PatchParams};

const FIELD_MANAGER: &str = "weebo-forgejo-operator";
/// Marks Secrets this operator emitted, for `kubectl get secret -l`.
const MANAGED_BY_LABEL: (&str, &str) = ("app.kubernetes.io/managed-by", "weebo-forgejo");

pub struct K8sSecretStore {
    client: Client,
}

impl K8sSecretStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    fn api(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
    ) -> Result<Api<Secret>, SecretStoreError> {
        let ns = target
            .namespace
            .as_deref()
            .or(default_namespace)
            .ok_or_else(|| {
                SecretStoreError(format!("secret target {:?} has no namespace", target.name))
            })?;
        Ok(Api::namespaced(self.client.clone(), ns))
    }
}

/// Used directly only by tests; operators go through the routing store,
/// which sends Kubernetes targets here.
#[async_trait::async_trait]
impl SecretStore for K8sSecretStore {
    fn default_backend(&self) -> api::instance::SecretStoreBackend {
        api::instance::SecretStoreBackend::Kubernetes
    }

    async fn write(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
        data: &BTreeMap<String, String>,
    ) -> Result<(), SecretStoreError> {
        let api = self.api(target, default_namespace)?;
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": target.name,
                "labels": { MANAGED_BY_LABEL.0: MANAGED_BY_LABEL.1 },
            },
            "type": "Opaque",
            "stringData": data,
        });
        api.patch(
            &target.name,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(&secret),
        )
        .await
        .map(|_| ())
        .map_err(|e| SecretStoreError(format!("writing secret {}: {e}", target.name)))
    }

    async fn exists(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
    ) -> Result<bool, SecretStoreError> {
        self.api(target, default_namespace)?
            .get_opt(&target.name)
            .await
            .map(|s| s.is_some())
            .map_err(|e| SecretStoreError(format!("reading secret {}: {e}", target.name)))
    }

    async fn delete(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
    ) -> Result<(), SecretStoreError> {
        match self
            .api(target, default_namespace)?
            .delete(&target.name, &DeleteParams::default())
            .await
        {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(SecretStoreError(format!(
                "deleting secret {}: {e}",
                target.name
            ))),
        }
    }
}
