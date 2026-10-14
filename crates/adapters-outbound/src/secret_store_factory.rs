//! Builds the per-instance `RoutingSecretStore` (the kit's) from a
//! `ForgejoInstance`'s `secretStore`. Vault logins are cached per instance
//! by the kit's `VaultLogins`, and only attempted when a target actually
//! routes to Vault. A `ForgejoLocalInstance` writes Kubernetes `Secret`s
//! only: the operator's Vault identity is shared by every namespace.

use std::sync::Arc;

use api::instance::{SecretStoreBackend, VaultSecretStoreSpec};
use application::ports::{BoundInstance, SecretStore, SecretStoreError, SecretStoreFactory};
use futures::FutureExt;
use kube::{Client, ResourceExt};
use weebo_kit_adapters::{
    K8sSecretStore, Resolved, RoutingSecretStore, VaultConfig, VaultLogins, VaultSecretStore,
    read_secret_key,
};

use crate::instance_resolver::ForgejoInstances;

/// Server-side-apply manager of the `Secret`s this operator emits.
pub const FIELD_MANAGER: &str = "weebo-forgejo-operator";
/// `app.kubernetes.io/managed-by` of the `Secret`s this operator emits.
pub const MANAGED_BY: &str = "weebo-forgejo";

/// The Kubernetes secret store, labelled and annotated as this operator's.
pub fn kubernetes_secret_store(client: Client) -> K8sSecretStore {
    K8sSecretStore::new(
        client,
        FIELD_MANAGER,
        MANAGED_BY,
        api::SECRET_OWNER_ANNOTATION,
    )
}

pub struct ForgejoSecretStoreFactory {
    client: Client,
    instances: Arc<ForgejoInstances>,
    kubernetes: Arc<K8sSecretStore>,
    vault: Arc<VaultLogins>,
}

impl ForgejoSecretStoreFactory {
    pub fn new(client: Client, instances: Arc<ForgejoInstances>) -> Self {
        Self {
            instances,
            kubernetes: Arc::new(kubernetes_secret_store(client.clone())),
            client,
            vault: Arc::new(VaultLogins::default()),
        }
    }
}

/// Logs in to the Vault of `instance` (cached by `logins`). The CA bundle
/// is read first: its digest is part of the cache key, so a rotated CA is
/// picked up at once rather than when the login expires.
async fn vault_for(
    client: Client,
    logins: Arc<VaultLogins>,
    instance: String,
    spec: VaultSecretStoreSpec,
) -> Result<Arc<VaultSecretStore>, String> {
    let ca = match &spec.ca_secret_ref {
        Some(r) => Some(read_secret_key(&client, r).await?.ok_or_else(|| {
            format!(
                "Vault caSecretRef {}/{} has no key {:?}",
                r.namespace, r.name, r.key
            )
        })?),
        None => None,
    };
    let config = VaultConfig {
        address: spec.address.clone(),
        mount: spec.mount.clone(),
        path_prefix: spec.path_prefix.clone(),
        path_grants: spec.path_grants.clone(),
        kubernetes_auth_role: spec.kubernetes_auth_role.clone(),
        kubernetes_auth_mount: spec.kubernetes_auth_mount.clone(),
        ca_source: spec
            .ca_secret_ref
            .as_ref()
            .zip(ca.as_ref())
            .map(|(r, pem)| VaultConfig::ca_source_of(r, pem)),
    };
    logins
        .get(&instance, &config, || async move { Ok(ca) })
        .await
}

#[async_trait::async_trait]
impl SecretStoreFactory for ForgejoSecretStoreFactory {
    async fn store_for(
        &self,
        bound: &BoundInstance,
    ) -> Result<Arc<dyn SecretStore>, SecretStoreError> {
        let instance = match self
            .instances
            .get(bound)
            .await
            .map_err(SecretStoreError)?
            .ok_or_else(|| SecretStoreError(format!("{bound} not found")))?
        {
            Resolved::Cluster(instance) => instance,
            Resolved::Local(_) => {
                return Ok(Arc::new(RoutingSecretStore::new(
                    self.kubernetes.clone(),
                    Err(format!(
                        "{bound} writes Kubernetes Secrets only: Vault targets need a ForgejoInstance"
                    )),
                    SecretStoreBackend::Kubernetes,
                )));
            }
        };
        let store_spec = &instance.spec.secret_store;
        // A broken Vault must not block Kubernetes targets: it is only
        // logged in to — and its error surfaced — when a target routes to
        // it.
        let Some(vault) = store_spec.vault.clone() else {
            return Ok(Arc::new(RoutingSecretStore::new(
                self.kubernetes.clone(),
                Err(format!(
                    "ForgejoInstance {:?} has no secretStore.vault configured",
                    instance.name_any()
                )),
                store_spec.backend,
            )));
        };
        let (client, logins, name) = (self.client.clone(), self.vault.clone(), instance.name_any());
        Ok(Arc::new(RoutingSecretStore::lazy(
            self.kubernetes.clone(),
            Box::new(move || vault_for(client, logins, name, vault).boxed()),
            store_spec.backend,
        )))
    }
}
