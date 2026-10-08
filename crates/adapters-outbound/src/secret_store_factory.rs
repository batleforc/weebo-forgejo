//! Builds the per-instance `RoutingSecretStore` (the kit's) from a
//! `ForgejoInstance`'s `secretStore`. Vault logins are cached per instance
//! by the kit's `VaultLogins`.

use std::sync::Arc;

use api::ForgejoInstance;
use api::instance::VaultSecretStoreSpec;
use application::ports::{SecretStore, SecretStoreError, SecretStoreFactory};
use kube::runtime::reflector::Store;
use kube::{Client, ResourceExt};
use weebo_kit_adapters::{
    K8sSecretStore, RoutingSecretStore, VaultConfig, VaultLogins, VaultSecretStore, read_secret_key,
};

use crate::instance_resolver::InstanceResolver;

/// Server-side-apply manager of the `Secret`s this operator emits.
pub const FIELD_MANAGER: &str = "weebo-forgejo-operator";
/// `app.kubernetes.io/managed-by` of the `Secret`s this operator emits.
pub const MANAGED_BY: &str = "weebo-forgejo";

/// The Kubernetes secret store, labelled as this operator's.
pub fn kubernetes_secret_store(client: Client) -> K8sSecretStore {
    K8sSecretStore::new(client, FIELD_MANAGER, MANAGED_BY)
}

pub struct ForgejoSecretStoreFactory {
    client: Client,
    instances: InstanceResolver,
    kubernetes: Arc<K8sSecretStore>,
    vault: VaultLogins,
}

impl ForgejoSecretStoreFactory {
    pub fn new(client: Client, store: Option<Store<ForgejoInstance>>) -> Self {
        Self {
            instances: InstanceResolver::new(client.clone(), store),
            kubernetes: Arc::new(kubernetes_secret_store(client.clone())),
            client,
            vault: VaultLogins::default(),
        }
    }

    async fn vault_for(
        &self,
        instance: &ForgejoInstance,
        spec: &VaultSecretStoreSpec,
    ) -> Result<Arc<VaultSecretStore>, String> {
        let config = VaultConfig {
            address: spec.address.clone(),
            mount: spec.mount.clone(),
            path_prefix: spec.path_prefix.clone(),
            kubernetes_auth_role: spec.kubernetes_auth_role.clone(),
            kubernetes_auth_mount: spec.kubernetes_auth_mount.clone(),
            ca_source: spec
                .ca_secret_ref
                .as_ref()
                .map(|r| format!("{}/{}/{}", r.namespace, r.name, r.key)),
        };
        self.vault
            .get(&instance.name_any(), &config, || async {
                match &spec.ca_secret_ref {
                    Some(r) => read_secret_key(&self.client, r)
                        .await?
                        .map(Some)
                        .ok_or_else(|| {
                            format!(
                                "Vault caSecretRef {}/{} has no key {:?}",
                                r.namespace, r.name, r.key
                            )
                        }),
                    None => Ok(None),
                }
            })
            .await
    }
}

#[async_trait::async_trait]
impl SecretStoreFactory for ForgejoSecretStoreFactory {
    async fn store_for(
        &self,
        instance_ref: Option<&str>,
    ) -> Result<Arc<dyn SecretStore>, SecretStoreError> {
        let instances = self.instances.list().await.map_err(SecretStoreError)?;
        let instance = crate::gateway_factory::select(&instances, instance_ref)
            .map_err(|e| SecretStoreError(e.to_string()))?;
        let store_spec = &instance.spec.secret_store;
        // A broken Vault must not block Kubernetes targets: the error is
        // only surfaced to a write that actually routes to Vault.
        let vault = match &store_spec.vault {
            Some(spec) => self.vault_for(instance, spec).await,
            None => Err(format!(
                "ForgejoInstance {:?} has no secretStore.vault configured",
                instance.name_any()
            )),
        };
        Ok(Arc::new(RoutingSecretStore::new(
            self.kubernetes.clone(),
            vault,
            store_spec.backend,
        )))
    }
}
