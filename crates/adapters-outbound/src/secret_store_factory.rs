//! Builds the per-instance `RoutingSecretStore`. The Vault login is cached
//! per instance for 80% of its lease (each login mints a Vault token that
//! lives its whole TTL — logging in on every reconcile churned tokens), and
//! rebuilt when the instance's Vault settings change.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use api::ForgejoInstance;
use api::instance::VaultSecretStoreSpec;
use application::ports::{SecretStore, SecretStoreError, SecretStoreFactory};
use kube::runtime::reflector::Store;
use kube::{Client, ResourceExt};
use tokio::sync::Mutex;

use crate::instance_resolver::InstanceResolver;
use crate::secret_k8s::K8sSecretStore;
use crate::secret_ref::read_secret_key;
use crate::secret_routing::RoutingSecretStore;
use crate::secret_vault::VaultSecretStore;

/// The operator's projected ServiceAccount token, exchanged for a Vault
/// token. Overridable for tests and unusual mounts.
const DEFAULT_JWT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

struct CachedVault {
    spec: VaultSecretStoreSpec,
    store: Arc<VaultSecretStore>,
    expires: Instant,
}

pub struct ForgejoSecretStoreFactory {
    client: Client,
    instances: InstanceResolver,
    kubernetes: Arc<K8sSecretStore>,
    vault: Mutex<HashMap<String, CachedVault>>,
}

impl ForgejoSecretStoreFactory {
    pub fn new(client: Client, store: Option<Store<ForgejoInstance>>) -> Self {
        Self {
            instances: InstanceResolver::new(client.clone(), store),
            kubernetes: Arc::new(K8sSecretStore::new(client.clone())),
            client,
            vault: Mutex::new(HashMap::new()),
        }
    }

    async fn vault_for(
        &self,
        instance: &ForgejoInstance,
        spec: &VaultSecretStoreSpec,
    ) -> Result<Arc<VaultSecretStore>, String> {
        let key = instance.name_any();
        let mut cache = self.vault.lock().await;
        if let Some(cached) = cache.get(&key)
            && cached.spec == *spec
            && cached.expires > Instant::now()
        {
            return Ok(cached.store.clone());
        }

        let jwt_path =
            std::env::var("VAULT_KUBERNETES_JWT_PATH").unwrap_or_else(|_| DEFAULT_JWT_PATH.into());
        let jwt = std::fs::read_to_string(&jwt_path)
            .map_err(|e| format!("reading the ServiceAccount token {jwt_path}: {e}"))?;
        let ca = match &spec.ca_secret_ref {
            Some(r) => Some(read_secret_key(&self.client, r).await?.ok_or_else(|| {
                format!(
                    "Vault caSecretRef {}/{} has no key {:?}",
                    r.namespace, r.name, r.key
                )
            })?),
            None => None,
        };
        let store = Arc::new(
            VaultSecretStore::new(spec, &jwt, ca.as_deref())
                .await
                .map_err(|e| e.0)?,
        );
        match store.cache_ttl() {
            Some(ttl) => {
                cache.insert(
                    key,
                    CachedVault {
                        spec: spec.clone(),
                        store: store.clone(),
                        expires: Instant::now() + ttl,
                    },
                );
            }
            None => {
                cache.remove(&key);
            }
        }
        Ok(store)
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
        Ok(Arc::new(RoutingSecretStore {
            kubernetes: self.kubernetes.clone(),
            vault,
            default_backend: store_spec.backend,
        }))
    }
}
