//! The `SecretStore` of one `ForgejoInstance`: every target goes to its
//! own backend — the Kubernetes API, or the instance's Vault connection.

use std::collections::BTreeMap;
use std::sync::Arc;

use api::common::SecretTarget;
use api::instance::SecretStoreBackend;
use application::ports::{SecretStore, SecretStoreError};

use crate::secret_k8s::K8sSecretStore;
use crate::secret_vault::VaultSecretStore;

pub struct RoutingSecretStore {
    pub(crate) kubernetes: Arc<K8sSecretStore>,
    /// `Err` holds why Vault is unavailable (not configured, login failed),
    /// reported only when a target actually needs it.
    pub(crate) vault: Result<Arc<VaultSecretStore>, String>,
    pub(crate) default_backend: SecretStoreBackend,
}

impl RoutingSecretStore {
    fn vault(&self) -> Result<&VaultSecretStore, SecretStoreError> {
        self.vault
            .as_deref()
            .map_err(|why| SecretStoreError(why.clone()))
    }

    fn vault_path(
        vault: &VaultSecretStore,
        target: &SecretTarget,
        default_namespace: Option<&str>,
    ) -> Result<String, SecretStoreError> {
        if let Some(path) = &target.path {
            return Ok(path.clone());
        }
        let ns = target
            .namespace
            .as_deref()
            .or(default_namespace)
            .ok_or_else(|| {
                SecretStoreError(format!(
                    "Vault target {:?} needs a path or a namespace",
                    target.name
                ))
            })?;
        Ok(vault.default_path(ns, &target.name))
    }
}

#[async_trait::async_trait]
impl SecretStore for RoutingSecretStore {
    fn default_backend(&self) -> SecretStoreBackend {
        self.default_backend
    }

    async fn write(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
        data: &BTreeMap<String, String>,
    ) -> Result<(), SecretStoreError> {
        match target.backend {
            SecretStoreBackend::Kubernetes => {
                self.kubernetes.write(target, default_namespace, data).await
            }
            SecretStoreBackend::Vault => {
                let vault = self.vault()?;
                let path = Self::vault_path(vault, target, default_namespace)?;
                vault.write_path(&path, data).await
            }
        }
    }

    async fn exists(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
    ) -> Result<bool, SecretStoreError> {
        match target.backend {
            SecretStoreBackend::Kubernetes => {
                self.kubernetes.exists(target, default_namespace).await
            }
            SecretStoreBackend::Vault => {
                let vault = self.vault()?;
                let path = Self::vault_path(vault, target, default_namespace)?;
                Ok(vault.read_path(&path).await?.is_some())
            }
        }
    }

    async fn delete(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
    ) -> Result<(), SecretStoreError> {
        match target.backend {
            SecretStoreBackend::Kubernetes => {
                self.kubernetes.delete(target, default_namespace).await
            }
            SecretStoreBackend::Vault => {
                let vault = self.vault()?;
                let path = Self::vault_path(vault, target, default_namespace)?;
                vault.delete_path(&path).await
            }
        }
    }
}
