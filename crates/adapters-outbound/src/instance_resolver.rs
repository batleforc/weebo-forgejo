//! The operator's instances, both kinds — `ForgejoInstance`
//! (cluster-scoped) and `ForgejoLocalInstance` (namespaced) — through the
//! kit's `Instances`: read from the binary's reflector `Store`s, or from the
//! API on every call (tests), on the operator's watch scope. It is also the
//! `InstanceDirectory` resolving a CR's `instanceRef`.

use api::{ForgejoInstance, ForgejoLocalInstance};
use application::ports::{BoundInstance, ClusterError, InstanceVault, InstanceVaults};
use weebo_kit_adapters::Resolved;

pub type ForgejoInstances = weebo_kit_adapters::Instances<ForgejoInstance, ForgejoLocalInstance>;

/// [`InstanceVaults`] over the instances: what the admission webhook checks
/// Vault targets against.
pub struct ForgejoInstanceVaults(pub std::sync::Arc<ForgejoInstances>);

#[async_trait::async_trait]
impl InstanceVaults for ForgejoInstanceVaults {
    async fn vault_of(&self, instance: &BoundInstance) -> Result<InstanceVault, ClusterError> {
        let resolved = self
            .0
            .get(instance)
            .await
            .map_err(|e| ClusterError(e.to_string()))?;
        Ok(match resolved {
            None => InstanceVault::NotFound,
            Some(Resolved::Local(_)) => InstanceVault::None,
            Some(Resolved::Cluster(cluster)) => match cluster.spec.secret_store.vault.clone() {
                Some(vault) => InstanceVault::Vault(Box::new(vault)),
                None => InstanceVault::None,
            },
        })
    }
}
