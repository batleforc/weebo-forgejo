//! Resolves `ForgejoInstance` CRs for the gateway factory. Served from a
//! live reflector `Store` when `operator::main` wires one in (no
//! per-reconcile apiserver GET/LIST), from the API otherwise (tests).

use api::ForgejoInstance;
use kube::Client;
use kube::api::Api;
use kube::runtime::reflector::Store;

pub(crate) struct InstanceResolver {
    client: Client,
    store: Option<Store<ForgejoInstance>>,
}

impl InstanceResolver {
    pub(crate) fn new(client: Client, store: Option<Store<ForgejoInstance>>) -> Self {
        Self { client, store }
    }

    /// Every instance in the cluster.
    pub(crate) async fn list(&self) -> Result<Vec<ForgejoInstance>, String> {
        // A dropped writer (shutdown) makes `wait_until_ready` fail: fall
        // through to a live lookup rather than answering from a dead cache.
        if let Some(store) = &self.store
            && store.wait_until_ready().await.is_ok()
        {
            return Ok(store.state().iter().map(|i| (**i).clone()).collect());
        }
        let api: Api<ForgejoInstance> = Api::all(self.client.clone());
        Ok(api
            .list(&Default::default())
            .await
            .map_err(|e| format!("listing ForgejoInstance: {e}"))?
            .items)
    }
}
