//! Test-only `SecretStoreFactory`: hands out one given store for every
//! instance.

use std::sync::Arc;

use application::ports::{SecretStore, SecretStoreError, SecretStoreFactory};

pub struct StaticSecretStoreFactory {
    store: Arc<dyn SecretStore>,
}

impl StaticSecretStoreFactory {
    pub fn new(store: Arc<dyn SecretStore>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl SecretStoreFactory for StaticSecretStoreFactory {
    async fn store_for(
        &self,
        _instance: &application::ports::BoundInstance,
    ) -> Result<Arc<dyn SecretStore>, SecretStoreError> {
        Ok(self.store.clone())
    }
}
