//! Test-only `GatewayFactory`: always returns the gateway it was built
//! with, whatever the `instanceRef` — no `ForgejoInstance` CR or token
//! Secret is needed by controller tests.

use std::sync::Arc;

use application::ports::{ForgejoGateway, GatewayFactory, GatewayFactoryError};

pub struct StaticGatewayFactory {
    gateway: Arc<dyn ForgejoGateway>,
}

impl StaticGatewayFactory {
    pub fn new(gateway: Arc<dyn ForgejoGateway>) -> Self {
        Self { gateway }
    }
}

#[async_trait::async_trait]
impl GatewayFactory for StaticGatewayFactory {
    async fn gateway_for(
        &self,
        _instance_ref: Option<&str>,
    ) -> Result<Arc<dyn ForgejoGateway>, GatewayFactoryError> {
        Ok(self.gateway.clone())
    }
}
