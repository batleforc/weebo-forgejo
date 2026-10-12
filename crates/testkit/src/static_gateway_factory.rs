//! Test-only `GatewayFactory` and `InstanceDirectory`: always returns the
//! gateway it was built with, whatever the instance — no `ForgejoInstance`
//! CR or token Secret is needed by controller tests.

use std::sync::Arc;

use api::common::{InstanceKind, InstanceRef};
use application::ports::{
    BoundInstance, ForgejoGateway, GatewayFactory, GatewayFactoryError, InstanceDirectory,
    InstanceError,
};

/// What a CR without `instanceRef` resolves to.
pub const DEFAULT_INSTANCE: &str = "default";

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
        _instance: &BoundInstance,
    ) -> Result<Arc<dyn ForgejoGateway>, GatewayFactoryError> {
        Ok(self.gateway.clone())
    }
}

/// Every `instanceRef` resolves: to a `ForgejoLocalInstance` when it says
/// so, to a `ForgejoInstance` of that name otherwise; no ref to the
/// [`DEFAULT_INSTANCE`].
#[async_trait::async_trait]
impl InstanceDirectory for StaticGatewayFactory {
    async fn resolve(
        &self,
        cr_namespace: Option<&str>,
        instance_ref: Option<&InstanceRef>,
        _recorded: Option<&BoundInstance>,
    ) -> Result<BoundInstance, InstanceError> {
        let Some(r) = instance_ref else {
            return Ok(BoundInstance::cluster(DEFAULT_INSTANCE));
        };
        Ok(match (r.kind, r.namespace.as_deref().or(cr_namespace)) {
            (Some(InstanceKind::LocalInstance), Some(ns)) => BoundInstance::local(ns, &r.name),
            _ => BoundInstance::cluster(&r.name),
        })
    }
}
