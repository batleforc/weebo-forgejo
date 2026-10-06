//! Outbound adapters: [`ForgejoHttpGateway`] (wraps the generated
//! `forgejo-client`), the [`ForgejoGatewayFactory`] resolving it per
//! `ForgejoInstance`, and the secret stores — Kubernetes, Vault, and the
//! per-instance [`ForgejoSecretStoreFactory`] routing each target.

pub mod forgejo_http;
pub mod gateway_factory;
mod instance_resolver;
pub mod secret_k8s;
mod secret_ref;
pub mod secret_routing;
pub mod secret_store_factory;
pub mod secret_vault;

pub use forgejo_http::ForgejoHttpGateway;
pub use gateway_factory::ForgejoGatewayFactory;
pub use secret_k8s::K8sSecretStore;
pub use secret_store_factory::ForgejoSecretStoreFactory;
