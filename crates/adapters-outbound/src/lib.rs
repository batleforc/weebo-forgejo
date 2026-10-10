//! Outbound adapters: [`ForgejoHttpGateway`] (wraps the generated
//! `forgejo-client`), the [`ForgejoGatewayFactory`] resolving it per
//! `ForgejoInstance`, the per-instance [`ForgejoSecretStoreFactory`]
//! (over the kit's Kubernetes and Vault stores, `weebo_kit_adapters`), and
//! the [`KubeClusterReader`] behind the reference and policy lookups.

pub mod cluster_reader;
pub mod forgejo_http;
pub mod gateway_factory;
mod instance_resolver;
pub mod metered;
pub mod secret_store_factory;

pub use cluster_reader::KubeClusterReader;
pub use forgejo_http::ForgejoHttpGateway;
pub use gateway_factory::ForgejoGatewayFactory;
pub use metered::MeteredGateway;
pub use secret_store_factory::ForgejoSecretStoreFactory;
pub use secret_store_factory::kubernetes_secret_store;
pub use weebo_kit_adapters::K8sSecretStore;
