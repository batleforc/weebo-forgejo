//! Shared test harnesses: a real kube-apiserver + etcd (`envtest`),
//! polling helpers, and a `GatewayFactory` that always hands out one given
//! gateway (typically `application::test_support::FakeForgejo`).

pub mod envtest;
pub mod polling;
pub mod static_gateway_factory;
pub mod static_secret_store_factory;
