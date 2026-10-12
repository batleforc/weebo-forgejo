//! The operator's instances, both kinds — `ForgejoInstance`
//! (cluster-scoped) and `ForgejoLocalInstance` (namespaced) — through the
//! kit's `Instances`: read from the binary's reflector `Store`s, or from the
//! API on every call (tests), on the operator's watch scope. It is also the
//! `InstanceDirectory` resolving a CR's `instanceRef`.

use api::{ForgejoInstance, ForgejoLocalInstance};

pub type ForgejoInstances = weebo_kit_adapters::Instances<ForgejoInstance, ForgejoLocalInstance>;
