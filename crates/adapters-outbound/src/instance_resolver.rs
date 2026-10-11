//! Resolves `ForgejoInstance` CRs for the gateway and secret-store
//! factories: the kit's resolver, served from a live reflector `Store`
//! when `operator::main` wires one in, from the API otherwise (tests).

use api::ForgejoInstance;

pub(crate) type InstanceResolver = weebo_kit_adapters::InstanceResolver<ForgejoInstance>;
