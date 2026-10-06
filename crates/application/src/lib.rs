//! Use-cases (`reconcile_*`) orchestrating `domain` and the port traits in
//! [`ports`]. No concrete adapter dependency — see `.prompt/plan.md`,
//! "Architecture hexagonale".

pub mod ports;
pub mod use_cases;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
