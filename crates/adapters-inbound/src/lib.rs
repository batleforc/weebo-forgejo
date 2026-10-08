//! Inbound adapters: one kube-runtime controller per CRD, the admission
//! webhook, and the shared reconcile metrics.

pub mod controller;
pub mod metrics;
pub mod webhook;
