//! Reconcile-loop metrics shared by every controller: the kit's
//! `ReconcileMetrics`, as `weebo_forgejo_reconcile_*` and
//! `weebo_forgejo_remote_writes_total`. Recording is a no-op until
//! `operator`'s telemetry installs a real `MeterProvider`, so controllers
//! record unconditionally.

use std::sync::OnceLock;
use std::time::Duration;

use application::use_cases::{Outcome, RemoteWrite};
use weebo_kit_runtime::metrics::ReconcileMetrics;

fn metrics() -> &'static ReconcileMetrics {
    static METRICS: OnceLock<ReconcileMetrics> = OnceLock::new();
    METRICS.get_or_init(|| ReconcileMetrics::new("weebo-forgejo-operator", "weebo_forgejo"))
}

/// Records one reconcile run, keyed by the `Ready` reason it ended on (the
/// label set stays bounded by `ReasonCode`), and the write it made to
/// Forgejo, if any.
pub fn record_reconcile(kind: &'static str, outcome: &Outcome, elapsed: Duration) {
    metrics().record(kind, outcome.reason(), elapsed);
    if let Some(write) = outcome.write {
        record_write(kind, write);
    }
}

/// One write to Forgejo (`weebo_forgejo_remote_writes_total{kind, cause}`):
/// flat at rest — a steady `cause="drift"` rate for a kind is a field
/// compared wrong, not a drift (weebo-si RFC 0003).
pub fn record_write(kind: &'static str, write: RemoteWrite) {
    metrics().record_write(kind, write);
}
