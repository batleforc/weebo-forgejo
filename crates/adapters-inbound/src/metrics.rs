//! Reconcile-loop metrics shared by every controller: the kit's
//! `ReconcileMetrics`, as `weebo_forgejo_reconcile_*`. Recording is a no-op
//! until `operator`'s telemetry installs a real `MeterProvider`, so
//! controllers record unconditionally.

use std::sync::OnceLock;
use std::time::Duration;

use domain::error::ReasonCode;
use weebo_kit_runtime::metrics::ReconcileMetrics;

/// Records one reconcile run. `reason` is the `Ready` condition's reason
/// the run ended on, so the label set stays bounded by `ReasonCode`.
pub fn record_reconcile(kind: &'static str, reason: ReasonCode, elapsed: Duration) {
    static METRICS: OnceLock<ReconcileMetrics> = OnceLock::new();
    METRICS
        .get_or_init(|| ReconcileMetrics::new("weebo-forgejo-operator", "weebo_forgejo"))
        .record(kind, reason, elapsed);
}
