//! Reconcile-loop metrics shared by every controller. Recording through
//! `opentelemetry::global` is a no-op until `operator::telemetry` installs a
//! real `MeterProvider` (only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set), so
//! controllers record unconditionally.

use std::sync::OnceLock;
use std::time::Duration;

use domain::error::ReasonCode;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram};

struct Instruments {
    total: Counter<u64>,
    duration: Histogram<f64>,
}

fn instruments() -> &'static Instruments {
    static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();
    INSTRUMENTS.get_or_init(|| {
        let meter = opentelemetry::global::meter("weebo-forgejo-operator");
        Instruments {
            total: meter
                .u64_counter("weebo_forgejo_reconcile_total")
                .with_description("Reconcile runs, by kind, result and reason")
                .build(),
            duration: meter
                .f64_histogram("weebo_forgejo_reconcile_duration_seconds")
                .with_description("Reconcile run duration")
                .with_unit("s")
                .build(),
        }
    })
}

/// Records one reconcile run. `reason` is the `Ready` condition's reason
/// the run ended on, so the label set stays bounded by `ReasonCode`.
pub fn record_reconcile(kind: &'static str, reason: ReasonCode, elapsed: Duration) {
    let result = match reason.severity() {
        domain::error::Severity::Advisory => "success",
        domain::error::Severity::Blocking => "error",
    };
    let attrs = [
        KeyValue::new("kind", kind),
        KeyValue::new("result", result),
        KeyValue::new("reason", reason.as_str()),
    ];
    let i = instruments();
    i.total.add(1, &attrs);
    i.duration.record(elapsed.as_secs_f64(), &attrs[..1]);
}
