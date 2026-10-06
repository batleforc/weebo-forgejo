use crate::ports::ForgejoGateway;
use crate::use_cases::{Failure, Outcome};
use domain::error::ReasonCode;

/// Oldest Forgejo major this operator supports: v16 introduced the admin
/// access-token API (`.prompt/plan.md`, "Périmètre").
pub const MIN_MAJOR_VERSION: u64 = 16;

/// A `ForgejoInstance` has no Forgejo-side object: reconciling it is a
/// connectivity, token and version check, whose result every other CR's
/// readiness implicitly depends on.
pub async fn reconcile_instance(gateway: &dyn ForgejoGateway) -> Outcome {
    let version = match gateway.server_version().await {
        Ok(v) => v,
        Err(e) => return Outcome::failed(None, e),
    };
    match major(&version) {
        Some(m) if m >= MIN_MAJOR_VERSION => Outcome::synced(None, format!("Forgejo {version}")),
        _ => Outcome::failed(
            None,
            Failure::new(
                ReasonCode::UnsupportedForgejoVersion,
                format!("Forgejo {version} is older than v{MIN_MAJOR_VERSION}"),
            ),
        ),
    }
}

/// Forgejo reports versions like `16.0.5+gitea-1.22.0` or
/// `16.0.0-dev-505-abcdef`.
fn major(version: &str) -> Option<u64> {
    version.split(['.', '-', '+']).next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeForgejo;

    #[tokio::test]
    async fn v16_is_ready_and_reports_its_version() {
        let fj = FakeForgejo::with_version("16.0.5+gitea-1.22.0");
        let outcome = reconcile_instance(&fj).await;
        assert_eq!(outcome.ready, Ok("Forgejo 16.0.5+gitea-1.22.0".to_string()));
    }

    #[tokio::test]
    async fn older_majors_are_refused() {
        let fj = FakeForgejo::with_version("11.0.16");
        let outcome = reconcile_instance(&fj).await;
        assert_eq!(outcome.reason(), ReasonCode::UnsupportedForgejoVersion);
    }

    #[tokio::test]
    async fn unreachable_instance_is_reported() {
        let fj = FakeForgejo::default();
        fj.fail_next(crate::ports::GatewayError::Unreachable("dns".into()));
        let outcome = reconcile_instance(&fj).await;
        assert_eq!(outcome.reason(), ReasonCode::InstanceUnreachable);
    }
}
