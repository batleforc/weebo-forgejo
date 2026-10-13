use crate::ports::ForgejoGateway;
use crate::use_cases::{Failure, Outcome};
use domain::error::ReasonCode;

/// Oldest Forgejo major this operator supports: v16 introduced the admin
/// access-token API (`.prompt/plan.md`, "Périmètre").
pub const MIN_MAJOR_VERSION: u64 = 16;

/// A `ForgejoInstance` has no Forgejo-side object: reconciling it is a
/// connectivity, token and version check, whose result every other CR's
/// readiness implicitly depends on. `require_admin`: the token must be a
/// site admin's (a `ForgejoInstance`; a `ForgejoLocalInstance`'s token
/// only bounds what its namespace can do).
pub async fn reconcile_instance(gateway: &dyn ForgejoGateway, require_admin: bool) -> Outcome {
    let version = match gateway.server_version().await {
        Ok(v) => v,
        Err(e) => return Outcome::failed(None, e),
    };
    if major(&version).is_none_or(|m| m < MIN_MAJOR_VERSION) {
        return Outcome::failed(
            None,
            Failure::new(
                ReasonCode::UnsupportedForgejoVersion,
                format!("Forgejo {version} is older than v{MIN_MAJOR_VERSION}"),
            ),
        );
    }
    let user = match gateway.token_user().await {
        Ok(u) => u,
        Err(e) => return Outcome::failed(None, e),
    };
    if user.admin {
        return Outcome::synced(
            None,
            format!("Forgejo {version}, as site admin {:?}", user.login),
        );
    }
    if require_admin {
        return Outcome::failed(
            None,
            Failure::new(
                ReasonCode::InstanceTokenNotAdmin,
                format!(
                    "the token belongs to {:?}, not a site admin: user, token and organization \
                     management would fail",
                    user.login
                ),
            ),
        );
    }
    Outcome::synced(
        None,
        format!(
            "Forgejo {version}, as {:?} (not a site admin: only what that account may do)",
            user.login
        ),
    )
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
        let outcome = reconcile_instance(&fj, true).await;
        assert_eq!(
            outcome.ready,
            Ok("Forgejo 16.0.5+gitea-1.22.0, as site admin \"admin\"".to_string())
        );
    }

    #[tokio::test]
    async fn a_shared_instance_needs_a_site_admin_token() {
        let fj = FakeForgejo::with_version("16.0.5");
        fj.set_token_admin(false);
        let outcome = reconcile_instance(&fj, true).await;
        assert_eq!(outcome.reason(), ReasonCode::InstanceTokenNotAdmin);
        let local = reconcile_instance(&fj, false).await;
        assert!(local.ready.is_ok(), "{local:?}");
    }

    #[tokio::test]
    async fn older_majors_are_refused() {
        let fj = FakeForgejo::with_version("11.0.16");
        let outcome = reconcile_instance(&fj, true).await;
        assert_eq!(outcome.reason(), ReasonCode::UnsupportedForgejoVersion);
    }

    #[tokio::test]
    async fn unreachable_instance_is_reported() {
        let fj = FakeForgejo::default();
        fj.fail_next(crate::ports::GatewayError::Unreachable("dns".into()));
        let outcome = reconcile_instance(&fj, true).await;
        assert_eq!(outcome.reason(), ReasonCode::InstanceUnreachable);
    }
}
