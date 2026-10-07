//! One `reconcile_*` use-case per CRD. Each returns an [`Outcome`] the
//! controller adapter turns into a status patch and, on transitions, a
//! Kubernetes `Event` — always through a `ReasonCode`, never a free string.

pub mod admission;
pub mod emit;
pub mod import;
pub mod reconcile_instance;
pub mod reconcile_key;
pub mod reconcile_namespace_policy;
pub mod reconcile_oauth2;
pub mod reconcile_organization;
pub mod reconcile_repository;
pub mod reconcile_team;
pub mod reconcile_token;
pub mod reconcile_user;
pub mod reconcile_webhook;

use domain::error::ReasonCode;

use crate::ports::{ForgejoGateway, ForgejoRef, GatewayError};

/// A finalizer cleanup's gateway, resolved by the caller up front — but its
/// error only matters once the cleanup actually has to call Forgejo: an
/// `Orphan` CR, or one that never owned anything, is released even while
/// its `ForgejoInstance` can't be resolved.
pub type CleanupGateway<'a> = Result<&'a dyn ForgejoGateway, &'a Failure>;

/// A `Ready: False` cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub reason: ReasonCode,
    pub message: String,
}

impl Failure {
    pub fn new(reason: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

impl From<GatewayError> for Failure {
    fn from(err: GatewayError) -> Self {
        Failure::new(err.reason(), err.to_string())
    }
}

/// A non-blocking condition shown next to `Ready: True` (its `type` is the
/// reason's name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub reason: ReasonCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The Forgejo object this CR now owns (or observes). Persisted even
    /// alongside a failure: a create that succeeded before a later step
    /// failed must never be attempted twice.
    pub forgejo: Option<ForgejoRef>,
    /// `Ok(message)` for `Ready: True`.
    pub ready: Result<String, Failure>,
    pub advisories: Vec<Advisory>,
    /// New `status.appliedSecretHash`, when write-only inputs were sent.
    pub secret_hash: Option<String>,
    /// New `status.lastRotation`, when a secret was (re)issued.
    pub last_rotation: Option<String>,
    /// Reconcile again no later than this (seconds), when something is due
    /// sooner than the steady-state requeue (a token's `rotationPeriod`).
    pub due_in: Option<u64>,
    /// New `status.secretPending`: `Some(true)` when a secret was issued
    /// but not written to every target, `Some(false)` once it was.
    pub secret_pending: Option<bool>,
    /// New `status.ownerId`, the Forgejo id of the account `forgejo`
    /// belongs to; written (or cleared) along with every `forgejo`.
    pub owner_id: Option<i64>,
}

impl Outcome {
    pub fn synced(forgejo: Option<ForgejoRef>, message: impl Into<String>) -> Self {
        Self {
            forgejo,
            ready: Ok(message.into()),
            advisories: Vec::new(),
            secret_hash: None,
            last_rotation: None,
            due_in: None,
            secret_pending: None,
            owner_id: None,
        }
    }

    pub fn failed(forgejo: Option<ForgejoRef>, failure: impl Into<Failure>) -> Self {
        Self {
            forgejo,
            ready: Err(failure.into()),
            advisories: Vec::new(),
            secret_hash: None,
            last_rotation: None,
            due_in: None,
            secret_pending: None,
            owner_id: None,
        }
    }

    /// The reason `Ready` ends on — what metrics and Events are keyed by.
    pub fn reason(&self) -> ReasonCode {
        match &self.ready {
            Ok(_) => ReasonCode::Reconciled,
            Err(f) => f.reason,
        }
    }

    /// Sets `owner_id` to the account `forgejo` belongs to: the `stored`
    /// one (`status.ownerId`) when a failure kept the `current` ref, the
    /// `desired` one otherwise — a success, or a new object, is always
    /// under the resolved owner (`None` = the admin account).
    pub(crate) fn with_owner(
        mut self,
        current: Option<&ForgejoRef>,
        stored: Option<i64>,
        desired: Option<i64>,
    ) -> Self {
        let kept = self.ready.is_err() && self.forgejo.as_ref() == current;
        self.owner_id = if kept { stored } else { desired };
        self
    }
}

/// Where the objects made for the stored owner (`stored_login`, as of
/// `status.ownerId` = `stored_id`) live, when that owner isn't the desired
/// one any more: `Ok(None)` = same account (a rename keeps the id, and the
/// objects are addressed by the new `login`). An empty login is the admin
/// account, which has no id to compare. Two different ids under one login
/// are told apart by asking Forgejo where the stored id is now: renamed
/// away (still holding the objects, under its new login) or deleted (they
/// went with it, and the account under `login` is a fresh start).
///
/// `locate` = false when the caller only needs to know whether the owner
/// changed (a refused disruptive update): two ids under two logins are
/// then answered without asking Forgejo, with `stored_login` standing in
/// for wherever the old account is now.
pub(crate) async fn previous_owner(
    gateway: &dyn ForgejoGateway,
    stored_login: &str,
    stored_id: Option<i64>,
    login: &str,
    id: Option<i64>,
    locate: bool,
) -> Result<Option<String>, GatewayError> {
    let by_login = || (stored_login != login).then(|| stored_login.to_string());
    if stored_login.is_empty() || login.is_empty() {
        return Ok(by_login());
    }
    match (stored_id, id) {
        (Some(a), Some(b)) if a == b => Ok(None),
        (Some(_), Some(_)) if !locate && stored_login != login => Ok(by_login()),
        (Some(a), Some(_)) => match gateway.user_login(a).await? {
            Some(now) => Ok(Some(now)),
            None => Ok(by_login()),
        },
        // A status written before ids were recorded.
        _ => Ok(by_login()),
    }
}

/// The login the objects made for `stored_login` (as of `stored_id`)
/// are under now: a renamed account keeps its id, and another one may
/// have taken the old login since. `Ok(None)` = the account was deleted,
/// and its objects with it. An empty login (the admin account) or a
/// status written before ids were recorded is taken as is.
pub(crate) async fn owner_login_now(
    gateway: &dyn ForgejoGateway,
    stored_login: &str,
    stored_id: Option<i64>,
) -> Result<Option<String>, GatewayError> {
    match stored_id {
        Some(id) if !stored_login.is_empty() => gateway.user_login(id).await,
        _ => Ok(Some(stored_login.to_string())),
    }
}

/// Ignores a `NotFound`: deleting what is already gone succeeds.
pub(crate) fn gone_ok(result: Result<(), GatewayError>) -> Result<(), GatewayError> {
    match result {
        Err(GatewayError::NotFound(_)) => Ok(()),
        other => other,
    }
}

/// `None` = no opinion; otherwise the remote flag must match.
pub(crate) fn differs_flag(desired: Option<bool>, remote: bool) -> bool {
    desired.is_some_and(|d| d != remote)
}

/// Distinguishes "the spec carries no opinion" (`None`) from a value that
/// must match: an unset optional field never forces a PATCH.
pub(crate) fn differs(desired: &Option<String>, remote: &str) -> bool {
    desired.as_deref().is_some_and(|d| d != remote)
}

#[cfg(test)]
mod tests {
    use super::{owner_login_now, previous_owner};
    use crate::ports::ForgejoGateway;
    use crate::test_support::FakeForgejo;

    #[tokio::test]
    async fn previous_owner_follows_the_id() {
        let fj = FakeForgejo::default();
        let alice = fj.insert_user("alice");
        let bob = fj.insert_user("bob");
        let same = |l: &'static str, i| previous_owner(&fj, "alice", Some(alice), l, i, true);
        assert_eq!(same("alice", Some(alice)).await.unwrap(), None);
        assert_eq!(same("alicia", Some(alice)).await.unwrap(), None, "renamed");
        assert_eq!(same("bob", Some(bob)).await.unwrap(), Some("alice".into()));
        assert_eq!(
            previous_owner(&fj, "alice", None, "bob", Some(bob), true)
                .await
                .unwrap(),
            Some("alice".into()),
            "legacy status"
        );
    }

    #[tokio::test]
    async fn same_login_new_id_is_told_apart() {
        let fj = FakeForgejo::default();
        let old = fj.insert_user("alice");
        // Deleted and recreated: nothing left on the old account.
        fj.remove_user("alice");
        let recreated = fj.insert_user("alice");
        let found = previous_owner(&fj, "alice", Some(old), "alice", Some(recreated), true);
        assert_eq!(found.await.unwrap(), None);

        // Renamed away, and a new account took the login: the old one
        // still holds the objects.
        fj.rename_user("alice", "alicia").await.unwrap();
        let newcomer = fj.insert_user("alice");
        let found = previous_owner(&fj, "alice", Some(recreated), "alice", Some(newcomer), true);
        assert_eq!(found.await.unwrap(), Some("alicia".into()));
    }

    #[tokio::test]
    async fn admin_account_only_matches_itself() {
        let fj = FakeForgejo::default();
        let alice = fj.insert_user("alice");
        assert_eq!(
            previous_owner(&fj, "", None, "", None, true).await.unwrap(),
            None
        );
        // A stale ownerId left over from a user owner must not match.
        let found = previous_owner(&fj, "", Some(alice), "alice", Some(alice), true);
        assert_eq!(found.await.unwrap(), Some(String::new()));
        let found = previous_owner(&fj, "alice", Some(alice), "", Some(alice), true);
        assert_eq!(found.await.unwrap(), Some("alice".into()));
    }

    #[tokio::test]
    async fn refusal_check_skips_the_lookup() {
        let fj = FakeForgejo::default();
        let alice = fj.insert_user("alice");
        let bob = fj.insert_user("bob");
        fj.rename_user("alice", "alicia").await.unwrap();
        // Told apart by login alone: a change, whatever alice is called now.
        fj.fail_next(crate::ports::GatewayError::Unreachable(
            "no call expected".into(),
        ));
        let found = previous_owner(&fj, "alice", Some(alice), "bob", Some(bob), false);
        assert_eq!(found.await.unwrap(), Some("alice".into()));
        // Same login, other id: only Forgejo can tell a rename from a
        // deletion.
        assert!(
            previous_owner(&fj, "bob", Some(alice), "bob", Some(bob), false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn owner_login_now_follows_renames_and_deletions() {
        let fj = FakeForgejo::default();
        let alice = fj.insert_user("alice");
        fj.rename_user("alice", "alicia").await.unwrap();
        fj.insert_user("alice");
        let now = owner_login_now(&fj, "alice", Some(alice)).await.unwrap();
        assert_eq!(now.as_deref(), Some("alicia"));
        fj.remove_user("alicia");
        assert_eq!(
            owner_login_now(&fj, "alice", Some(alice)).await.unwrap(),
            None
        );
        let legacy = owner_login_now(&fj, "alice", None).await.unwrap();
        assert_eq!(legacy.as_deref(), Some("alice"));
        assert_eq!(
            owner_login_now(&fj, "", Some(alice))
                .await
                .unwrap()
                .as_deref(),
            Some("")
        );
    }
}
