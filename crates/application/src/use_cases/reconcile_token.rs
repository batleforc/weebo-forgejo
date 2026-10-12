//! `ForgejoAccessToken`, issued through the v16 admin token API. A token's
//! value is shown once: losing it (or rotating) means revoking and issuing
//! a new one under the same name.

use std::collections::{BTreeMap, BTreeSet};

use api::common::DeletionPolicy;
use api::token::ForgejoAccessTokenSpec;
use domain::error::ReasonCode;

use crate::ports::{
    DesiredToken, ForgejoGateway, ForgejoRef, RemoteToken, SecretOwner, SecretStore,
};
use crate::use_cases::emit::{self, rotation_requested};
use crate::use_cases::reconcile_repository::go_duration_secs;
use crate::use_cases::{
    CleanupGateway, Failure, Outcome, gone_ok, owner_login_now, previous_owner,
};

pub struct TokenInput<'a> {
    pub spec: &'a ForgejoAccessTokenSpec,
    pub cr_name: &'a str,
    pub namespace: &'a str,
    /// Login of the resolved `spec.userRef`.
    pub user: String,
    /// Forgejo id of the resolved `spec.userRef`.
    pub user_id: Option<i64>,
    /// `owner/name` of the resolved `spec.repositoryRefs`.
    pub repositories: Vec<String>,
    /// `status.forgejoId` (token id) / `status.forgejoName` (user login).
    pub current: Option<ForgejoRef>,
    /// `status.ownerId`: the id of the user `current` was issued for.
    pub owner_id: Option<i64>,
    /// `status.secretPending`: the last issued token never reached every
    /// target, which may still hold a revoked one.
    pub secret_pending: bool,
    pub rotate_nonce: Option<String>,
    pub last_rotation: Option<String>,
    pub allow_disruptive_update: bool,
    /// Unix seconds, injected for testability.
    pub now: i64,
}

pub const KIND: &str = "ForgejoAccessToken";

pub fn token_name(spec: &ForgejoAccessTokenSpec, namespace: &str, cr_name: &str) -> String {
    spec.name
        .clone()
        .unwrap_or_else(|| format!("{namespace}-{cr_name}"))
}

/// Token names are unique per user, yet a rotation must issue the new
/// token before revoking the old one (consumers keep a working token until
/// the new one reached every target): the token alternates between its
/// name and this one.
pub fn rotated_name(name: &str) -> String {
    format!("{name}-next")
}

/// The name a token replacing `current` (named `current_name`) is issued
/// under.
fn next_name(base: &str, current_name: Option<&str>) -> String {
    if current_name == Some(base) {
        rotated_name(base)
    } else {
        base.to_string()
    }
}

/// The only scopes Forgejo accepts on a token limited to repositories.
const REPOSITORY_LIMITED_SCOPES: [&str; 4] = [
    "read:issue",
    "write:issue",
    "read:repository",
    "write:repository",
];

pub async fn reconcile_token(
    input: TokenInput<'_>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Outcome {
    let (current, stored, desired) = (input.current.clone(), input.owner_id, input.user_id);
    issue(input, gateway, secrets)
        .await
        .with_owner(current.as_ref(), stored, desired)
}

async fn issue(
    input: TokenInput<'_>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Outcome {
    let spec = input.spec;
    if let Some(p) = &spec.rotation_period
        && go_duration_secs(p).is_none_or(|s| s == 0)
    {
        return Outcome::failed(
            input.current,
            Failure::new(
                ReasonCode::InvalidSpec,
                format!("spec.rotationPeriod {p:?} is not a positive Go duration (e.g. 720h)"),
            ),
        );
    }
    // Forgejo refuses (400) a repository-limited token with any other
    // scope; say so before the round trip.
    if !spec.repository_refs.is_empty()
        && let Some(bad) = spec
            .scopes
            .iter()
            .find(|s| !REPOSITORY_LIMITED_SCOPES.contains(&s.as_str()))
    {
        return Outcome::failed(
            input.current,
            Failure::new(
                ReasonCode::InvalidSpec,
                format!(
                    "scope {bad:?} can't be combined with spec.repositoryRefs: Forgejo only \
                     allows {} on repository-limited tokens",
                    REPOSITORY_LIMITED_SCOPES.join(", ")
                ),
            ),
        );
    }
    let owner = SecretOwner::namespaced(KIND, input.namespace, input.cr_name);
    if let Err(f) = emit::check_targets(&spec.secret_targets, &owner) {
        return Outcome::failed(input.current, f);
    }
    let mut desired = DesiredToken {
        name: token_name(spec, input.namespace, input.cr_name),
        scopes: sorted(&spec.scopes),
        repositories: sorted(&input.repositories),
    };
    let targets = emit::targets(&spec.secret_targets, input.cr_name, secrets);

    // A changed userRef: the old user's token is revoked below and a new
    // one issued — same disruption as a scope change. A renamed user is
    // still the same one.
    let previous = match &input.current {
        Some(c) => {
            match previous_owner(
                gateway,
                &c.name,
                input.owner_id,
                &input.user,
                input.user_id,
                input.allow_disruptive_update,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => return Outcome::failed(input.current.clone(), e),
            }
        }
        None => None,
    };
    let same_user = previous.is_none();
    if !same_user && !input.allow_disruptive_update {
        return Outcome::failed(
            input.current.clone(),
            Failure::new(
                ReasonCode::DisruptiveUpdateRefused,
                "changing userRef revokes the current token and issues one for the new user; \
                 annotate the CR with forgejo.weebo.io/allow-disruptive-update=\"true\"",
            ),
        );
    }
    let remote = match (&input.current, same_user) {
        (Some(c), true) => match gateway.list_access_tokens(&input.user).await {
            Ok(tokens) => tokens.into_iter().find(|t| t.id == c.id),
            Err(e) => return Outcome::failed(input.current.clone(), e),
        },
        _ => None,
    };

    // Without a remote token there's nothing to keep: issue one.
    if let Some(r) = &remote {
        if token_differs(&desired, r) && !input.allow_disruptive_update {
            return Outcome::failed(
                input.current.clone(),
                Failure::new(
                    ReasonCode::DisruptiveUpdateRefused,
                    "changing scopes or repositories issues a new token (the current one is \
                     revoked); annotate the CR with \
                     forgejo.weebo.io/allow-disruptive-update=\"true\"",
                ),
            );
        }
        let expires_at = spec
            .rotation_period
            .as_deref()
            .and_then(go_duration_secs)
            .zip(r.created_at)
            .and_then(|(period, created)| created.checked_add(i64::try_from(period).ok()?));
        let expired = expires_at.is_some_and(|at| at <= input.now);
        let lost = match emit::any_missing(&targets, &owner, secrets).await {
            Ok(lost) => lost,
            Err(f) => return Outcome::failed(input.current.clone(), f),
        };
        let renew = token_differs(&desired, r)
            || expired
            || lost
            || input.secret_pending
            || rotation_requested(&input.rotate_nonce, &input.last_rotation);
        if !renew {
            // Under the user's current login: a rename moved the token along.
            let current = input.current.map(|c| ForgejoRef {
                id: c.id,
                name: input.user.clone(),
            });
            let mut outcome = Outcome::synced(current, "token valid");
            // Come back when it expires, not at the next 300 s requeue.
            outcome.due_in = expires_at.map(|at| {
                u64::try_from(at.saturating_sub(input.now))
                    .unwrap_or(0)
                    .max(1)
            });
            return outcome;
        }
    }

    // Issue the replacement first, under the name the current token
    // doesn't use, then fan it out, then revoke the old one: consumers
    // never hold a revoked token while the operator can help it. After a
    // userRef change the old token lives on another user: no name clash.
    let old_user = previous.clone().unwrap_or_else(|| input.user.clone());
    let base = desired.name.clone();
    desired.name = next_name(&base, remote.as_ref().map(|r| r.name.as_str()));
    let (token, value) = match create_token(gateway, &input.user, &desired, remote.as_ref()).await {
        Ok(t) => t,
        Err(e) => return Outcome::failed(input.current.clone(), e),
    };
    let issued = ForgejoRef {
        id: token.id,
        name: input.user.clone(),
    };
    let data = BTreeMap::from([
        ("FORGEJO_TOKEN".to_string(), value),
        ("FORGEJO_USERNAME".to_string(), input.user.clone()),
        ("FORGEJO_URL".to_string(), gateway.web_url().to_string()),
    ]);
    if let Err(f) = emit::write_all(&targets, &owner, &data, secrets).await {
        // Keep the old token (consumers may still hold it) and revoke the
        // new one, whose value is lost: the next reconcile issues again
        // under the then free name, whether the targets exist or not.
        let mut outcome = match gone_ok(gateway.delete_access_token(&input.user, token.id).await) {
            Ok(()) => Outcome::failed(input.current.clone(), f),
            // Can't revoke it: track it so it's the one replaced next time.
            Err(_) => Outcome::failed(Some(issued), f),
        };
        outcome.secret_pending = Some(true);
        return outcome;
    }
    // Every target holds the new token: revoke the old one. A failure
    // leaves it to expire or to the next rotation — never block on it.
    if let Some(c) = &input.current
        && c.id != token.id
        && let Err(e) = gone_ok(gateway.delete_access_token(&old_user, c.id).await)
    {
        tracing::warn!(error = %e, token = c.id, "revoking the replaced token failed");
    }
    let current = Some(issued);
    let mut outcome = Outcome::synced(current, "token issued");
    outcome.secret_pending = Some(false);
    outcome.last_rotation = input.rotate_nonce.clone().or(input.last_rotation.clone());
    outcome.due_in = spec
        .rotation_period
        .as_deref()
        .and_then(go_duration_secs)
        .map(|p| p.max(1));
    outcome
}

/// `owner_id` is `status.ownerId`: the token is revoked on that account
/// under its login now, not the stored one — a rename (and another account
/// taking the old login) would otherwise revoke on the wrong user, whose
/// `NotFound` reads as success and leaves the token live.
pub async fn cleanup_token(
    spec: &ForgejoAccessTokenSpec,
    cr_name: &str,
    namespace: &str,
    current: Option<&ForgejoRef>,
    owner_id: Option<i64>,
    gateway: CleanupGateway<'_>,
    secrets: &dyn SecretStore,
) -> Result<(), Failure> {
    if spec.deletion_policy == DeletionPolicy::Delete
        && let Some(c) = current
    {
        let gateway = gateway.map_err(Clone::clone)?;
        // A deleted account took its tokens with it.
        if let Some(user) = owner_login_now(gateway, &c.name, owner_id).await? {
            gone_ok(gateway.delete_access_token(&user, c.id).await)?;
        }
    }
    let targets = emit::targets(&spec.secret_targets, cr_name, secrets);
    let owner = SecretOwner::namespaced(KIND, namespace, cr_name);
    emit::delete_all(&targets, &owner, secrets).await
}

/// Issues `desired`. A token already holding its name that isn't the one
/// being replaced is ours from an earlier attempt whose response was lost
/// (the name is derived from the CR): revoked, then issued again.
async fn create_token(
    gateway: &dyn ForgejoGateway,
    user: &str,
    desired: &DesiredToken,
    replacing: Option<&RemoteToken>,
) -> Result<(ForgejoRef, String), Failure> {
    match gateway.create_access_token(user, desired).await {
        Err(e) if e.reason() == ReasonCode::ForgejoObjectAlreadyExists => {
            let stale = gateway
                .list_access_tokens(user)
                .await?
                .into_iter()
                .find(|t| t.name == desired.name && Some(t.id) != replacing.map(|r| r.id));
            let Some(stale) = stale else {
                return Err(e.into());
            };
            gone_ok(gateway.delete_access_token(user, stale.id).await)?;
            Ok(gateway.create_access_token(user, desired).await?)
        }
        other => Ok(other?),
    }
}

fn sorted(v: &[String]) -> Vec<String> {
    v.iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// `d.name` is the base name: a rotated token carries [`rotated_name`].
fn token_differs(d: &DesiredToken, r: &RemoteToken) -> bool {
    (d.name != r.name && rotated_name(&d.name) != r.name)
        || d.scopes != sorted(&r.scopes)
        || d.repositories != sorted(&r.repositories)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeForgejo, FakeSecretStore};

    const DAY: i64 = 86_400;

    fn spec() -> ForgejoAccessTokenSpec {
        ForgejoAccessTokenSpec {
            instance_ref: None,
            user_ref: api::common::IdentityRef::named("ci-bot"),
            name: None,
            scopes: vec!["write:repository".into(), "read:user".into()],
            repository_refs: vec![],
            rotation_period: None,
            secret_targets: vec![],
            deletion_policy: DeletionPolicy::Delete,
        }
    }

    fn input<'a>(
        spec: &'a ForgejoAccessTokenSpec,
        current: Option<ForgejoRef>,
        now: i64,
    ) -> TokenInput<'a> {
        TokenInput {
            spec,
            cr_name: "ci",
            namespace: "team-a",
            user: "ci-bot".into(),
            user_id: Some(1),
            repositories: vec![],
            current,
            owner_id: Some(1),
            secret_pending: false,
            rotate_nonce: None,
            last_rotation: None,
            allow_disruptive_update: false,
            now,
        }
    }

    fn forgejo() -> FakeForgejo {
        let fj = FakeForgejo::default();
        fj.insert_user("ci-bot");
        fj
    }

    fn value(secrets: &FakeSecretStore) -> String {
        secrets.get("team-a/ci").unwrap()["FORGEJO_TOKEN"].clone()
    }

    #[tokio::test]
    async fn issues_once_then_stays_quiet() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let s = spec();
        let current = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        assert_eq!(fj.token(current.id).unwrap().1, value(&secrets));
        assert_eq!(fj.token(current.id).unwrap().0.name, "team-a-ci");

        fj.clear_calls();
        reconcile_token(input(&s, Some(current), DAY), &fj, &secrets).await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn rotation_period_renews_and_revokes_the_old_token() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let mut s = spec();
        s.rotation_period = Some("720h".into());
        let issued = reconcile_token(input(&s, None, 0), &fj, &secrets).await;
        assert_eq!(issued.due_in, Some(30 * DAY as u64), "back when it expires");
        let first = issued.forgejo.unwrap();
        let old = value(&secrets);

        let still = reconcile_token(input(&s, Some(first.clone()), 29 * DAY), &fj, &secrets).await;
        assert_eq!(still.forgejo, Some(first.clone()));
        assert_eq!(still.due_in, Some(DAY as u64), "the day left, not 300 s");

        let renewed = reconcile_token(input(&s, Some(first.clone()), 31 * DAY), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        assert_ne!(renewed.id, first.id);
        assert!(fj.token(first.id).is_none(), "old token revoked");
        assert_ne!(value(&secrets), old);
    }

    #[tokio::test]
    async fn lost_target_reissues() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let s = spec();
        let first = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        secrets.remove("team-a/ci");
        let second = reconcile_token(input(&s, Some(first.clone()), 0), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        assert_ne!(first.id, second.id);
        assert!(secrets.get("team-a/ci").is_some());
    }

    #[tokio::test]
    async fn scope_change_is_gated() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let mut s = spec();
        let first = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo;
        s.scopes.push("write:issue".into());
        let refused = reconcile_token(input(&s, first.clone(), 0), &fj, &secrets).await;
        assert_eq!(refused.reason(), ReasonCode::DisruptiveUpdateRefused);

        let mut allowed = input(&s, first.clone(), 0);
        allowed.allow_disruptive_update = true;
        let renewed = reconcile_token(allowed, &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        assert!(
            fj.token(renewed.id)
                .unwrap()
                .0
                .scopes
                .contains(&"write:issue".to_string())
        );
    }

    #[tokio::test]
    async fn failed_write_over_an_existing_target_reissues() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let s = spec();
        let first = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo;

        // A rotation whose write fails: the old token stays valid (the
        // target still holds it), the new one is revoked again.
        secrets.fail_writes(true);
        let mut rotate = input(&s, first.clone(), 0);
        rotate.rotate_nonce = Some("1".into());
        let failed = reconcile_token(rotate, &fj, &secrets).await;
        assert_eq!(failed.reason(), ReasonCode::SecretTargetFailed);
        assert_eq!(failed.secret_pending, Some(true));
        let issued = failed.forgejo.unwrap();
        assert_eq!(Some(&issued), first.as_ref(), "the old token is kept");
        assert_eq!(
            fj.token(issued.id).unwrap().1,
            value(&secrets),
            "still valid"
        );
        assert_eq!(fj.tokens_of("ci-bot").len(), 1, "the new token is revoked");

        secrets.fail_writes(false);
        let mut retry = input(&s, Some(issued.clone()), 0);
        retry.rotate_nonce = Some("1".into());
        retry.last_rotation = Some("1".into());
        retry.secret_pending = true;
        let fixed = reconcile_token(retry, &fj, &secrets).await;
        assert!(fixed.ready.is_ok(), "{fixed:?}");
        assert_eq!(fixed.secret_pending, Some(false));
        let current = fixed.forgejo.unwrap();
        assert_ne!(current.id, issued.id);
        assert_eq!(fj.token(current.id).unwrap().1, value(&secrets));
    }

    #[tokio::test]
    async fn renamed_user_keeps_its_token() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let s = spec();
        let first = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        fj.rename_user("ci-bot", "ci-robot").await.unwrap();
        fj.clear_calls();

        let mut renamed = input(&s, Some(first.clone()), 0);
        renamed.user = "ci-robot".into();
        let outcome = reconcile_token(renamed, &fj, &secrets).await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
        assert_eq!(
            outcome.forgejo,
            Some(ForgejoRef {
                id: first.id,
                name: "ci-robot".into()
            })
        );
    }

    #[tokio::test]
    async fn recreated_user_gets_a_new_token() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let s = spec();
        let first = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        // Deleted out of band and recreated under the same login: new id,
        // and the token went with the old account.
        fj.remove_user("ci-bot");
        let new_id = fj.insert_user("ci-bot");

        let mut recreated = input(&s, Some(first.clone()), 0);
        recreated.user_id = Some(new_id);
        let outcome = reconcile_token(recreated, &fj, &secrets).await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        assert_eq!(outcome.owner_id, Some(new_id));
        let issued = outcome.forgejo.unwrap();
        assert_ne!(issued.id, first.id);
        assert_eq!(fj.token(issued.id).unwrap().1, value(&secrets));
    }

    #[tokio::test]
    async fn login_taken_over_after_a_rename_revokes_the_old_token() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let s = spec();
        let first = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        // ci-bot renamed away (its token follows), a new ci-bot created.
        fj.rename_user("ci-bot", "ci-old").await.unwrap();
        let newcomer = fj.insert_user("ci-bot");

        let mut taken = input(&s, Some(first.clone()), 0);
        taken.user_id = Some(newcomer);
        let refused = reconcile_token(taken, &fj, &secrets).await;
        assert_eq!(refused.reason(), ReasonCode::DisruptiveUpdateRefused);
        assert_eq!(refused.owner_id, Some(1), "still the old account's token");

        let mut allowed = input(&s, Some(first.clone()), 0);
        allowed.user_id = Some(newcomer);
        allowed.allow_disruptive_update = true;
        let renewed = reconcile_token(allowed, &fj, &secrets).await;
        assert!(renewed.ready.is_ok(), "{renewed:?}");
        assert!(
            fj.token(first.id).is_none(),
            "revoked on the renamed account"
        );
        assert_eq!(renewed.owner_id, Some(newcomer));
    }

    #[tokio::test]
    async fn cleanup_revokes_on_the_renamed_account() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let s = spec();
        let first = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        // Renamed away and the login taken over before any reconcile.
        fj.rename_user("ci-bot", "ci-old").await.unwrap();
        let newcomer = fj.insert_user("ci-bot");
        cleanup_token(&s, "ci", "team-a", Some(&first), Some(1), Ok(&fj), &secrets)
            .await
            .unwrap();
        assert!(fj.token(first.id).is_none(), "revoked on ci-old");

        // The account deleted with its tokens: nothing left to revoke.
        let mut fresh = input(&s, None, 0);
        fresh.user_id = Some(newcomer);
        let again = reconcile_token(fresh, &fj, &secrets).await.forgejo.unwrap();
        fj.remove_user("ci-bot");
        fj.clear_calls();
        cleanup_token(
            &s,
            "ci",
            "team-a",
            Some(&again),
            Some(newcomer),
            Ok(&fj),
            &secrets,
        )
        .await
        .unwrap();
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn user_ref_change_is_gated() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let other = fj.insert_user("deploy-bot");
        let s = spec();
        let first = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        fj.clear_calls();

        let mut moved = input(&s, Some(first.clone()), 0);
        moved.user = "deploy-bot".into();
        moved.user_id = Some(other);
        let refused = reconcile_token(moved, &fj, &secrets).await;
        assert_eq!(refused.reason(), ReasonCode::DisruptiveUpdateRefused);
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());

        let mut allowed = input(&s, Some(first.clone()), 0);
        allowed.user = "deploy-bot".into();
        allowed.user_id = Some(other);
        allowed.allow_disruptive_update = true;
        let renewed = reconcile_token(allowed, &fj, &secrets).await;
        assert_eq!(renewed.owner_id, Some(other));
        assert!(fj.token(first.id).is_none(), "old user's token revoked");
        assert_eq!(
            fj.token(renewed.forgejo.unwrap().id).unwrap().0.name,
            "team-a-ci"
        );
    }

    #[tokio::test]
    async fn bad_rotation_period_is_invalid() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let mut s = spec();
        s.rotation_period = Some("monthly".into());
        let outcome = reconcile_token(input(&s, None, 0), &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
    }

    #[tokio::test]
    async fn repository_limited_token_rejects_other_scopes() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let mut s = spec();
        s.repository_refs = vec![api::common::ObjectRef { name: "app".into() }];
        s.scopes = vec!["read:repository".into(), "read:user".into()];
        let outcome = reconcile_token(input(&s, None, 0), &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }
}
