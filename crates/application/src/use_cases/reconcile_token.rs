//! `ForgejoAccessToken`, issued through the v16 admin token API. A token's
//! value is shown once: losing it (or rotating) means revoking and issuing
//! a new one under the same name.

use std::collections::{BTreeMap, BTreeSet};

use api::common::DeletionPolicy;
use api::token::ForgejoAccessTokenSpec;
use domain::error::ReasonCode;

use crate::ports::{DesiredToken, ForgejoGateway, ForgejoRef, RemoteToken, SecretStore};
use crate::use_cases::emit::{self, rotation_requested};
use crate::use_cases::reconcile_repository::go_duration_secs;
use crate::use_cases::{Failure, Outcome, gone_ok};

pub struct TokenInput<'a> {
    pub spec: &'a ForgejoAccessTokenSpec,
    pub cr_name: &'a str,
    pub namespace: &'a str,
    /// Login of the resolved `spec.userRef`.
    pub user: String,
    /// `owner/name` of the resolved `spec.repositoryRefs`.
    pub repositories: Vec<String>,
    /// `status.forgejoId` (token id) / `status.forgejoName` (user login).
    pub current: Option<ForgejoRef>,
    pub rotate_nonce: Option<String>,
    pub last_rotation: Option<String>,
    pub allow_disruptive_update: bool,
    /// Unix seconds, injected for testability.
    pub now: i64,
}

pub fn token_name(spec: &ForgejoAccessTokenSpec, namespace: &str, cr_name: &str) -> String {
    spec.name
        .clone()
        .unwrap_or_else(|| format!("{namespace}-{cr_name}"))
}

pub async fn reconcile_token(
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
    let desired = DesiredToken {
        name: token_name(spec, input.namespace, input.cr_name),
        scopes: sorted(&spec.scopes),
        repositories: sorted(&input.repositories),
    };
    let targets = emit::targets(&spec.secret_targets, input.cr_name, secrets);
    let ns = Some(input.namespace);

    // A changed userRef: the old user's token is revoked below and a new
    // one issued — same disruption as a scope change.
    let same_user = input.current.as_ref().is_none_or(|c| c.name == input.user);
    let remote = match (&input.current, same_user) {
        (Some(c), true) => match gateway.list_access_tokens(&input.user).await {
            Ok(tokens) => tokens.into_iter().find(|t| t.id == c.id),
            Err(e) => return Outcome::failed(input.current.clone(), e),
        },
        _ => None,
    };

    let renew = match &remote {
        None => true,
        Some(r) => {
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
            let expired = spec
                .rotation_period
                .as_deref()
                .and_then(go_duration_secs)
                .zip(r.created_at)
                .is_some_and(|(period, created)| created + period as i64 <= input.now);
            let lost = match emit::any_missing(&targets, ns, secrets).await {
                Ok(lost) => lost,
                Err(f) => return Outcome::failed(input.current.clone(), f),
            };
            token_differs(&desired, r)
                || expired
                || lost
                || rotation_requested(&input.rotate_nonce, &input.last_rotation)
        }
    };
    if !renew {
        return Outcome::synced(input.current, "token valid");
    }

    // Names are unique per user: revoke before issuing. Also drops the
    // previous user's token after a userRef change.
    if let Some(c) = &input.current
        && let Err(e) = gone_ok(gateway.delete_access_token(&c.name, c.id).await)
    {
        return Outcome::failed(input.current.clone(), e);
    }
    let (token, value) = match gateway.create_access_token(&input.user, &desired).await {
        Ok(t) => t,
        Err(e) => return Outcome::failed(None, e),
    };
    let current = Some(ForgejoRef {
        id: token.id,
        name: input.user.clone(),
    });
    let data = BTreeMap::from([
        ("FORGEJO_TOKEN".to_string(), value),
        ("FORGEJO_USERNAME".to_string(), input.user.clone()),
        ("FORGEJO_URL".to_string(), gateway.web_url().to_string()),
    ]);
    if let Err(f) = emit::write_all(&targets, ns, &data, secrets).await {
        return Outcome::failed(current, f);
    }
    let mut outcome = Outcome::synced(current, "token issued");
    outcome.last_rotation = input.rotate_nonce.clone().or(input.last_rotation.clone());
    outcome
}

pub async fn cleanup_token(
    spec: &ForgejoAccessTokenSpec,
    cr_name: &str,
    namespace: &str,
    current: Option<&ForgejoRef>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Result<(), Failure> {
    if spec.deletion_policy == DeletionPolicy::Delete
        && let Some(c) = current
    {
        gone_ok(gateway.delete_access_token(&c.name, c.id).await)?;
    }
    let targets = emit::targets(&spec.secret_targets, cr_name, secrets);
    emit::delete_all(&targets, Some(namespace), secrets).await
}

fn sorted(v: &[String]) -> Vec<String> {
    v.iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn token_differs(d: &DesiredToken, r: &RemoteToken) -> bool {
    d.name != r.name || d.scopes != sorted(&r.scopes) || d.repositories != sorted(&r.repositories)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeForgejo, FakeSecretStore};

    const DAY: i64 = 86_400;

    fn spec() -> ForgejoAccessTokenSpec {
        ForgejoAccessTokenSpec {
            instance_ref: None,
            user_ref: api::common::ObjectRef {
                name: "ci-bot".into(),
            },
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
            repositories: vec![],
            current,
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
        let first = reconcile_token(input(&s, None, 0), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        let old = value(&secrets);

        let still = reconcile_token(input(&s, Some(first.clone()), 29 * DAY), &fj, &secrets).await;
        assert_eq!(still.forgejo, Some(first.clone()));

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
    async fn bad_rotation_period_is_invalid() {
        let (fj, secrets) = (forgejo(), FakeSecretStore::default());
        let mut s = spec();
        s.rotation_period = Some("monthly".into());
        let outcome = reconcile_token(input(&s, None, 0), &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
    }
}
