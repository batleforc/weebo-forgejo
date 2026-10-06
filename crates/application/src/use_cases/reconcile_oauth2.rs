//! `ForgejoOAuth2Application`. Forgejo regenerates the client secret on
//! *every* update and never shows it again, so this use-case only updates
//! when it must: a real spec difference, a target that lost the secret, or
//! a new rotation nonce — never blindly on each requeue.

use std::collections::{BTreeMap, BTreeSet};

use api::common::DeletionPolicy;
use api::oauth2::ForgejoOAuth2ApplicationSpec;
use domain::error::ReasonCode;

use crate::ports::{DesiredOAuth2App, ForgejoGateway, ForgejoRef, RemoteOAuth2App, SecretStore};
use crate::use_cases::emit::{self, rotation_requested};
use crate::use_cases::{Failure, Outcome, gone_ok};

pub struct OAuth2Input<'a> {
    pub spec: &'a ForgejoOAuth2ApplicationSpec,
    pub cr_name: &'a str,
    pub namespace: &'a str,
    /// Login of the resolved `spec.ownerRef`; `None` = the admin account.
    pub owner: Option<String>,
    /// `status.forgejoId` (app id) / `status.forgejoName` (owner login, or
    /// empty for the admin account).
    pub current: Option<ForgejoRef>,
    pub rotate_nonce: Option<String>,
    pub last_rotation: Option<String>,
    pub allow_disruptive_update: bool,
}

pub async fn reconcile_oauth2(
    input: OAuth2Input<'_>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Outcome {
    let desired = desired_app(&input);
    let owner_name = input.owner.clone().unwrap_or_default();
    let targets = emit::targets(&input.spec.secret_targets, input.cr_name, secrets);
    let ns = Some(input.namespace);

    // An application can't change owner: delete under the old one, then
    // create under the new one (new client id).
    let mut current = input.current.clone();
    if let Some(c) = &current
        && c.name != owner_name
    {
        if !input.allow_disruptive_update {
            return Outcome::failed(
                current,
                Failure::new(
                    ReasonCode::DisruptiveUpdateRefused,
                    "changing ownerRef recreates the application with a new client id; annotate \
                     the CR with forgejo.weebo.io/allow-disruptive-update=\"true\"",
                ),
            );
        }
        if let Err(e) = gone_ok(gateway.delete_oauth2_app(sudo(&c.name), c.id).await) {
            return Outcome::failed(current, e);
        }
        current = None;
    }

    let remote = match &current {
        Some(c) => match gateway.get_oauth2_app(input.owner.as_deref(), c.id).await {
            Ok(r) => r,
            Err(e) => return Outcome::failed(current, e),
        },
        None => None,
    };

    let (app, secret) = match remote {
        None => match gateway
            .create_oauth2_app(input.owner.as_deref(), &desired)
            .await
        {
            Ok((app, secret)) => (app, Some(secret)),
            Err(e) => return Outcome::failed(None, e),
        },
        Some(remote) => {
            let lost = match emit::any_missing(&targets, ns, secrets).await {
                Ok(lost) => lost,
                Err(f) => return Outcome::failed(current, f),
            };
            if app_differs(&desired, &remote)
                || lost
                || rotation_requested(&input.rotate_nonce, &input.last_rotation)
            {
                match gateway
                    .update_oauth2_app(input.owner.as_deref(), remote.id, &desired)
                    .await
                {
                    Ok(secret) => (remote, Some(secret)),
                    Err(e) => return Outcome::failed(current, e),
                }
            } else {
                (remote, None)
            }
        }
    };

    let current = Some(ForgejoRef {
        id: app.id,
        name: owner_name,
    });
    let mut outcome = Outcome::synced(current.clone(), "application synced");
    if let Some(secret) = secret {
        let data = BTreeMap::from([
            ("FORGEJO_CLIENT_ID".to_string(), app.client_id.clone()),
            ("FORGEJO_CLIENT_SECRET".to_string(), secret),
            // Forgejo's OIDC issuer is the instance root.
            ("FORGEJO_URL".to_string(), gateway.web_url().to_string()),
        ]);
        // On failure the secret is lost; the next reconcile sees the target
        // missing and rotates again.
        if let Err(f) = emit::write_all(&targets, ns, &data, secrets).await {
            return Outcome::failed(current, f);
        }
        outcome.last_rotation = input.rotate_nonce.clone().or(input.last_rotation.clone());
    }
    outcome
}

pub async fn cleanup_oauth2(
    spec: &ForgejoOAuth2ApplicationSpec,
    cr_name: &str,
    namespace: &str,
    current: Option<&ForgejoRef>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Result<(), Failure> {
    if spec.deletion_policy == DeletionPolicy::Delete
        && let Some(c) = current
    {
        gone_ok(gateway.delete_oauth2_app(sudo(&c.name), c.id).await)?;
    }
    let targets = emit::targets(&spec.secret_targets, cr_name, secrets);
    emit::delete_all(&targets, Some(namespace), secrets).await
}

/// `status.forgejoName` holds the owner login, empty for the admin.
fn sudo(owner: &str) -> Option<&str> {
    (!owner.is_empty()).then_some(owner)
}

fn desired_app(input: &OAuth2Input<'_>) -> DesiredOAuth2App {
    DesiredOAuth2App {
        name: input
            .spec
            .name
            .clone()
            .unwrap_or_else(|| input.cr_name.to_string()),
        redirect_uris: input.spec.redirect_uris.clone(),
        confidential_client: input.spec.confidential_client,
    }
}

fn app_differs(d: &DesiredOAuth2App, r: &RemoteOAuth2App) -> bool {
    let set = |v: &[String]| v.iter().cloned().collect::<BTreeSet<_>>();
    d.name != r.name
        || d.confidential_client != r.confidential_client
        || set(&d.redirect_uris) != set(&r.redirect_uris)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeForgejo, FakeSecretStore};

    fn spec() -> ForgejoOAuth2ApplicationSpec {
        ForgejoOAuth2ApplicationSpec {
            instance_ref: None,
            owner_ref: None,
            name: None,
            redirect_uris: vec!["https://app.example.com/callback".into()],
            confidential_client: true,
            secret_targets: vec![],
            deletion_policy: DeletionPolicy::Delete,
        }
    }

    fn input<'a>(
        spec: &'a ForgejoOAuth2ApplicationSpec,
        owner: Option<&str>,
        current: Option<ForgejoRef>,
    ) -> OAuth2Input<'a> {
        OAuth2Input {
            spec,
            cr_name: "app",
            namespace: "team-a",
            owner: owner.map(str::to_string),
            current,
            rotate_nonce: None,
            last_rotation: None,
            allow_disruptive_update: false,
        }
    }

    #[tokio::test]
    async fn creates_under_the_owner_and_emits_credentials() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        fj.insert_user("sso-bot");
        let s = spec();
        let outcome = reconcile_oauth2(input(&s, Some("sso-bot"), None), &fj, &secrets).await;
        let current = outcome.forgejo.unwrap();
        assert_eq!(current.name, "sso-bot");

        let (owner, _app, secret) = fj.oauth2_app(current.id).unwrap();
        assert_eq!(owner, "sso-bot");
        let data = secrets.get("team-a/app").expect("default target");
        assert_eq!(data["FORGEJO_CLIENT_SECRET"], secret);
        assert_eq!(data["FORGEJO_URL"], "https://git.example.com");
    }

    #[tokio::test]
    async fn steady_state_never_regenerates_the_secret() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let s = spec();
        let current = reconcile_oauth2(input(&s, None, None), &fj, &secrets)
            .await
            .forgejo;
        fj.clear_calls();
        reconcile_oauth2(input(&s, None, current), &fj, &secrets).await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn redirect_change_lost_target_and_nonce_each_rotate() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut s = spec();
        let current = reconcile_oauth2(input(&s, None, None), &fj, &secrets)
            .await
            .forgejo;
        let first = secrets.get("team-a/app").unwrap()["FORGEJO_CLIENT_SECRET"].clone();

        s.redirect_uris.push("https://app.example.com/cb2".into());
        reconcile_oauth2(input(&s, None, current.clone()), &fj, &secrets).await;
        let second = secrets.get("team-a/app").unwrap()["FORGEJO_CLIENT_SECRET"].clone();
        assert_ne!(first, second);

        secrets.remove("team-a/app");
        reconcile_oauth2(input(&s, None, current.clone()), &fj, &secrets).await;
        let third = secrets.get("team-a/app").unwrap()["FORGEJO_CLIENT_SECRET"].clone();
        assert_ne!(second, third);

        let mut rotate = input(&s, None, current.clone());
        rotate.rotate_nonce = Some("1".into());
        let rotated = reconcile_oauth2(rotate, &fj, &secrets).await;
        assert_eq!(rotated.last_rotation.as_deref(), Some("1"));
        assert_eq!(rotated.forgejo, current, "same application, new secret");
    }

    #[tokio::test]
    async fn owner_change_is_gated_then_recreates() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        fj.insert_user("sso-bot");
        let s = spec();
        let current = reconcile_oauth2(input(&s, None, None), &fj, &secrets)
            .await
            .forgejo;

        let refused =
            reconcile_oauth2(input(&s, Some("sso-bot"), current.clone()), &fj, &secrets).await;
        assert_eq!(refused.reason(), ReasonCode::DisruptiveUpdateRefused);

        let mut allowed = input(&s, Some("sso-bot"), current.clone());
        allowed.allow_disruptive_update = true;
        let moved = reconcile_oauth2(allowed, &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        assert_ne!(Some(moved.id), current.map(|c| c.id));
        assert_eq!(fj.oauth2_app(moved.id).unwrap().0, "sso-bot");
    }
}
