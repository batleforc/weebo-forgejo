//! SSH keys — `ForgejoDeployKey` (on a repository) and `ForgejoUserKey`
//! (on a user) share this use-case. Keys are immutable in Forgejo: any
//! change of title, key or access deletes and recreates. Without a
//! `publicKey`, an ed25519 pair is generated and its private half written
//! to `secretTargets`; a missing target or a new rotation nonce generates
//! a fresh pair (a private key can't be read back).

use std::collections::BTreeMap;

use api::common::DeletionPolicy;
use api::keys::KeySource;
use domain::error::ReasonCode;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use crate::ports::{ForgejoGateway, ForgejoRef, GatewayError, RemoteKey, SecretStore};
use crate::use_cases::{Failure, Outcome, gone_ok};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOwner {
    /// `owner/name` of the repository (deploy key).
    Repository(String),
    /// Login of the user (user key).
    User(String),
}

pub struct KeyInput<'a> {
    pub owner: KeyOwner,
    pub title: String,
    /// Always `false` for user keys.
    pub read_only: bool,
    pub source: &'a KeySource,
    /// The CR's namespace; `None` for the cluster-scoped `ForgejoUserKey`.
    pub namespace: Option<&'a str>,
    pub current: Option<ForgejoRef>,
    /// The `forgejo.weebo.io/rotate-secret` annotation.
    pub rotate_nonce: Option<String>,
    pub last_rotation: Option<String>,
}

pub fn validate(source: &KeySource, namespace: Option<&str>) -> Result<(), Failure> {
    let invalid = |m: &str| Err(Failure::new(ReasonCode::InvalidSpec, m));
    if source.public_key.is_none() && source.secret_targets.is_empty() {
        return invalid("a generated key (no spec.publicKey) needs spec.secretTargets");
    }
    for target in &source.secret_targets {
        if target.namespace.is_none() && namespace.is_none() {
            return invalid("spec.secretTargets[].namespace is required on a cluster-scoped CR");
        }
    }
    Ok(())
}

pub async fn reconcile_key(
    input: KeyInput<'_>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Outcome {
    if let Err(f) = validate(input.source, input.namespace) {
        return Outcome::failed(input.current, f);
    }

    let remote = match &input.current {
        Some(c) => match get(&input.owner, c.id, gateway).await {
            Ok(r) => r,
            Err(e) => return Outcome::failed(input.current.clone(), e),
        },
        None => None,
    };

    // A generated pair is renewed when nothing exists yet, a rotation was
    // asked for, or a target lost the private key.
    let generated = input.source.public_key.is_none();
    let rotation_requested =
        input.rotate_nonce.is_some() && input.rotate_nonce != input.last_rotation;
    let renew = generated
        && (remote.is_none()
            || rotation_requested
            || match any_target_missing(&input, secrets).await {
                Ok(missing) => missing,
                Err(f) => return Outcome::failed(input.current.clone(), f),
            });

    let mut new_pair = None;
    let wanted_key = match (&input.source.public_key, &remote) {
        (Some(key), _) => key.clone(),
        (None, Some(r)) if !renew => r.key.clone(),
        (None, _) => match generate_pair() {
            Ok((private, public)) => {
                let key = public.clone();
                new_pair = Some((private, public));
                key
            }
            Err(f) => return Outcome::failed(input.current.clone(), f),
        },
    };

    let up_to_date = remote.as_ref().is_some_and(|r| {
        same_key(&r.key, &wanted_key) && r.title == input.title && r.read_only == input.read_only
    });
    let current = if up_to_date {
        input.current.clone()
    } else {
        if let Some(r) = &remote
            && let Err(e) = gone_ok(delete(&input.owner, r.id, gateway).await)
        {
            return Outcome::failed(input.current.clone(), e);
        }
        match create(&input, &wanted_key, gateway).await {
            Ok(created) => Some(created),
            Err(e) => return Outcome::failed(None, e),
        }
    };

    let mut outcome = Outcome::synced(current.clone(), "key synced");
    if let Some((private, public)) = new_pair {
        let data = BTreeMap::from([
            ("ssh-privatekey".to_string(), private),
            ("ssh-publickey".to_string(), public),
        ]);
        for target in &input.source.secret_targets {
            if let Err(e) = secrets.write(target, input.namespace, &data).await {
                // The key exists in Forgejo; the next reconcile sees the
                // target missing and renews the pair.
                return Outcome::failed(
                    current,
                    Failure::new(ReasonCode::SecretTargetFailed, e.to_string()),
                );
            }
        }
        outcome.last_rotation = input.rotate_nonce.clone().or(input.last_rotation.clone());
    }
    outcome
}

/// `owner` is `None` when the repository/user is already gone — and took
/// the key with it: only the emitted secrets are left to delete.
pub async fn cleanup_key(
    owner: Option<&KeyOwner>,
    source: &KeySource,
    namespace: Option<&str>,
    deletion_policy: DeletionPolicy,
    current: Option<&ForgejoRef>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Result<(), Failure> {
    if deletion_policy == DeletionPolicy::Delete
        && let (Some(owner), Some(current)) = (owner, current)
    {
        gone_ok(delete(owner, current.id, gateway).await)?;
    }
    if source.public_key.is_none() {
        for target in &source.secret_targets {
            secrets
                .delete(target, namespace)
                .await
                .map_err(|e| Failure::new(ReasonCode::SecretTargetFailed, e.to_string()))?;
        }
    }
    Ok(())
}

async fn get(
    owner: &KeyOwner,
    id: i64,
    gateway: &dyn ForgejoGateway,
) -> Result<Option<RemoteKey>, GatewayError> {
    match owner {
        KeyOwner::Repository(repo) => gateway.get_deploy_key(repo, id).await,
        KeyOwner::User(user) => gateway.get_user_key(user, id).await,
    }
}

async fn create(
    input: &KeyInput<'_>,
    key: &str,
    gateway: &dyn ForgejoGateway,
) -> Result<ForgejoRef, GatewayError> {
    match &input.owner {
        KeyOwner::Repository(repo) => {
            gateway
                .create_deploy_key(repo, &input.title, key, input.read_only)
                .await
        }
        KeyOwner::User(user) => gateway.create_user_key(user, &input.title, key).await,
    }
}

async fn delete(
    owner: &KeyOwner,
    id: i64,
    gateway: &dyn ForgejoGateway,
) -> Result<(), GatewayError> {
    match owner {
        KeyOwner::Repository(repo) => gateway.delete_deploy_key(repo, id).await,
        KeyOwner::User(user) => gateway.delete_user_key(user, id).await,
    }
}

async fn any_target_missing(
    input: &KeyInput<'_>,
    secrets: &dyn SecretStore,
) -> Result<bool, Failure> {
    for target in &input.source.secret_targets {
        let exists = secrets
            .exists(target, input.namespace)
            .await
            .map_err(|e| Failure::new(ReasonCode::SecretTargetFailed, e.to_string()))?;
        if !exists {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Compares algorithm and key material only: Forgejo may drop or rewrite
/// the trailing comment.
fn same_key(a: &str, b: &str) -> bool {
    a.split_whitespace()
        .take(2)
        .eq(b.split_whitespace().take(2))
}

/// `(OpenSSH private key PEM, public key line)`.
fn generate_pair() -> Result<(String, String), Failure> {
    let fail =
        |e: ssh_key::Error| Failure::new(ReasonCode::InvalidSpec, format!("key generation: {e}"));
    let private =
        PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).map_err(fail)?;
    let public = private.public_key().to_openssh().map_err(fail)?;
    let pem = private.to_openssh(LineEnding::LF).map_err(fail)?;
    Ok((pem.to_string(), public))
}

#[cfg(test)]
mod tests {
    use api::common::SecretTarget;
    use api::instance::SecretStoreBackend;

    use super::*;
    use crate::test_support::{FakeForgejo, FakeSecretStore};

    const ALICE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb5yJ0ib7G0kO7HW2zVhgEqv9n0LjQeYv3tG9Z4yW7r alice";

    fn generated() -> KeySource {
        KeySource {
            public_key: None,
            secret_targets: vec![SecretTarget {
                backend: SecretStoreBackend::Kubernetes,
                name: "deploy".into(),
                namespace: None,
                path: None,
            }],
        }
    }

    fn input<'a>(source: &'a KeySource, current: Option<ForgejoRef>) -> KeyInput<'a> {
        KeyInput {
            owner: KeyOwner::Repository("weebo/app".into()),
            title: "ci".into(),
            read_only: true,
            source,
            namespace: Some("team-a"),
            current,
            rotate_nonce: None,
            last_rotation: None,
        }
    }

    #[tokio::test]
    async fn generated_key_lands_in_forgejo_and_the_secret() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let outcome = reconcile_key(input(&source, None), &fj, &secrets).await;
        let id = outcome.forgejo.unwrap().id;

        let secret = secrets.get("team-a/deploy").unwrap();
        assert!(secret["ssh-privatekey"].starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert_eq!(fj.key(id).unwrap().key, secret["ssh-publickey"]);
    }

    #[tokio::test]
    async fn steady_state_touches_nothing() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let current = reconcile_key(input(&source, None), &fj, &secrets)
            .await
            .forgejo;
        fj.clear_calls();
        let again = reconcile_key(input(&source, current.clone()), &fj, &secrets).await;
        assert_eq!(again.forgejo, current);
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn lost_secret_or_rotation_renews_the_pair() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let first = reconcile_key(input(&source, None), &fj, &secrets)
            .await
            .forgejo
            .unwrap();

        secrets.remove("team-a/deploy");
        let second = reconcile_key(input(&source, Some(first.clone())), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        assert_ne!(first.id, second.id);
        assert!(fj.key(first.id).is_none());

        let mut rotate = input(&source, Some(second.clone()));
        rotate.rotate_nonce = Some("2026-10".into());
        let rotated = reconcile_key(rotate, &fj, &secrets).await;
        assert_ne!(rotated.forgejo.unwrap().id, second.id);
        assert_eq!(rotated.last_rotation.as_deref(), Some("2026-10"));
    }

    #[tokio::test]
    async fn provided_key_ignores_comment_changes_but_recreates_on_access_change() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = KeySource {
            public_key: Some(ALICE_KEY.into()),
            secret_targets: vec![],
        };
        let first = reconcile_key(input(&source, None), &fj, &secrets)
            .await
            .forgejo
            .unwrap();

        let recommented = KeySource {
            public_key: Some(ALICE_KEY.replace(" alice", " alice@laptop")),
            secret_targets: vec![],
        };
        let same = reconcile_key(input(&recommented, Some(first.clone())), &fj, &secrets).await;
        assert_eq!(same.forgejo.unwrap().id, first.id);

        let mut write = input(&source, Some(first.clone()));
        write.read_only = false;
        let recreated = reconcile_key(write, &fj, &secrets).await.forgejo.unwrap();
        assert_ne!(recreated.id, first.id);
        assert!(!fj.key(recreated.id).unwrap().read_only);
    }

    #[tokio::test]
    async fn generated_key_without_targets_is_invalid() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = KeySource::default();
        let outcome = reconcile_key(input(&source, None), &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
    }
}
