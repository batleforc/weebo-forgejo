//! SSH keys — `ForgejoDeployKey` (on a repository) and `ForgejoUserKey`
//! (on a user) share this use-case. Keys are immutable in Forgejo: any
//! change of title, key or access deletes and recreates. Without a
//! `publicKey`, an ed25519 pair is generated and its private half written
//! to `secretTargets`; a missing target or a new rotation nonce generates
//! a fresh pair (a private key can't be read back), added before the old
//! key is deleted (the title alternates with `<title>-next`).

use std::collections::BTreeMap;

use api::common::DeletionPolicy;
use api::keys::KeySource;
use domain::error::ReasonCode;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use crate::ports::{ForgejoGateway, ForgejoRef, GatewayError, RemoteKey, SecretOwner, SecretStore};
use crate::use_cases::{CleanupGateway, Failure, Outcome, emit, gone_ok};

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
    /// The CR, as the owner of the emitted private key (its namespace is
    /// `None` for the cluster-scoped `ForgejoUserKey`).
    pub secret_owner: SecretOwner<'a>,
    pub current: Option<ForgejoRef>,
    /// Where `current` was created (the `forgejo.weebo.io/key-owner`
    /// record); `None` = unknown, assumed to be `owner`.
    pub created_on: Option<KeyOwner>,
    /// The `forgejo.weebo.io/rotate-secret` annotation.
    pub rotate_nonce: Option<String>,
    pub last_rotation: Option<String>,
    /// `status.secretPending`: the last generated pair never reached every
    /// target, which may hold a private key Forgejo no longer accepts.
    pub secret_pending: bool,
}

pub fn validate(source: &KeySource, owner: &SecretOwner<'_>) -> Result<(), Failure> {
    if source.public_key.is_none() && source.secret_targets.is_empty() {
        return Err(Failure::new(
            ReasonCode::InvalidSpec,
            "a generated key (no spec.publicKey) needs spec.secretTargets",
        ));
    }
    emit::check_targets(&source.secret_targets, owner)
}

pub async fn reconcile_key(
    input: KeyInput<'_>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Outcome {
    if let Err(f) = validate(input.source, &input.secret_owner) {
        return Outcome::failed(input.current, f);
    }

    let remote = match &input.current {
        Some(c) => match get(&input.owner, c.id, gateway).await {
            Ok(Some(r)) => Some(r),
            // Not on `owner`: if the ref moved to another repository/user
            // (and not merely a rename, which keeps the key where `get`
            // found it), the key may still be on the old one — delete it
            // there before creating its replacement. Only once `get` found
            // it there: the old name may belong to another account or
            // repository by now, which refuses a key that isn't its own.
            Ok(None) => {
                if let Some(old) = input.created_on.as_ref().filter(|o| **o != input.owner)
                    && let Err(e) = delete_if_held(old, c.id, gateway).await
                {
                    return Outcome::failed(input.current.clone(), e);
                }
                None
            }
            Err(e) => return Outcome::failed(input.current.clone(), e),
        },
        None => None,
    };

    // A generated pair is renewed when nothing exists yet, a rotation was
    // asked for, a target lost the private key, or the last pair never
    // reached every target.
    let generated = input.source.public_key.is_none();
    let rotation_requested =
        input.rotate_nonce.is_some() && input.rotate_nonce != input.last_rotation;
    let renew = generated
        && (remote.is_none()
            || rotation_requested
            || input.secret_pending
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

    // A renewed pair alternates between the title and its rotated one.
    let up_to_date = remote.as_ref().is_some_and(|r| {
        same_key(&r.key, &wanted_key)
            && (r.title == input.title || r.title == rotated_title(&input.title))
            && r.read_only == input.read_only
    });
    // A generated pair renewed while the old key exists: the new key is
    // added first (under the title the old one doesn't use), written to
    // every target, and only then is the old one deleted — consumers never
    // hold a key Forgejo already refuses.
    if !up_to_date && let (Some(old), Some((private, public))) = (&remote, &new_pair) {
        return rotate(&input, old, private, public, gateway, secrets).await;
    }
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
        if let Err(f) = emit::write_all(
            &input.source.secret_targets,
            &input.secret_owner,
            &data,
            secrets,
        )
        .await
        {
            // The key exists in Forgejo, but some targets may hold the
            // previous private key: renew the pair next time, whether the
            // targets exist or not.
            let mut failed = Outcome::failed(current, f);
            failed.secret_pending = Some(true);
            return failed;
        }
        outcome.secret_pending = Some(false);
        outcome.last_rotation = input.rotate_nonce.clone().or(input.last_rotation.clone());
    }
    outcome
}

/// The title a renewed key is added under while `title` is still taken
/// by the key it replaces.
pub fn rotated_title(title: &str) -> String {
    format!("{title}-next")
}

async fn rotate(
    input: &KeyInput<'_>,
    old: &RemoteKey,
    private: &str,
    public: &str,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Outcome {
    let title = if old.title == input.title {
        rotated_title(&input.title)
    } else {
        input.title.clone()
    };
    let added = match &input.owner {
        KeyOwner::Repository(repo) => {
            gateway
                .create_deploy_key(repo, &title, public, input.read_only)
                .await
        }
        KeyOwner::User(user) => gateway.create_user_key(user, &title, public).await,
    };
    let added = match added {
        Ok(added) => added,
        Err(e) => return Outcome::failed(input.current.clone(), e),
    };
    let data = BTreeMap::from([
        ("ssh-privatekey".to_string(), private.to_string()),
        ("ssh-publickey".to_string(), public.to_string()),
    ]);
    let targets = &input.source.secret_targets;
    if let Err(f) = emit::write_all(targets, &input.secret_owner, &data, secrets).await {
        // Keep the old key (consumers may still hold it); the new one's
        // private half is lost: delete it, renew next time.
        if let Err(e) = gone_ok(delete(&input.owner, added.id, gateway).await) {
            tracing::error!(error = %e, key = added.id, "deleting an unused renewed key failed: delete it by hand");
        }
        let mut failed = Outcome::failed(input.current.clone(), f);
        failed.secret_pending = Some(true);
        return failed;
    }
    let mut outcome = Outcome::synced(Some(added), "key renewed");
    // Every target holds the new key: the old one goes.
    if let Err(e) = gone_ok(delete(&input.owner, old.id, gateway).await) {
        let failure = Failure::from(e);
        let message = format!(
            "the renewed key is in place, but deleting the replaced key {} failed: it is \
             still accepted, delete it by hand: {}",
            old.id, failure.message
        );
        tracing::error!(key = old.id, "{message}");
        outcome = Outcome::failed(outcome.forgejo, Failure::new(failure.reason, message));
    }
    outcome.secret_pending = Some(false);
    outcome.last_rotation = input.rotate_nonce.clone().or(input.last_rotation.clone());
    outcome
}

/// `owners` are the repositories/users the key may be on (where it was
/// created, then the current ref, which differs after a rename): it is
/// deleted on the first one `get` finds it on. A key found on none of
/// them is already gone. Never deleting blind matters: a wrong owner
/// doesn't always answer `NotFound` (Forgejo refuses a key that isn't the
/// repository's or the user's, e.g. once another account took a renamed
/// one's name), and that refusal would hold the finalizer forever. Empty
/// only when the controller has no record at all (never resolved, nothing
/// recorded): the key can't be addressed, only the emitted secrets are
/// left to delete.
pub async fn cleanup_key(
    owners: &[KeyOwner],
    source: &KeySource,
    secret_owner: &SecretOwner<'_>,
    deletion_policy: DeletionPolicy,
    current: Option<&ForgejoRef>,
    gateway: CleanupGateway<'_>,
    secrets: &dyn SecretStore,
) -> Result<(), Failure> {
    if deletion_policy == DeletionPolicy::Delete
        && let Some(current) = current
        && !owners.is_empty()
    {
        let gateway = gateway.map_err(Clone::clone)?;
        for owner in owners {
            if delete_if_held(owner, current.id, gateway).await? {
                break;
            }
        }
    }
    if source.public_key.is_none() {
        emit::delete_all(&source.secret_targets, secret_owner, secrets).await?;
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

/// Deletes a user's key when the user is a site admin the namespace may
/// no longer hold credentials of, like a revoked token: the private key
/// handed out no longer pushes. `None` once it's gone (or there was
/// none); the key, still recorded, when deleting it failed.
pub async fn revoke_denied_key(
    gateway: &dyn ForgejoGateway,
    owners: &[KeyOwner],
    current: Option<ForgejoRef>,
) -> Option<ForgejoRef> {
    let c = current?;
    for owner in owners {
        match delete_if_held(owner, c.id, gateway).await {
            Ok(true) => return None,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, key = c.id, "deleting a denied site-admin key failed");
                return Some(c);
            }
        }
    }
    // Held by none of them: already gone.
    None
}

/// Deletes key `id` from `owner` if `owner` holds it; `Ok(false)` when it
/// doesn't.
async fn delete_if_held(
    owner: &KeyOwner,
    id: i64,
    gateway: &dyn ForgejoGateway,
) -> Result<bool, GatewayError> {
    if get(owner, id, gateway).await?.is_none() {
        return Ok(false);
    }
    gone_ok(delete(owner, id, gateway).await)?;
    Ok(true)
}

async fn any_target_missing(
    input: &KeyInput<'_>,
    secrets: &dyn SecretStore,
) -> Result<bool, Failure> {
    emit::any_missing(&input.source.secret_targets, &input.secret_owner, secrets).await
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
            secret_owner: SecretOwner::namespaced("ForgejoDeployKey", "team-a", "ci"),
            current,
            created_on: None,
            rotate_nonce: None,
            last_rotation: None,
            secret_pending: false,
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

    #[tokio::test]
    async fn moved_ref_deletes_the_key_on_the_old_owner() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let first = reconcile_key(input(&source, None), &fj, &secrets)
            .await
            .forgejo
            .unwrap();

        let mut moved = input(&source, Some(first.clone()));
        moved.owner = KeyOwner::Repository("weebo/other".into());
        moved.created_on = Some(KeyOwner::Repository("weebo/app".into()));
        let outcome = reconcile_key(moved, &fj, &secrets).await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        let second = outcome.forgejo.unwrap();
        assert!(fj.key(first.id).is_none(), "old repository's key deleted");
        assert_eq!(
            fj.calls(),
            vec![
                "create_deploy_key weebo/app ci".to_string(),
                format!("delete_deploy_key weebo/app {}", first.id),
                "create_deploy_key weebo/other ci".to_string(),
            ]
        );
        assert!(fj.key(second.id).is_some());
    }

    #[tokio::test]
    async fn renamed_owner_keeps_its_key() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let first = reconcile_key(input(&source, None), &fj, &secrets)
            .await
            .forgejo;
        fj.clear_calls();
        // Recorded under a name the key no longer answers to, but `get`
        // finds it on the current owner: nothing to move.
        let mut renamed = input(&source, first.clone());
        renamed.created_on = Some(KeyOwner::Repository("weebo/old-name".into()));
        let outcome = reconcile_key(renamed, &fj, &secrets).await;
        assert_eq!(outcome.forgejo, first);
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn cleanup_falls_back_to_the_next_owner() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let created = reconcile_key(input(&source, None), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        let owners = [
            KeyOwner::Repository("weebo/old-name".into()),
            KeyOwner::Repository("weebo/app".into()),
        ];
        // The recorded name now belongs to another repository, which would
        // refuse the key outright: it is only deleted where it is.
        fj.clear_calls();
        cleanup_key(
            &owners,
            &source,
            &SecretOwner::namespaced("ForgejoDeployKey", "team-a", "ci"),
            DeletionPolicy::Delete,
            Some(&created),
            Ok(&fj),
            &secrets,
        )
        .await
        .unwrap();
        assert!(fj.key(created.id).is_none());
        assert_eq!(
            fj.calls(),
            vec![format!("delete_deploy_key weebo/app {}", created.id)]
        );
    }

    #[tokio::test]
    async fn cleanup_of_a_key_gone_everywhere_succeeds() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let created = reconcile_key(input(&source, None), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        fj.remove_key(created.id);
        fj.clear_calls();
        let owners = [
            KeyOwner::Repository("weebo/old-name".into()),
            KeyOwner::Repository("weebo/app".into()),
        ];
        cleanup_key(
            &owners,
            &source,
            &SecretOwner::namespaced("ForgejoDeployKey", "team-a", "ci"),
            DeletionPolicy::Delete,
            Some(&created),
            Ok(&fj),
            &secrets,
        )
        .await
        .unwrap();
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn key_gone_from_a_taken_over_old_owner_is_recreated() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let first = reconcile_key(input(&source, None), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        // Deleted out of band; the recorded owner name is someone else's
        // now and would refuse a blind delete.
        fj.remove_key(first.id);
        fj.clear_calls();
        let mut moved = input(&source, Some(first.clone()));
        moved.owner = KeyOwner::Repository("weebo/renamed".into());
        moved.created_on = Some(KeyOwner::Repository("weebo/app".into()));
        let outcome = reconcile_key(moved, &fj, &secrets).await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        assert_eq!(
            fj.calls(),
            vec!["create_deploy_key weebo/renamed ci".to_string()]
        );
    }

    /// An unresolvable instance only blocks a cleanup that must call
    /// Forgejo: an orphaned key still has its secret removed.
    #[tokio::test]
    async fn cleanup_needs_the_gateway_only_to_delete() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let created = reconcile_key(input(&source, None), &fj, &secrets)
            .await
            .forgejo
            .unwrap();
        let owner = KeyOwner::Repository("weebo/app".into());
        let unresolved = Failure::new(ReasonCode::InstanceNotFound, "gone");

        let deleting = cleanup_key(
            std::slice::from_ref(&owner),
            &source,
            &SecretOwner::namespaced("ForgejoDeployKey", "team-a", "ci"),
            DeletionPolicy::Delete,
            Some(&created),
            Err(&unresolved),
            &secrets,
        )
        .await;
        assert_eq!(deleting, Err(unresolved.clone()));
        assert!(fj.key(created.id).is_some());

        cleanup_key(
            std::slice::from_ref(&owner),
            &source,
            &SecretOwner::namespaced("ForgejoDeployKey", "team-a", "ci"),
            DeletionPolicy::Orphan,
            Some(&created),
            Err(&unresolved),
            &secrets,
        )
        .await
        .unwrap();
        assert!(fj.key(created.id).is_some());
        assert!(secrets.get("team-a/deploy").is_none());
    }

    /// A pair whose write failed is renewed even if every target exists
    /// (holding the previous private key).
    #[tokio::test]
    async fn a_failed_write_renews_the_pair_next_time() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let source = generated();
        let first = reconcile_key(input(&source, None), &fj, &secrets).await;
        let old_private = secrets.get("team-a/deploy").unwrap()["ssh-privatekey"].clone();

        secrets.fail_writes(true);
        let mut rotate = input(&source, first.forgejo.clone());
        rotate.rotate_nonce = Some("1".into());
        let failed = reconcile_key(rotate, &fj, &secrets).await;
        assert_eq!(failed.secret_pending, Some(true));

        secrets.fail_writes(false);
        let mut retry = input(&source, failed.forgejo.clone());
        retry.rotate_nonce = Some("1".into());
        retry.last_rotation = Some("1".into());
        retry.secret_pending = true;
        let fixed = reconcile_key(retry, &fj, &secrets).await;
        assert!(fixed.ready.is_ok(), "{fixed:?}");
        assert_eq!(fixed.secret_pending, Some(false));
        let secret = secrets.get("team-a/deploy").unwrap();
        assert_ne!(secret["ssh-privatekey"], old_private);
        assert_eq!(
            fj.key(fixed.forgejo.unwrap().id).unwrap().key,
            secret["ssh-publickey"]
        );
    }

    #[tokio::test]
    async fn targets_in_another_namespace_are_refused() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut source = generated();
        source.secret_targets[0].namespace = Some("kube-system".into());
        let outcome = reconcile_key(input(&source, None), &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::CrossNamespaceReference);
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    /// A renewed pair is added before the old key goes, and the old key
    /// stays when the new one can't be handed out.
    #[tokio::test]
    async fn a_renewed_pair_is_added_before_the_old_key_goes() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        fj.insert_user("ci-bot");
        let source = KeySource {
            public_key: None,
            secret_targets: vec![api::common::SecretTarget {
                backend: Default::default(),
                name: "ssh".into(),
                namespace: None,
                path: None,
            }],
        };
        let input = |current, nonce: Option<&str>| KeyInput {
            owner: KeyOwner::User("ci-bot".into()),
            title: "ci".into(),
            read_only: false,
            source: &source,
            secret_owner: SecretOwner::namespaced("ForgejoUserKey", "team-a", "k"),
            current,
            created_on: None,
            rotate_nonce: nonce.map(String::from),
            last_rotation: None,
            secret_pending: false,
        };
        let first = reconcile_key(input(None, None), &fj, &secrets).await;
        let old = first.forgejo.clone().unwrap();
        let private = secrets.get("team-a/ssh").unwrap()["ssh-privatekey"].clone();

        // The write fails: the old key and its secret stay.
        secrets.fail_writes(true);
        let failed = reconcile_key(input(Some(old.clone()), Some("1")), &fj, &secrets).await;
        assert_eq!(failed.secret_pending, Some(true));
        assert_eq!(failed.forgejo, Some(old.clone()));
        assert!(fj.get_user_key("ci-bot", old.id).await.unwrap().is_some());
        secrets.fail_writes(false);

        fj.clear_calls();
        let renewed = reconcile_key(input(Some(old.clone()), Some("1")), &fj, &secrets).await;
        assert!(renewed.ready.is_ok(), "{renewed:?}");
        let new = renewed.forgejo.unwrap();
        assert_ne!(new.id, old.id);
        let calls = fj.calls();
        let added = calls.iter().position(|c| c.starts_with("create_user_key"));
        let deleted = calls.iter().position(|c| c.starts_with("delete_user_key"));
        assert!(added.is_some() && added < deleted, "{calls:?}");
        assert!(fj.get_user_key("ci-bot", old.id).await.unwrap().is_none());
        let key = fj.get_user_key("ci-bot", new.id).await.unwrap().unwrap();
        assert_eq!(key.title, "ci-next");
        assert_ne!(
            secrets.get("team-a/ssh").unwrap()["ssh-privatekey"],
            private
        );
    }

    /// A user's key is deleted once its account is a denied site admin —
    /// found under the login it was created on or the current one — and
    /// kept (still recorded) when deleting it fails.
    #[tokio::test]
    async fn a_denied_admin_key_is_deleted() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        fj.insert_user("ci-bot");
        let source = generated();
        let input = KeyInput {
            owner: KeyOwner::User("ci-bot".into()),
            title: "ci".into(),
            read_only: false,
            source: &source,
            secret_owner: SecretOwner::namespaced("ForgejoUserKey", "team-a", "k"),
            current: None,
            created_on: None,
            rotate_nonce: None,
            last_rotation: None,
            secret_pending: false,
        };
        let key = reconcile_key(input, &fj, &secrets).await.forgejo.unwrap();
        let owners = [
            KeyOwner::User("old-login".into()),
            KeyOwner::User("ci-bot".into()),
        ];

        fj.fail_call("delete_user_key", GatewayError::Unreachable("down".into()));
        let kept = revoke_denied_key(&fj, &owners, Some(key.clone())).await;
        assert_eq!(kept, Some(key.clone()));
        assert!(fj.get_user_key("ci-bot", key.id).await.unwrap().is_some());

        assert_eq!(
            revoke_denied_key(&fj, &owners, Some(key.clone())).await,
            None
        );
        assert!(fj.get_user_key("ci-bot", key.id).await.unwrap().is_none());
        // Gone already, or nothing recorded: nothing to keep.
        assert_eq!(revoke_denied_key(&fj, &owners, Some(key)).await, None);
        assert_eq!(revoke_denied_key(&fj, &owners, None).await, None);
    }
}
