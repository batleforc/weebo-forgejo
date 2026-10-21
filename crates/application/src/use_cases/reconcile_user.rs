//! `ForgejoUser`: the three modes of `.prompt/plan.md`, "ForgejoUser : trois
//! modes". Managed users follow attempt-create-first; a rename in `spec`
//! renames in place (the old login comes from `status.forgejoName`).

use std::collections::BTreeMap;

use api::common::ManagementPolicy;
use api::user::ForgejoUserSpec;
use domain::error::ReasonCode;
use rand::Rng;
use rand::distr::Alphanumeric;

use crate::ports::{
    DesiredUser, ForgejoGateway, ForgejoRef, GatewayError, RemoteUser, SecretOwner, SecretStore,
    UserPatch,
};
use crate::use_cases::{CleanupGateway, Drift, Failure, Outcome, RemoteWrite, deleted, emit};

pub const KIND: &str = "ForgejoUser";

/// The CR `namespace/cr_name`, as the owner of the password secrets it
/// emits — and of those it wrote under `previous_owner` before it moved
/// into a namespace (`migrate-to-namespaced`).
fn secret_owner<'a>(
    namespace: &'a str,
    cr_name: &'a str,
    previous_owner: Option<&'a str>,
) -> SecretOwner<'a> {
    SecretOwner::namespaced(KIND, namespace, cr_name).formerly(previous_owner)
}

pub struct UserInput<'a> {
    pub spec: &'a ForgejoUserSpec,
    pub namespace: &'a str,
    pub cr_name: &'a str,
    /// The owner id of its secrets before it moved into a namespace (the
    /// `previous-owner` annotation).
    pub previous_owner: Option<&'a str>,
    /// From `status.forgejoId`/`status.forgejoName`.
    pub current: Option<ForgejoRef>,
    /// `metadata.generation != status.observedGeneration`: re-sends the
    /// fields Forgejo never returns (and so can't be diffed), those the
    /// spec sets.
    pub spec_changed: bool,
    /// `status.secretPending`: the last generated password never reached
    /// every target, which may still hold an outdated one.
    pub secret_pending: bool,
    /// `status.passwordEmitted`: a generated password was handed out.
    pub password_emitted: bool,
}

pub async fn reconcile_user(
    input: UserInput<'_>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Outcome {
    let spec = input.spec;
    if spec.management_policy == ManagementPolicy::Observe {
        return observe(spec, gateway).await;
    }
    let owner = secret_owner(input.namespace, input.cr_name, input.previous_owner);
    if let Err(f) = validate(spec, &owner) {
        return Outcome::failed(input.current, f);
    }

    let (remote, renamed) = match locate(spec, input.current.as_ref(), gateway).await {
        Ok(r) => r,
        Err(f) => return Outcome::failed(input.current, f),
    };

    let Some(remote) = remote else {
        return create(spec, &owner, gateway, secrets).await;
    };
    let current = Some(ForgejoRef {
        id: remote.id,
        name: remote.login.clone(),
    });

    let desired = desired_user(spec);
    let (mut drift, mut patch) = user_differs(&desired, &remote);
    drift.note("username", renamed);
    if input.spec_changed {
        patch.allow_create_organization = desired.allow_create_organization;
        patch.max_repo_creation = desired.max_repo_creation;
    }

    // A password can't be read back: a vanished target (or one a failed
    // write left outdated) means the only way to hand one out again is to
    // set a new one.
    let mut new_password = None;
    if spec.emits_password() {
        match emit::any_missing(&spec.secret_targets, &owner, secrets).await {
            Ok(false) if !input.secret_pending => {}
            Ok(_) => {
                let password = generate_password();
                patch.password = Some(password.clone());
                patch.must_change_password = Some(desired.must_change_password);
                new_password = Some(password);
            }
            Err(f) => return Outcome::failed(current, f),
        }
    }
    // Turned into a bot or an external account: the password handed out
    // before must stop working. Only a password the operator handed out —
    // an adopted account's own password is never touched.
    let revoke_password = !spec.emits_password() && input.password_emitted;
    if revoke_password {
        if spec.is_local() {
            patch.password = Some(generate_password());
            patch.must_change_password = Some(desired.must_change_password);
        }
        if let Err(f) = emit::delete_all(&spec.secret_targets, &owner, secrets).await {
            return Outcome::failed(current, f);
        }
    }

    let wrote = !patch.is_empty();
    if wrote && let Err(e) = gateway.edit_user(&remote.login, &patch).await {
        return Outcome::failed(current, source_failure(spec, e));
    }
    let mut outcome = Outcome::synced(current.clone(), "user synced");
    // A new password or a spec change of the unreadable fields is a write
    // without a drifted field: counted, not announced.
    if wrote || !drift.is_empty() {
        outcome = outcome.corrected(drift);
    }
    if let Some(password) = new_password {
        if let Err(f) = write_password(spec, &owner, &password, gateway, secrets).await {
            return pending(current, f);
        }
        outcome.secret_pending = Some(false);
    }
    // Recorded on every sync of an emitting user (users created before the
    // field existed included), cleared once replaced.
    if spec.emits_password() {
        outcome.password_emitted = Some(true);
    } else if revoke_password {
        outcome.password_emitted = Some(false);
    }
    outcome
}

/// Deletes the account only for `deletionPolicy: Delete` (never purged),
/// and the emitted password secrets in every case. `Ok(true)`: the account
/// was deleted by this call.
///
/// The account is addressed by its id, never by the stored login: after a
/// rename outside the operator, another account may hold the old login.
pub async fn cleanup_user(
    spec: &ForgejoUserSpec,
    namespace: &str,
    cr_name: &str,
    previous_owner: Option<&str>,
    current: Option<&ForgejoRef>,
    gateway: CleanupGateway<'_>,
    secrets: &dyn SecretStore,
) -> Result<bool, Failure> {
    if spec.management_policy == ManagementPolicy::Observe {
        return Ok(false);
    }
    let mut removed = false;
    if spec.deletion_policy == api::common::DeletionPolicy::Delete
        && let Some(current) = current
    {
        let gateway = gateway.map_err(Clone::clone)?;
        // `None`: already deleted.
        if let Some(login) = gateway.user_login(current.id).await? {
            removed = deleted(gateway.delete_user(&login).await)?;
        }
    }
    if spec.is_local() {
        emit::delete_all(
            &spec.secret_targets,
            &secret_owner(namespace, cr_name, previous_owner),
            secrets,
        )
        .await?;
    }
    Ok(removed)
}

async fn observe(spec: &ForgejoUserSpec, gateway: &dyn ForgejoGateway) -> Outcome {
    match gateway.get_user(&spec.username).await {
        Ok(Some(user)) => Outcome::synced(
            Some(ForgejoRef {
                id: user.id,
                name: user.login,
            }),
            "user observed",
        ),
        Ok(None) => Outcome::failed(
            None,
            Failure::new(
                ReasonCode::UserNotFound,
                format!(
                    "user {:?} does not exist in Forgejo yet (an OIDC user appears at first login)",
                    spec.username
                ),
            ),
        ),
        Err(e) => Outcome::failed(None, e),
    }
}

fn validate(spec: &ForgejoUserSpec, owner: &SecretOwner<'_>) -> Result<(), Failure> {
    let invalid = |m: &str| Err(Failure::new(ReasonCode::InvalidSpec, m));
    if spec.email.is_none() {
        return invalid("spec.email is required unless managementPolicy is Observe");
    }
    if spec.emits_password() && spec.secret_targets.is_empty() {
        return invalid(
            "a local, non-bot user needs spec.secretTargets to receive its generated password",
        );
    }
    emit::check_targets(&spec.secret_targets, owner)
}

/// Finds the remote user this CR owns — by id: a rename outside the
/// operator moves the account, and its old login may belong to someone
/// else by now — renaming it back to `spec.username` when they differ.
/// `Ok(None)` means nothing is owned yet, or it was deleted out of band,
/// in which case the CR (authoritative) recreates it.
/// Also says whether the account was renamed to find it.
async fn locate(
    spec: &ForgejoUserSpec,
    current: Option<&ForgejoRef>,
    gateway: &dyn ForgejoGateway,
) -> Result<(Option<RemoteUser>, bool), Failure> {
    let Some(current) = current else {
        return Ok((None, false));
    };
    let Some(login) = gateway.user_login(current.id).await? else {
        return Ok((None, false));
    };
    let mut renamed = false;
    if login != spec.username {
        match gateway.rename_user(&login, &spec.username).await {
            Ok(()) => renamed = true,
            Err(GatewayError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let remote = gateway
        .get_user(&spec.username)
        .await?
        // A same-name account with another id isn't ours (deleted and
        // recreated by someone else): surface the collision via create.
        .filter(|u| u.id == current.id);
    Ok((remote, renamed))
}

async fn create(
    spec: &ForgejoUserSpec,
    owner: &SecretOwner<'_>,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Outcome {
    let mut desired = desired_user(spec);
    // Forgejo requires a password for every local account, bots included;
    // a bot's is generated and discarded — unusable by anyone.
    let password = spec.is_local().then(generate_password);
    desired.password = password.clone();

    let created = match gateway.create_user(&desired).await {
        Ok(r) => r,
        Err(e) => return Outcome::failed(None, source_failure(spec, e)),
    };
    let current = Some(created.clone());

    if spec.emits_password()
        && let Some(password) = &password
        && let Err(f) = write_password(spec, owner, password, gateway, secrets).await
    {
        // Persisting the id matters most here: the next reconcile resets
        // the password instead of failing on a second create.
        return pending(current, f).wrote(RemoteWrite::Created);
    }

    // admin, active, prohibit_login & co. only exist on edit: all of them,
    // never the password just set.
    desired.password = None;
    if let Err(e) = gateway
        .edit_user(&created.name, &UserPatch::full(&desired))
        .await
    {
        return Outcome::failed(current, e).wrote(RemoteWrite::Created);
    }
    let mut outcome = Outcome::synced(current, "user created").wrote(RemoteWrite::Created);
    if spec.emits_password() {
        outcome.secret_pending = Some(false);
        outcome.password_emitted = Some(true);
    }
    outcome
}

/// Forgejo refuses an unknown `source_id` with a generic 422 "login source
/// does not exist": surfaced as `LoginSourceNotFound`.
fn source_failure(spec: &ForgejoUserSpec, e: GatewayError) -> Failure {
    match &e {
        GatewayError::Api { message: m, .. }
            if spec.login_source_id.is_some()
                && m.to_lowercase().contains("login source does not exist") =>
        {
            Failure::new(
                ReasonCode::LoginSourceNotFound,
                format!(
                    "spec.loginSourceId {} matches no authentication source in Forgejo",
                    spec.login_source_id.unwrap_or_default()
                ),
            )
        }
        _ => e.into(),
    }
}

/// A failed password write: the targets may hold an outdated password, so
/// the next reconcile sets a new one even if they all exist.
fn pending(current: Option<ForgejoRef>, f: Failure) -> Outcome {
    let mut outcome = Outcome::failed(current, f);
    outcome.secret_pending = Some(true);
    // Some targets may hold it already.
    outcome.password_emitted = Some(true);
    outcome
}

fn desired_user(spec: &ForgejoUserSpec) -> DesiredUser {
    let external = spec.login_source_id.is_some();
    DesiredUser {
        username: spec.username.clone(),
        email: spec.email.clone().unwrap_or_default(),
        full_name: spec.full_name.clone(),
        password: None,
        must_change_password: spec.emits_password() && spec.must_change_password.unwrap_or(true),
        source_id: spec.login_source_id,
        login_name: external.then(|| {
            spec.login_name
                .clone()
                .unwrap_or_else(|| spec.username.clone())
        }),
        admin: spec.admin,
        restricted: spec.restricted,
        visibility: spec.visibility.as_str(),
        active: spec.active,
        prohibit_login: spec.prohibit_login,
        allow_create_organization: spec.allow_create_organization,
        max_repo_creation: spec.max_repo_creation,
    }
}

/// The readable fields of `r` that differ from `d`, and the PATCH carrying
/// only them — never a password, nor the fields Forgejo doesn't return
/// (`allow_create_organization`, `max_repo_creation`: the caller adds them
/// on a spec change).
fn user_differs(d: &DesiredUser, r: &RemoteUser) -> (Drift, UserPatch) {
    let mut p = UserPatch {
        password: None,
        must_change_password: None,
        allow_create_organization: None,
        max_repo_creation: None,
        ..UserPatch::full(d)
    };
    let mut drift = Drift::default();
    drift.keep("email", &mut p.email, &r.email);
    drift.keep("full_name", &mut p.full_name, &r.full_name);
    drift.keep("admin", &mut p.admin, &r.admin);
    drift.keep("restricted", &mut p.restricted, &r.restricted);
    drift.keep_with("visibility", &mut p.visibility, &r.visibility, |d, r| {
        *d == r.as_str()
    });
    drift.keep("active", &mut p.active, &r.active);
    drift.keep("prohibit_login", &mut p.prohibit_login, &r.prohibit_login);
    drift.keep_with("login_source", &mut p.login_source, r, |(id, name), r| {
        *id == r.source_id && *name == r.login_name
    });
    (drift, p)
}

async fn write_password(
    spec: &ForgejoUserSpec,
    owner: &SecretOwner<'_>,
    password: &str,
    gateway: &dyn ForgejoGateway,
    secrets: &dyn SecretStore,
) -> Result<(), Failure> {
    let data = BTreeMap::from([
        ("FORGEJO_USERNAME".to_string(), spec.username.clone()),
        ("FORGEJO_PASSWORD".to_string(), password.to_string()),
        ("FORGEJO_URL".to_string(), gateway.web_url().to_string()),
    ]);
    emit::write_all(&spec.secret_targets, owner, &data, secrets).await
}

/// 32 alphanumerics: ~190 bits, and passes any `PASSWORD_COMPLEXITY`
/// setting short of requiring symbols.
fn generate_password() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use api::common::{DeletionPolicy, SecretTarget, Visibility};
    use api::instance::SecretStoreBackend;

    use super::*;
    use crate::test_support::{Edit, FakeForgejo, FakeSecretStore};

    fn target() -> SecretTarget {
        SecretTarget {
            backend: SecretStoreBackend::Kubernetes,
            name: "alice-forgejo".into(),
            namespace: Some("team-a".into()),
            path: None,
        }
    }

    fn local(username: &str) -> ForgejoUserSpec {
        ForgejoUserSpec {
            instance_ref: None,
            shared_with: None,
            username: username.into(),
            management_policy: ManagementPolicy::Manage,
            email: Some(format!("{username}@example.com")),
            full_name: None,
            login_source_id: None,
            login_name: None,
            bot: false,
            prohibit_login: false,
            must_change_password: None,
            admin: false,
            restricted: false,
            visibility: Visibility::Public,
            active: true,
            allow_create_organization: None,
            max_repo_creation: None,
            secret_targets: vec![target()],
            deletion_policy: DeletionPolicy::Orphan,
        }
    }

    async fn run(
        spec: &ForgejoUserSpec,
        current: Option<ForgejoRef>,
        fj: &FakeForgejo,
        secrets: &FakeSecretStore,
    ) -> Outcome {
        let input = UserInput {
            spec,
            namespace: "team-a",
            cr_name: "alice",
            previous_owner: None,
            current,
            spec_changed: false,
            secret_pending: false,
            password_emitted: false,
        };
        reconcile_user(input, fj, secrets).await
    }

    #[tokio::test]
    async fn local_user_is_created_with_its_password_emitted() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let outcome = run(&local("alice"), None, &fj, &secrets).await;

        let created = outcome.forgejo.clone().expect("id persisted");
        assert_eq!(created.name, "alice");
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        let secret = secrets.get("team-a/alice-forgejo").expect("secret written");
        let user = fj.user("alice").unwrap();
        assert_eq!(user.password.as_ref(), secret.get("FORGEJO_PASSWORD"));
        assert!(user.must_change_password);
        assert_eq!(secret["FORGEJO_URL"], "https://git.example.com");
    }

    #[tokio::test]
    async fn second_reconcile_without_changes_does_not_patch() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await.forgejo;
        fj.clear_calls();

        let outcome = run(&spec, created, &fj, &secrets).await;
        assert!(outcome.ready.is_ok());
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn drift_is_patched_back() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await.forgejo;

        spec.admin = true;
        fj.clear_calls();
        let outcome = run(&spec, created, &fj, &secrets).await;
        assert!(outcome.ready.is_ok());
        assert!(fj.user("alice").unwrap().remote.admin);
        // Only the drifted field: never the password, nor anything else.
        assert_eq!(
            fj.edits(),
            [Edit::User(UserPatch {
                admin: Some(true),
                ..Default::default()
            })]
        );
        assert_eq!(outcome.drift.fields(), ["admin"]);
    }

    #[tokio::test]
    async fn a_spec_change_resends_only_the_unreadable_fields_it_sets() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await;
        assert_eq!(created.write, Some(RemoteWrite::Created));
        spec.max_repo_creation = Some(3);
        fj.clear_calls();
        let input = UserInput {
            spec: &spec,
            namespace: "team-a",
            cr_name: "alice",
            previous_owner: None,
            current: created.forgejo,
            spec_changed: true,
            secret_pending: false,
            password_emitted: true,
        };
        let outcome = reconcile_user(input, &fj, &secrets).await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        assert_eq!(
            fj.edits(),
            [Edit::User(UserPatch {
                max_repo_creation: Some(3),
                ..Default::default()
            })]
        );
        // A write, but no field Forgejo showed as drifted.
        assert_eq!(outcome.write, Some(RemoteWrite::Drift));
        assert!(outcome.drift.is_empty());
    }

    #[tokio::test]
    async fn a_deleted_secret_target_resets_the_password() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await.forgejo;
        let first = fj.user("alice").unwrap().password;
        secrets.remove("team-a/alice-forgejo");

        run(&spec, created, &fj, &secrets).await;
        let user = fj.user("alice").unwrap();
        assert_ne!(user.password, first);
        assert_eq!(
            user.password.as_ref(),
            secrets
                .get("team-a/alice-forgejo")
                .unwrap()
                .get("FORGEJO_PASSWORD")
        );
    }

    #[tokio::test]
    async fn failed_secret_write_still_persists_the_created_id() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        secrets.fail_writes(true);
        let outcome = run(&local("alice"), None, &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::SecretTargetFailed);
        assert!(
            outcome.forgejo.is_some(),
            "a second create must never happen"
        );
    }

    #[tokio::test]
    async fn pending_write_resets_the_password_even_if_targets_exist() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await.forgejo;
        let first = fj.user("alice").unwrap().password;

        // A reset whose write fails leaves the target with the old password.
        secrets.remove("team-a/alice-forgejo");
        secrets.fail_writes(true);
        let failed = run(&spec, created.clone(), &fj, &secrets).await;
        assert_eq!(failed.secret_pending, Some(true));
        secrets.fail_writes(false);
        secrets
            .write(
                &target(),
                &secret_owner("team-a", "alice", None),
                &BTreeMap::from([("FORGEJO_PASSWORD".into(), "stale".into())]),
            )
            .await
            .unwrap();

        let input = UserInput {
            spec: &spec,
            namespace: "team-a",
            cr_name: "alice",
            previous_owner: None,
            current: created,
            spec_changed: false,
            secret_pending: true,
            password_emitted: false,
        };
        let fixed = reconcile_user(input, &fj, &secrets).await;
        assert!(fixed.ready.is_ok(), "{fixed:?}");
        assert_eq!(fixed.secret_pending, Some(false));
        let user = fj.user("alice").unwrap();
        assert_ne!(user.password, first);
        assert_eq!(
            user.password.as_ref(),
            secrets
                .get("team-a/alice-forgejo")
                .unwrap()
                .get("FORGEJO_PASSWORD")
        );
    }

    #[tokio::test]
    async fn taken_login_is_never_adopted() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        fj.insert_user("alice");
        let outcome = run(&local("alice"), None, &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::ForgejoObjectAlreadyExists);
        assert_eq!(outcome.forgejo, None);
    }

    #[tokio::test]
    async fn renaming_keeps_the_same_account() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await.forgejo.unwrap();

        spec.username = "alicia".into();
        let outcome = run(&spec, Some(created.clone()), &fj, &secrets).await;
        assert_eq!(outcome.forgejo.unwrap().id, created.id);
        assert!(fj.user("alice").is_none());
        assert!(fj.user("alicia").is_some());
    }

    #[tokio::test]
    async fn external_user_has_no_password_and_links_its_source() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("bob");
        spec.login_source_id = Some(2);
        spec.secret_targets.clear();

        let outcome = run(&spec, None, &fj, &secrets).await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        let user = fj.user("bob").unwrap();
        assert_eq!(user.password, None);
        assert_eq!(user.remote.source_id, 2);
        assert_eq!(user.remote.login_name, "bob");
    }

    #[tokio::test]
    async fn bot_gets_an_unknown_password_and_emits_nothing() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("ci-bot");
        spec.bot = true;
        spec.secret_targets.clear();

        let outcome = run(&spec, None, &fj, &secrets).await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        let user = fj.user("ci-bot").unwrap();
        assert!(user.password.is_some(), "Forgejo requires one");
        assert!(!user.must_change_password);
        // Forgejo would refuse its API tokens otherwise.
        assert!(!user.remote.prohibit_login);
        assert!(secrets.get("team-a/alice-forgejo").is_none());
    }

    #[tokio::test]
    async fn local_user_without_targets_is_invalid() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("alice");
        spec.secret_targets.clear();
        let outcome = run(&spec, None, &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
        assert!(fj.calls().is_empty());
    }

    #[tokio::test]
    async fn observed_user_waits_until_it_exists() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("carol");
        spec.management_policy = ManagementPolicy::Observe;
        spec.email = None;

        let outcome = run(&spec, None, &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::UserNotFound);

        let id = fj.insert_user("carol");
        let outcome = run(&spec, None, &fj, &secrets).await;
        assert_eq!(outcome.forgejo.unwrap().id, id);
        assert!(fj.calls().is_empty(), "observe never mutates");
    }

    #[tokio::test]
    async fn out_of_band_deletion_is_recreated() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await.forgejo;
        fj.remove_user("alice");

        let outcome = run(&spec, created.clone(), &fj, &secrets).await;
        assert!(outcome.ready.is_ok());
        assert_ne!(outcome.forgejo, created);
    }

    #[tokio::test]
    async fn cleanup_orphans_by_default_but_drops_the_secret() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await.forgejo;

        cleanup_user(
            &spec,
            "team-a",
            "alice",
            None,
            created.as_ref(),
            Ok(&fj),
            &secrets,
        )
        .await
        .unwrap();
        assert!(fj.user("alice").is_some());
        assert!(secrets.get("team-a/alice-forgejo").is_none());
    }

    #[tokio::test]
    async fn cleanup_deletes_with_delete_policy() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("alice");
        spec.deletion_policy = DeletionPolicy::Delete;
        let created = run(&spec, None, &fj, &secrets).await.forgejo;

        cleanup_user(
            &spec,
            "team-a",
            "alice",
            None,
            created.as_ref(),
            Ok(&fj),
            &secrets,
        )
        .await
        .unwrap();
        assert!(fj.user("alice").is_none());
    }

    /// Renamed in the UI: renamed back (found by id), never recreated next
    /// to the original with a fresh password.
    #[tokio::test]
    async fn a_user_renamed_out_of_band_is_renamed_back() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await.forgejo.unwrap();
        fj.rename_user("alice", "alice2").await.unwrap();
        let again = run(&spec, Some(created.clone()), &fj, &secrets).await;
        assert!(again.ready.is_ok(), "{again:?}");
        assert_eq!(again.forgejo.as_ref().map(|r| r.id), Some(created.id));
        assert!(fj.get_user("alice2").await.unwrap().is_none());
        assert_eq!(fj.get_user("alice").await.unwrap().unwrap().id, created.id);
    }

    /// Deleted by id: after an out-of-band rename, another account holding
    /// the old login is left alone.
    #[tokio::test]
    async fn cleanup_deletes_by_id_not_by_stored_login() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("alice");
        spec.deletion_policy = DeletionPolicy::Delete;
        let created = run(&spec, None, &fj, &secrets).await.forgejo.unwrap();
        fj.rename_user("alice", "alice2").await.unwrap();
        let other = run(&local("alice"), None, &fj, &FakeSecretStore::default())
            .await
            .forgejo
            .unwrap();
        cleanup_user(
            &spec,
            "team-a",
            "alice",
            None,
            Some(&created),
            Ok(&fj),
            &secrets,
        )
        .await
        .unwrap();
        assert!(
            fj.get_user("alice2").await.unwrap().is_none(),
            "ours is gone"
        );
        assert_eq!(fj.get_user("alice").await.unwrap().unwrap().id, other.id);
    }

    /// A target holding someone else's Secret is never overwritten.
    #[tokio::test]
    async fn a_foreign_secret_target_is_refused() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        secrets.insert_foreign(
            "team-a/alice-forgejo",
            "someone-else",
            BTreeMap::from([("db".to_string(), "keep".to_string())]),
        );
        let outcome = run(&local("alice"), None, &fj, &secrets).await;
        assert_eq!(outcome.reason(), ReasonCode::SecretTargetFailed);
        assert_eq!(secrets.get("team-a/alice-forgejo").unwrap()["db"], "keep");
    }

    /// Turned into a bot: the handed-out password stops working and its
    /// secret goes.
    #[tokio::test]
    async fn becoming_a_bot_revokes_the_emitted_password() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let mut spec = local("alice");
        let created = run(&spec, None, &fj, &secrets).await;
        assert_eq!(created.password_emitted, Some(true));
        assert!(secrets.get("team-a/alice-forgejo").is_some());
        let handed_out = fj.user("alice").unwrap().password;
        spec.bot = true;
        fj.clear_calls();
        let input = UserInput {
            spec: &spec,
            namespace: "team-a",
            cr_name: "alice",
            previous_owner: None,
            current: created.forgejo,
            spec_changed: true,
            secret_pending: false,
            password_emitted: true,
        };
        let outcome = reconcile_user(input, &fj, &secrets).await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        assert_eq!(outcome.password_emitted, Some(false));
        assert!(secrets.get("team-a/alice-forgejo").is_none());
        assert_ne!(fj.user("alice").unwrap().password, handed_out);
    }

    /// An adopted account (the importer marks it `bot`, `--manage-users`)
    /// keeps its own password whatever its spec changes.
    #[tokio::test]
    async fn an_adopted_account_keeps_its_password() {
        let (fj, secrets) = (FakeForgejo::default(), FakeSecretStore::default());
        let id = fj.insert_user("alice");
        let mut spec = local("alice");
        spec.bot = true;
        spec.secret_targets = vec![];
        spec.email = Some(String::new());
        for spec_changed in [true, false] {
            let input = UserInput {
                spec: &spec,
                namespace: "team-a",
                cr_name: "alice",
                previous_owner: None,
                current: Some(ForgejoRef {
                    id,
                    name: "alice".into(),
                }),
                spec_changed,
                secret_pending: false,
                password_emitted: false,
            };
            let outcome = reconcile_user(input, &fj, &secrets).await;
            assert!(outcome.ready.is_ok(), "{outcome:?}");
            assert_eq!(outcome.password_emitted, None);
            assert_eq!(fj.user("alice").unwrap().password, None, "never set");
        }
    }
}
