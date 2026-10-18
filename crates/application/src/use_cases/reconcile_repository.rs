//! `ForgejoRepository`: creation (empty / template / migration), settings,
//! rename, gated transfer, archive, branch protections and team access.
//! The repository is tracked by id (`GET /repositories/{id}`), so renames
//! and transfers never lose it.

use std::collections::{BTreeMap, BTreeSet};

use api::common::DeletionPolicy;
use api::repository::{BranchProtection, ForgejoRepositorySpec};
use domain::error::ReasonCode;

use crate::ports::{
    DesiredRepository, ForgejoGateway, ForgejoRef, GatewayError, GenerateOptions, MigrateOptions,
    ProtectionRule, RemoteRepository, RepositoryInitOptions, RepositoryPatch,
};
use crate::use_cases::{CleanupGateway, Drift, Failure, Outcome, RemoteWrite, deleted, gone_ok};

/// The resolved owner (`spec.organizationRef` / `spec.userRef`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    Organization(String),
    User(String),
}

impl Owner {
    pub fn name(&self) -> &str {
        match self {
            Owner::Organization(n) | Owner::User(n) => n,
        }
    }
}

/// How a missing repository gets created: when nothing is owned yet, or
/// when the owned one was deleted out of band and must come back the way
/// the spec describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Empty(RepositoryInitOptions),
    /// `owner/name` of the template repository.
    Template(String, GenerateOptions),
    Migrate(MigrateOptions),
}

pub struct RepositoryInput<'a> {
    pub spec: &'a ForgejoRepositorySpec,
    /// `status.forgejoId` (id) / `status.forgejoName` (`owner/name`).
    pub current: Option<ForgejoRef>,
    pub owner: Owner,
    /// Why the controller couldn't resolve it otherwise. Required when
    /// nothing is owned yet; when something is, an unresolvable source (a
    /// template deleted since) must not block the existing repository — it
    /// only blocks recreating one that vanished, and says why.
    pub source: Result<Source, Failure>,
    /// Names of the resolved `spec.teamRefs`, all `Ready`.
    pub teams: Vec<String>,
    pub allow_disruptive_update: bool,
}

/// One-of checks the CRD schema can't express.
pub fn validate(spec: &ForgejoRepositorySpec) -> Result<(), Failure> {
    let invalid = |m: &str| Err(Failure::new(ReasonCode::InvalidSpec, m));
    match (&spec.organization_ref, &spec.user_ref) {
        (Some(_), Some(_)) | (None, None) => {
            return invalid("set exactly one of spec.organizationRef and spec.userRef");
        }
        (None, Some(_)) if !spec.team_refs.is_empty() => {
            return invalid("spec.teamRefs only applies to organization-owned repositories");
        }
        _ => {}
    }
    let sources = [
        spec.init.is_some(),
        spec.from_template.is_some(),
        spec.migrate.is_some(),
    ];
    if sources.iter().filter(|s| **s).count() > 1 {
        return invalid("set at most one of spec.init, spec.fromTemplate and spec.migrate");
    }
    if let Some(t) = &spec.from_template {
        match (&t.repository_ref, &t.repository) {
            (Some(_), Some(_)) | (None, None) => {
                return invalid(
                    "set exactly one of spec.fromTemplate.repositoryRef and \
                     spec.fromTemplate.repository",
                );
            }
            (None, Some(name)) if !is_full_name(name) => {
                return invalid("spec.fromTemplate.repository must be owner/name");
            }
            _ => {}
        }
    }
    let mut rules = BTreeSet::new();
    for rule in spec.branch_protections.iter().flatten() {
        if !rules.insert(&rule.rule_name) {
            return invalid(&format!(
                "spec.branchProtections lists {:?} twice",
                rule.rule_name
            ));
        }
    }
    Ok(())
}

pub async fn reconcile_repository(
    input: RepositoryInput<'_>,
    gateway: &dyn ForgejoGateway,
) -> Outcome {
    let spec = input.spec;
    let desired = desired_repository(spec);

    let remote = match &input.current {
        Some(current) => match gateway.get_repository(current.id).await {
            Ok(r) => r,
            Err(e) => return Outcome::failed(input.current.clone(), e),
        },
        None => None,
    };
    // What a creation writes next (settings a template or a migration
    // didn't apply, teams, protections) is part of it, not a drift.
    let created = remote.is_none();
    let mut remote = match remote {
        Some(r) => r,
        None => match create(&input, &desired, gateway).await {
            Ok(r) => r,
            Err((created, f)) => {
                let failed = Outcome::failed(created.clone(), f);
                return if created.is_some() {
                    failed.wrote(RemoteWrite::Created)
                } else {
                    failed
                };
            }
        },
    };
    let mut drift = Drift::default();
    let wrote = |outcome: Outcome, drift: Drift| {
        if created {
            outcome.wrote(RemoteWrite::Created)
        } else if drift.is_empty() {
            outcome
        } else {
            outcome.corrected(drift)
        }
    };
    let mut current = Some(ForgejoRef {
        id: remote.id,
        name: remote.full_name(),
    });

    if remote.owner != input.owner.name() {
        if !input.allow_disruptive_update {
            return Outcome::failed(
                current,
                Failure::new(
                    ReasonCode::DisruptiveUpdateRefused,
                    format!(
                        "moving {} to {:?} transfers the repository (URLs and access change); \
                         annotate the CR with forgejo.weebo.io/allow-disruptive-update=\"true\"",
                        remote.full_name(),
                        input.owner.name()
                    ),
                ),
            );
        }
        if let Err(e) = gateway
            .transfer_repository(&remote.full_name(), input.owner.name())
            .await
        {
            return Outcome::failed(current, e);
        }
        drift.note("owner", true);
        remote = match refetch(gateway, remote.id).await {
            Ok(r) => r,
            Err(f) => return Outcome::failed(current, f),
        };
        current = Some(ForgejoRef {
            id: remote.id,
            name: remote.full_name(),
        });
    }

    // Archived repositories refuse most writes (Forgejo answers 423): while
    // the spec keeps it archived, leave it frozen.
    if remote.archived && spec.archived {
        let frozen = Outcome::synced(current, "repository archived, settings frozen");
        return wrote(frozen, drift);
    }
    if remote.archived {
        if let Err(e) = gateway
            .set_repository_archived(&remote.full_name(), false)
            .await
        {
            return Outcome::failed(current, e);
        }
        drift.note("archived", true);
    }

    let (fields, patch) = repository_differs(&desired, &remote);
    if !patch.is_empty() {
        if let Err(e) = gateway.edit_repository(&remote.full_name(), &patch).await {
            return Outcome::failed(current, e);
        }
        for field in fields.fields() {
            drift.note(field, true);
        }
        remote.owner = input.owner.name().to_string();
        remote.name = desired.name.clone();
        current = Some(ForgejoRef {
            id: remote.id,
            name: remote.full_name(),
        });
    }
    let full_name = remote.full_name();

    // Teams first: Forgejo silently drops a branch-protection allow-list
    // team that has no write access to the repository yet, which would
    // read back as a perpetual diff.
    if matches!(input.owner, Owner::Organization(_)) {
        match sync_teams(&full_name, &input.teams, gateway).await {
            Ok(changed) => drift.note("teams", changed),
            Err(e) => return Outcome::failed(current, e),
        }
    }
    // Unset: someone else's (a template's copy, Forgejo's UI).
    if let Some(wanted) = &spec.branch_protections {
        match sync_protections(&full_name, wanted, gateway).await {
            Ok(changed) => drift.note("branch_protections", changed),
            Err(e) => return Outcome::failed(current, e),
        }
    }
    if spec.archived {
        if let Err(e) = gateway.set_repository_archived(&full_name, true).await {
            return Outcome::failed(current, e);
        }
        drift.note("archived", true);
    }
    wrote(Outcome::synced(current, "repository synced"), drift)
}

/// `Ok(true)`: the Forgejo object was deleted by this call.
pub async fn cleanup_repository(
    spec: &ForgejoRepositorySpec,
    current: Option<&ForgejoRef>,
    gateway: CleanupGateway<'_>,
) -> Result<bool, Failure> {
    if spec.deletion_policy != DeletionPolicy::Delete {
        return Ok(false);
    }
    let Some(current) = current else {
        return Ok(false);
    };
    let gateway = gateway.map_err(Clone::clone)?;
    // Resolve by id: the stored name may predate a rename or transfer.
    let Some(remote) = gateway.get_repository(current.id).await? else {
        return Ok(false);
    };
    Ok(deleted(
        gateway.delete_repository(&remote.full_name()).await,
    )?)
}

/// Returns the created repository, or the failure (with the ref to persist
/// if the repository exists despite it).
async fn create(
    input: &RepositoryInput<'_>,
    desired: &DesiredRepository,
    gateway: &dyn ForgejoGateway,
) -> Result<RemoteRepository, (Option<ForgejoRef>, Failure)> {
    let owner = input.owner.name();
    let source = match input.source.clone() {
        Ok(s) => s,
        Err(_) if input.spec.from_template.is_none() && input.spec.migrate.is_none() => {
            Source::Empty(init_options(input.spec))
        }
        // Never fall back to an empty repository for a mirror or a
        // template-generated one.
        Err(f) => {
            return Err((
                None,
                Failure::new(
                    ReasonCode::ReferenceNotReady,
                    format!(
                        "the repository is gone from Forgejo and spec.fromTemplate/spec.migrate \
                         can't be resolved to recreate it: {}",
                        f.message
                    ),
                ),
            ));
        }
    };
    let created = match &source {
        Source::Empty(init) => {
            let is_org = matches!(input.owner, Owner::Organization(_));
            gateway
                .create_repository(owner, is_org, desired, init)
                .await
        }
        Source::Template(template, options) => {
            gateway
                .generate_repository(template, owner, desired, options)
                .await
        }
        Source::Migrate(options) => gateway.migrate_repository(owner, desired, options).await,
    }
    .map_err(|e| (None, creation_failure(&source, e)))?;

    refetch(gateway, created.id)
        .await
        .map_err(|f| (Some(created), f))
}

/// A missing template says so, rather than a bare 404.
fn creation_failure(source: &Source, err: GatewayError) -> Failure {
    match (source, err) {
        (Source::Template(template, _), GatewayError::NotFound(_)) => Failure::new(
            ReasonCode::ReferenceNotFound,
            format!("template repository {template} not found in Forgejo"),
        ),
        (_, e) => e.into(),
    }
}

fn is_full_name(name: &str) -> bool {
    matches!(name.split_once('/'), Some((o, r)) if !o.is_empty() && !r.is_empty() && !r.contains('/'))
}

async fn refetch(gateway: &dyn ForgejoGateway, id: i64) -> Result<RemoteRepository, Failure> {
    gateway.get_repository(id).await?.ok_or_else(|| {
        Failure::new(
            ReasonCode::ForgejoApiError,
            format!("repository {id} vanished right after being written"),
        )
    })
}

/// Deletes rules not in the spec, creates missing ones, PATCHes changed
/// ones. `true` when any was written.
async fn sync_protections(
    full_name: &str,
    wanted: &[BranchProtection],
    gateway: &dyn ForgejoGateway,
) -> Result<bool, GatewayError> {
    let wanted: BTreeMap<String, ProtectionRule> = wanted
        .iter()
        .map(|p| (p.rule_name.clone(), protection_rule(p)))
        .collect();
    let actual: BTreeMap<String, ProtectionRule> = gateway
        .list_branch_protections(full_name)
        .await?
        .into_iter()
        .map(|r| (r.rule_name.clone(), normalized(r)))
        .collect();

    let mut changed = false;
    for name in actual.keys().filter(|n| !wanted.contains_key(*n)) {
        gone_ok(gateway.delete_branch_protection(full_name, name).await)?;
        changed = true;
    }
    for (name, rule) in &wanted {
        match actual.get(name) {
            None => gateway.create_branch_protection(full_name, rule).await?,
            Some(existing) if existing != rule => {
                gateway.edit_branch_protection(full_name, rule).await?
            }
            Some(_) => continue,
        }
        changed = true;
    }
    Ok(changed)
}

/// Teams Forgejo grants on its own (`Owners`, `includesAllRepositories`)
/// can't be removed per repository, so they're left out of the diff.
/// `true` when a team was added or removed.
async fn sync_teams(
    full_name: &str,
    wanted: &[String],
    gateway: &dyn ForgejoGateway,
) -> Result<bool, GatewayError> {
    let wanted: BTreeSet<&str> = wanted.iter().map(String::as_str).collect();
    let actual = gateway.list_repository_teams(full_name).await?;
    let removable: BTreeSet<&str> = actual
        .iter()
        .filter(|t| t.name != "Owners" && !t.includes_all_repositories)
        .map(|t| t.name.as_str())
        .collect();
    let present: BTreeSet<&str> = actual.iter().map(|t| t.name.as_str()).collect();

    let mut changed = false;
    for team in wanted.difference(&present) {
        gateway.add_repository_team(full_name, team).await?;
        changed = true;
    }
    for team in removable.difference(&wanted) {
        gone_ok(gateway.remove_repository_team(full_name, team).await)?;
        changed = true;
    }
    Ok(changed)
}

/// `spec.init` as creation options (an absent `init` creates a bare
/// repository).
pub fn init_options(spec: &ForgejoRepositorySpec) -> RepositoryInitOptions {
    let init = spec.init.clone().unwrap_or_default();
    RepositoryInitOptions {
        auto_init: spec.init.is_some() && init.auto_init,
        gitignores: init.gitignores,
        license: init.license,
        readme: init.readme,
        object_format: init.object_format,
    }
}

fn desired_repository(spec: &ForgejoRepositorySpec) -> DesiredRepository {
    DesiredRepository {
        name: spec.name.clone(),
        description: spec.description.clone(),
        website: spec.website.clone(),
        private: spec.private,
        template: spec.is_template,
        default_branch: spec.default_branch.clone(),
        has_issues: spec.units.issues,
        has_wiki: spec.units.wiki,
        has_pull_requests: spec.units.pull_requests,
        has_projects: spec.units.projects,
        has_releases: spec.units.releases,
        has_packages: spec.units.packages,
        has_actions: spec.units.actions,
        mirror_interval: spec
            .migrate
            .as_ref()
            .filter(|m| m.mirror)
            .and_then(|m| m.mirror_interval.clone()),
    }
}

/// The settings of `r` that differ from `d`, and the PATCH carrying only
/// them (`None` in the spec: no opinion). A mirror interval is compared
/// as a duration (Forgejo echoes Go's canonical form), and only sent for
/// a mirror.
fn repository_differs(d: &DesiredRepository, r: &RemoteRepository) -> (Drift, RepositoryPatch) {
    let mut p = RepositoryPatch::full(d);
    let mut drift = Drift::default();
    drift.keep("name", &mut p.name, &r.name);
    drift.keep("description", &mut p.description, &r.description);
    drift.keep("website", &mut p.website, &r.website);
    drift.keep("private", &mut p.private, &r.private);
    drift.keep("template", &mut p.template, &r.template);
    drift.keep("default_branch", &mut p.default_branch, &r.default_branch);
    drift.keep("has_issues", &mut p.has_issues, &r.has_issues);
    drift.keep("has_wiki", &mut p.has_wiki, &r.has_wiki);
    drift.keep(
        "has_pull_requests",
        &mut p.has_pull_requests,
        &r.has_pull_requests,
    );
    drift.keep("has_projects", &mut p.has_projects, &r.has_projects);
    drift.keep("has_releases", &mut p.has_releases, &r.has_releases);
    drift.keep("has_packages", &mut p.has_packages, &r.has_packages);
    drift.keep("has_actions", &mut p.has_actions, &r.has_actions);
    if !r.mirror {
        p.mirror_interval = None;
    }
    drift.keep_with(
        "mirror_interval",
        &mut p.mirror_interval,
        &r.mirror_interval,
        |d, r| go_duration_secs(d) == go_duration_secs(r),
    );
    (drift, p)
}

/// Seconds in a Go duration (`8h`, `1h30m`, `8h0m0s`) — Forgejo echoes
/// intervals in Go's canonical form, so `8h` and `8h0m0s` must compare
/// equal. `None` for anything unparsable (compared as-is then).
pub fn go_duration_secs(s: &str) -> Option<u64> {
    if s == "0" || s.is_empty() {
        return Some(0);
    }
    let mut total = 0u64;
    let mut number = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            number.push(c);
            continue;
        }
        let n: u64 = number.parse().ok()?;
        number.clear();
        let unit = match c {
            'h' => 3600,
            's' => 1,
            'm' if chars.peek() == Some(&'s') => {
                chars.next();
                0
            }
            'm' => 60,
            _ => return None,
        };
        // Overflow is an invalid duration, not a wrap-around (a huge
        // rotation period must never read as already expired).
        total = total.checked_add(n.checked_mul(unit)?)?;
    }
    (number.is_empty() && i64::try_from(total).is_ok()).then_some(total)
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v
}

pub fn protection_rule(p: &BranchProtection) -> ProtectionRule {
    let push_whitelist = p.enable_push
        && (!p.push_whitelist_usernames.is_empty()
            || !p.push_whitelist_teams.is_empty()
            || p.push_whitelist_deploy_keys);
    ProtectionRule {
        rule_name: p.rule_name.clone(),
        enable_push: p.enable_push,
        // Forgejo only keeps the push allow-list switches while pushing is
        // enabled (EnableWhitelist = EnablePush && EnablePushWhitelist):
        // ask for what it will store, or the rule reads back as a diff.
        enable_push_whitelist: push_whitelist,
        push_whitelist_usernames: sorted(&p.push_whitelist_usernames),
        push_whitelist_teams: sorted(&p.push_whitelist_teams),
        push_whitelist_deploy_keys: push_whitelist && p.push_whitelist_deploy_keys,
        enable_merge_whitelist: !p.merge_whitelist_usernames.is_empty()
            || !p.merge_whitelist_teams.is_empty(),
        merge_whitelist_usernames: sorted(&p.merge_whitelist_usernames),
        merge_whitelist_teams: sorted(&p.merge_whitelist_teams),
        required_approvals: p.required_approvals,
        enable_approvals_whitelist: !p.approvals_whitelist_usernames.is_empty()
            || !p.approvals_whitelist_teams.is_empty(),
        approvals_whitelist_usernames: sorted(&p.approvals_whitelist_usernames),
        approvals_whitelist_teams: sorted(&p.approvals_whitelist_teams),
        enable_status_check: !p.status_check_contexts.is_empty(),
        status_check_contexts: sorted(&p.status_check_contexts),
        block_on_rejected_reviews: p.block_on_rejected_reviews,
        block_on_official_review_requests: p.block_on_official_review_requests,
        block_on_outdated_branch: p.block_on_outdated_branch,
        dismiss_stale_approvals: p.dismiss_stale_approvals,
        ignore_stale_approvals: p.ignore_stale_approvals,
        require_signed_commits: p.require_signed_commits,
        apply_to_admins: p.apply_to_admins,
        protected_file_patterns: p.protected_file_patterns.clone().unwrap_or_default(),
        unprotected_file_patterns: p.unprotected_file_patterns.clone().unwrap_or_default(),
    }
}

/// Forgejo returns lists in its own order and keeps lists whose switch is
/// off; compare in the spec's normal form.
fn normalized(mut r: ProtectionRule) -> ProtectionRule {
    for list in [
        &mut r.push_whitelist_usernames,
        &mut r.push_whitelist_teams,
        &mut r.merge_whitelist_usernames,
        &mut r.merge_whitelist_teams,
        &mut r.approvals_whitelist_usernames,
        &mut r.approvals_whitelist_teams,
        &mut r.status_check_contexts,
    ] {
        list.sort();
    }
    r
}

#[cfg(test)]
mod tests {
    use api::common::{IdentityRef, ObjectRef};
    use api::repository::{MigrateSource, RepositoryUnits, TemplateSource};

    use super::*;
    use crate::ports::{DesiredOrganization, DesiredTeam};
    use crate::test_support::{Edit, FakeForgejo};

    fn spec(name: &str) -> ForgejoRepositorySpec {
        ForgejoRepositorySpec {
            instance_ref: None,
            organization_ref: Some(IdentityRef::named("weebo")),
            user_ref: None,
            name: name.into(),
            description: Some("demo".into()),
            website: None,
            private: false,
            is_template: false,
            archived: false,
            default_branch: None,
            units: RepositoryUnits::default(),
            init: None,
            from_template: None,
            migrate: None,
            branch_protections: None,
            team_refs: vec![],
            deletion_policy: DeletionPolicy::Orphan,
        }
    }

    async fn forgejo() -> FakeForgejo {
        let fj = FakeForgejo::default();
        for org in ["weebo", "labs"] {
            fj.create_organization(
                None,
                &DesiredOrganization {
                    name: org.into(),
                    visibility: "public",
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        fj
    }

    fn input<'a>(
        spec: &'a ForgejoRepositorySpec,
        current: Option<ForgejoRef>,
        owner: &str,
    ) -> RepositoryInput<'a> {
        RepositoryInput {
            spec,
            current,
            owner: Owner::Organization(owner.into()),
            source: Ok(Source::Empty(Default::default())),
            teams: vec![],
            allow_disruptive_update: false,
        }
    }

    #[tokio::test]
    async fn creates_then_only_patches_on_drift() {
        let fj = forgejo().await;
        let mut s = spec("app");
        let created = reconcile_repository(input(&s, None, "weebo"), &fj).await;
        let current = created.forgejo.clone().unwrap();
        assert_eq!(current.name, "weebo/app");
        assert_eq!(fj.repo(current.id).unwrap().description, "demo");

        fj.clear_calls();
        reconcile_repository(input(&s, Some(current.clone()), "weebo"), &fj).await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());

        s.private = true;
        let outcome = reconcile_repository(input(&s, Some(current.clone()), "weebo"), &fj).await;
        assert!(fj.repo(current.id).unwrap().private);
        assert_eq!(
            fj.edits(),
            [Edit::Repository(RepositoryPatch {
                private: Some(true),
                ..Default::default()
            })],
            "only the drifted field"
        );
        assert_eq!(outcome.drift.fields(), ["private"]);
        assert_eq!(created.write, Some(RemoteWrite::Created));
    }

    #[tokio::test]
    async fn rename_keeps_the_id_and_updates_the_name() {
        let fj = forgejo().await;
        let mut s = spec("app");
        let current = reconcile_repository(input(&s, None, "weebo"), &fj)
            .await
            .forgejo
            .unwrap();
        s.name = "app2".into();
        let outcome = reconcile_repository(input(&s, Some(current.clone()), "weebo"), &fj).await;
        assert_eq!(
            outcome.forgejo,
            Some(ForgejoRef {
                id: current.id,
                name: "weebo/app2".into()
            })
        );
    }

    #[tokio::test]
    async fn transfer_needs_the_annotation() {
        let fj = forgejo().await;
        let s = spec("app");
        let current = reconcile_repository(input(&s, None, "weebo"), &fj)
            .await
            .forgejo
            .unwrap();

        let refused = reconcile_repository(input(&s, Some(current.clone()), "labs"), &fj).await;
        assert_eq!(refused.reason(), ReasonCode::DisruptiveUpdateRefused);

        let mut allowed = input(&s, Some(current.clone()), "labs");
        allowed.allow_disruptive_update = true;
        let moved = reconcile_repository(allowed, &fj).await;
        assert_eq!(moved.forgejo.unwrap().name, "labs/app");
        assert_eq!(fj.repo(current.id).unwrap().owner, "labs");
    }

    #[tokio::test]
    async fn branch_protections_are_authoritative() {
        let fj = forgejo().await;
        let mut s = spec("app");
        s.branch_protections = Some(vec![BranchProtection {
            rule_name: "main".into(),
            required_approvals: 1,
            push_whitelist_teams: vec!["devs".into()],
            enable_push: true,
            ..Default::default()
        }]);
        let current = reconcile_repository(input(&s, None, "weebo"), &fj)
            .await
            .forgejo
            .unwrap();
        let rules = fj.protections(current.id);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].enable_push_whitelist);

        fj.clear_calls();
        reconcile_repository(input(&s, Some(current.clone()), "weebo"), &fj).await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());

        s.branch_protections.as_mut().unwrap()[0].rule_name = "release/*".into();
        reconcile_repository(input(&s, Some(current.clone()), "weebo"), &fj).await;
        let names: Vec<_> = fj
            .protections(current.id)
            .into_iter()
            .map(|r| r.rule_name)
            .collect();
        assert_eq!(names, vec!["release/*"]);

        // Unset: the rules stay, whoever made them, and aren't even read.
        s.branch_protections = None;
        fj.clear_calls();
        reconcile_repository(input(&s, Some(current.clone()), "weebo"), &fj).await;
        assert_eq!(fj.protections(current.id).len(), 1);
        assert!(
            fj.calls().iter().all(|c| !c.contains("branch_protection")),
            "{:?}",
            fj.calls()
        );

        // Empty: every rule goes.
        s.branch_protections = Some(vec![]);
        reconcile_repository(input(&s, Some(current.clone()), "weebo"), &fj).await;
        assert!(fj.protections(current.id).is_empty());
    }

    /// Forgejo drops the push allow-list switches while pushing is off.
    #[tokio::test]
    async fn push_allow_list_without_push_does_not_drift() {
        let fj = forgejo().await;
        let mut s = spec("app");
        s.branch_protections = Some(vec![BranchProtection {
            rule_name: "main".into(),
            push_whitelist_usernames: vec!["alice".into()],
            push_whitelist_deploy_keys: true,
            enable_push: false,
            ..Default::default()
        }]);
        let current = reconcile_repository(input(&s, None, "weebo"), &fj)
            .await
            .forgejo
            .unwrap();
        fj.clear_calls();
        reconcile_repository(input(&s, Some(current), "weebo"), &fj).await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn teams_are_synced_except_the_ones_forgejo_grants() {
        let fj = forgejo().await;
        for (name, all) in [("devs", false), ("ops", false), ("everyone", true)] {
            fj.create_team(
                "weebo",
                &DesiredTeam {
                    name: name.into(),
                    permission: "read",
                    includes_all_repositories: all,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        let s = spec("app");
        let mut first = input(&s, None, "weebo");
        first.teams = vec!["devs".into(), "ops".into()];
        let current = reconcile_repository(first, &fj).await.forgejo.unwrap();

        let mut second = input(&s, Some(current.clone()), "weebo");
        second.teams = vec!["ops".into()];
        reconcile_repository(second, &fj).await;
        let mut teams = fj.repo_teams(current.id);
        teams.sort();
        assert_eq!(teams, vec!["everyone", "ops"]);
    }

    #[tokio::test]
    async fn archived_repositories_are_frozen() {
        let fj = forgejo().await;
        let mut s = spec("app");
        s.archived = true;
        let current = reconcile_repository(input(&s, None, "weebo"), &fj)
            .await
            .forgejo
            .unwrap();
        assert!(fj.repo(current.id).unwrap().archived);

        fj.clear_calls();
        s.description = Some("changed".into());
        let outcome = reconcile_repository(input(&s, Some(current.clone()), "weebo"), &fj).await;
        assert!(outcome.ready.is_ok());
        assert!(fj.calls().is_empty());

        s.archived = false;
        reconcile_repository(input(&s, Some(current.clone()), "weebo"), &fj).await;
        let repo = fj.repo(current.id).unwrap();
        assert!(!repo.archived);
        assert_eq!(repo.description, "changed");
    }

    #[tokio::test]
    async fn migration_carries_the_mirror_settings() {
        let fj = forgejo().await;
        let mut s = spec("mirror");
        s.migrate = Some(MigrateSource {
            clone_addr: "https://example.com/x.git".into(),
            service: "git".into(),
            mirror: true,
            mirror_interval: Some("8h".into()),
            lfs: false,
            wiki: false,
            issues: false,
            pull_requests: false,
            releases: false,
            labels: false,
            milestones: false,
            auth_secret_ref: None,
        });
        let mut i = input(&s, None, "weebo");
        i.source = Ok(Source::Migrate(MigrateOptions {
            clone_addr: "https://example.com/x.git".into(),
            mirror: true,
            mirror_interval: Some("8h".into()),
            ..Default::default()
        }));
        let current = reconcile_repository(i, &fj).await.forgejo.unwrap();
        let repo = fj.repo(current.id).unwrap();
        assert!(repo.mirror);

        // Forgejo echoes `8h0m0s`: no perpetual PATCH.
        fj.clear_calls();
        reconcile_repository(input(&s, Some(current), "weebo"), &fj).await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    /// A mirror deleted out of band comes back as a mirror, never as an
    /// empty repository.
    #[tokio::test]
    async fn vanished_mirror_is_recreated_from_its_source() {
        let fj = forgejo().await;
        let mut s = spec("mirror");
        s.migrate = Some(MigrateSource {
            clone_addr: "https://example.com/x.git".into(),
            service: "git".into(),
            mirror: true,
            mirror_interval: None,
            lfs: false,
            wiki: false,
            issues: false,
            pull_requests: false,
            releases: false,
            labels: false,
            milestones: false,
            auth_secret_ref: None,
        });
        let migrate = Source::Migrate(MigrateOptions {
            clone_addr: "https://example.com/x.git".into(),
            mirror: true,
            ..Default::default()
        });
        let mut first = input(&s, None, "weebo");
        first.source = Ok(migrate.clone());
        let current = reconcile_repository(first, &fj).await.forgejo.unwrap();
        fj.delete_repository("weebo/mirror").await.unwrap();

        // The source couldn't be resolved: wait, don't create an empty one.
        let mut unresolved = input(&s, Some(current.clone()), "weebo");
        unresolved.source = Err(Failure::new(
            ReasonCode::ReferenceNotReady,
            "secrets is forbidden",
        ));
        let waiting = reconcile_repository(unresolved, &fj).await;
        assert_eq!(waiting.reason(), ReasonCode::ReferenceNotReady);
        assert!(
            waiting
                .ready
                .unwrap_err()
                .message
                .ends_with("secrets is forbidden"),
            "says why"
        );
        assert!(waiting.forgejo.is_none());

        let mut resolved = input(&s, Some(current), "weebo");
        resolved.source = Ok(migrate);
        let recreated = reconcile_repository(resolved, &fj).await.forgejo.unwrap();
        assert!(fj.repo(recreated.id).unwrap().mirror);
    }

    #[test]
    fn go_durations_compare_by_value() {
        assert_eq!(go_duration_secs("8h"), go_duration_secs("8h0m0s"));
        assert_eq!(go_duration_secs("1h30m"), Some(5400));
        assert_eq!(go_duration_secs("10m0s"), Some(600));
        assert_eq!(go_duration_secs("0"), Some(0));
        assert_eq!(go_duration_secs("soon"), None);
        assert_eq!(go_duration_secs("99999999999999999999h"), None);
        assert_eq!(go_duration_secs(&format!("{}h", u64::MAX / 3600)), None);
    }

    #[test]
    fn one_of_violations_are_invalid() {
        let mut s = spec("x");
        s.user_ref = Some(IdentityRef::named("a"));
        assert!(validate(&s).is_err());
        let mut s = spec("x");
        s.init = Some(Default::default());
        s.migrate = Some(MigrateSource {
            clone_addr: "u".into(),
            service: "git".into(),
            mirror: false,
            mirror_interval: None,
            lfs: false,
            wiki: false,
            issues: false,
            pull_requests: false,
            releases: false,
            labels: false,
            milestones: false,
            auth_secret_ref: None,
        });
        assert!(validate(&s).is_err());
        assert!(validate(&spec("x")).is_ok());
    }

    fn template(repository_ref: Option<&str>, repository: Option<&str>) -> TemplateSource {
        TemplateSource {
            repository_ref: repository_ref.map(|n| ObjectRef { name: n.into() }),
            repository: repository.map(Into::into),
            git_content: true,
            topics: false,
            labels: false,
            webhooks: false,
            protected_branches: false,
            git_hooks: false,
            avatar: false,
        }
    }

    #[test]
    fn a_template_is_named_exactly_once_as_owner_slash_name() {
        let with = |t| {
            let mut s = spec("x");
            s.from_template = Some(t);
            validate(&s)
        };
        assert!(with(template(Some("tpl"), None)).is_ok());
        assert!(with(template(None, Some("batlehub/weebo-base"))).is_ok());
        for bad in [
            template(None, None),
            template(Some("tpl"), Some("batlehub/weebo-base")),
            template(None, Some("weebo-base")),
            template(None, Some("batlehub/")),
            template(None, Some("a/b/c")),
        ] {
            let f = with(bad.clone()).unwrap_err();
            assert_eq!(f.reason, ReasonCode::InvalidSpec, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn generates_from_a_template_by_name() {
        let fj = forgejo().await;
        let mut base = spec("weebo-base");
        base.is_template = true;
        reconcile_repository(input(&base, None, "labs"), &fj).await;

        let mut s = spec("app");
        s.from_template = Some(template(None, Some("labs/weebo-base")));
        let mut resolved = input(&s, None, "weebo");
        resolved.source = Ok(Source::Template(
            "labs/weebo-base".into(),
            GenerateOptions::default(),
        ));
        let created = reconcile_repository(resolved, &fj).await;
        assert!(created.ready.is_ok(), "{:?}", created.ready);
        assert!(
            fj.calls()
                .iter()
                .any(|c| c == "generate_repository labs/weebo-base weebo/app"),
            "{:?}",
            fj.calls()
        );

        s.name = "other".into();
        let mut resolved = input(&s, None, "weebo");
        resolved.source = Ok(Source::Template(
            "labs/gone".into(),
            GenerateOptions::default(),
        ));
        let missing = reconcile_repository(resolved, &fj).await;
        assert_eq!(missing.forgejo, None);
        let f = missing.ready.unwrap_err();
        assert_eq!(f.reason, ReasonCode::ReferenceNotFound);
        assert!(f.message.contains("labs/gone"), "{}", f.message);
    }
}
