//! `ForgejoTeam`: the team itself (attempt-create-first, PATCH on drift)
//! and its authoritative member list. Moving a team to another organization
//! is a delete-and-recreate, gated by the disruptive-update annotation.

use std::collections::BTreeSet;

use api::common::DeletionPolicy;
use api::team::{ForgejoTeamSpec, TeamPermission};
use domain::error::ReasonCode;

use crate::ports::{DesiredTeam, ForgejoGateway, ForgejoRef, GatewayError, RemoteTeam};
use crate::use_cases::{Advisory, CleanupGateway, Failure, Outcome, differs};

/// A `spec.memberRefs` entry, resolved by the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Member {
    /// Login of a `ForgejoUser` that exists in Forgejo.
    Ready(String),
    /// A `ForgejoUser` CR that is missing, not ready yet, or observes an
    /// OIDC account that hasn't logged in once. `name` is the CR name;
    /// `login` its `spec.username` when the CR exists — that account may
    /// well be in the team already (a CR only briefly not `Ready`).
    Pending {
        name: String,
        why: String,
        login: Option<String>,
    },
}

pub struct TeamInput<'a> {
    pub spec: &'a ForgejoTeamSpec,
    /// From `status.forgejoId`/`status.forgejoName`.
    pub current: Option<ForgejoRef>,
    /// Name of the resolved `spec.organizationRef`, already `Ready`.
    pub organization: String,
    /// Its Forgejo id: a renamed organization is still the same one.
    pub organization_id: Option<i64>,
    pub members: Vec<Member>,
    /// The `forgejo.weebo.io/allow-disruptive-update: "true"` annotation.
    pub allow_disruptive_update: bool,
}

pub async fn reconcile_team(input: TeamInput<'_>, gateway: &dyn ForgejoGateway) -> Outcome {
    let desired = desired_team(input.spec);

    let remote = match &input.current {
        Some(current) => match gateway.get_team(current.id).await {
            Ok(r) => r,
            Err(e) => return Outcome::failed(input.current.clone(), e),
        },
        None => None,
    };

    let moved = |remote: &RemoteTeam| match (input.organization_id, remote.organization_id) {
        (Some(want), Some(have)) => want != have,
        _ => remote.organization != input.organization,
    };
    let team = match remote {
        Some(remote) if moved(&remote) => {
            if !input.allow_disruptive_update {
                return Outcome::failed(
                    input.current.clone(),
                    Failure::new(
                        ReasonCode::DisruptiveUpdateRefused,
                        format!(
                            "moving the team from {:?} to {:?} deletes and recreates it (losing its \
                             repository grants); annotate the CR with \
                             forgejo.weebo.io/allow-disruptive-update=\"true\" to proceed",
                            remote.organization, input.organization
                        ),
                    ),
                );
            }
            if let Err(e) = gateway.delete_team(remote.id).await {
                return Outcome::failed(input.current.clone(), e);
            }
            match gateway.create_team(&input.organization, &desired).await {
                Ok(r) => r,
                Err(e) => return Outcome::failed(None, e),
            }
        }
        Some(remote) => {
            let current = ForgejoRef {
                id: remote.id,
                name: remote.name.clone(),
            };
            if team_differs(&desired, &remote)
                && let Err(e) = gateway.edit_team(remote.id, &desired).await
            {
                return Outcome::failed(Some(current), e);
            }
            ForgejoRef {
                id: remote.id,
                name: desired.name.clone(),
            }
        }
        None => match gateway.create_team(&input.organization, &desired).await {
            Ok(r) => r,
            Err(e) => return Outcome::failed(None, e),
        },
    };

    let current = Some(team.clone());
    if let Err(e) = sync_members(team.id, &input.members, gateway).await {
        return Outcome::failed(current, e);
    }

    let mut outcome = Outcome::synced(current, "team synced");
    let pending: Vec<String> = input
        .members
        .iter()
        .filter_map(|m| match m {
            Member::Pending { name, why, .. } => Some(format!("{name} ({why})")),
            Member::Ready(_) => None,
        })
        .collect();
    if !pending.is_empty() {
        outcome.advisories.push(Advisory {
            reason: ReasonCode::MemberPending,
            message: format!("not in Forgejo yet: {}", pending.join(", ")),
        });
    }
    outcome
}

pub async fn cleanup_team(
    spec: &ForgejoTeamSpec,
    current: Option<&ForgejoRef>,
    gateway: CleanupGateway<'_>,
) -> Result<(), Failure> {
    if spec.deletion_policy != DeletionPolicy::Delete {
        return Ok(());
    }
    let Some(current) = current else {
        return Ok(());
    };
    match gateway.map_err(Clone::clone)?.delete_team(current.id).await {
        Ok(()) | Err(GatewayError::NotFound(_)) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Adds every ready member, removes everyone not listed. A pending member
/// is neither added (not confirmed yet) nor removed: its CR may only be
/// briefly not `Ready` (an instance hiccup, a first reconcile after an
/// import) while the account is already in the team.
async fn sync_members(
    team: i64,
    members: &[Member],
    gateway: &dyn ForgejoGateway,
) -> Result<(), GatewayError> {
    let wanted: BTreeSet<&str> = members
        .iter()
        .filter_map(|m| match m {
            Member::Ready(login) => Some(login.as_str()),
            Member::Pending { .. } => None,
        })
        .collect();
    let kept: BTreeSet<&str> = members
        .iter()
        .filter_map(|m| match m {
            Member::Pending { login, .. } => login.as_deref(),
            Member::Ready(_) => None,
        })
        .collect();
    let actual = gateway.list_team_members(team).await?;
    let actual: BTreeSet<&str> = actual.iter().map(String::as_str).collect();

    for login in wanted.difference(&actual) {
        gateway.add_team_member(team, login).await?;
    }
    for login in actual.difference(&wanted) {
        if !kept.contains(login) {
            gateway.remove_team_member(team, login).await?;
        }
    }
    Ok(())
}

/// Repository units a team gets when `spec.unitsMap` is empty — Forgejo
/// refuses a non-admin team without units ("units permission should not be
/// empty", as a 500), and its own UI defaults to every unit at the team's
/// permission. The external tracker/wiki units are left out: they only
/// ever allow `read`.
pub const DEFAULT_UNITS: &[&str] = &[
    "repo.code",
    "repo.issues",
    "repo.pulls",
    "repo.releases",
    "repo.wiki",
    "repo.projects",
    "repo.packages",
    "repo.actions",
];

fn desired_team(spec: &ForgejoTeamSpec) -> DesiredTeam {
    let permission = match spec.permission {
        TeamPermission::Read => "read",
        TeamPermission::Write => "write",
        TeamPermission::Admin => "admin",
    };
    let units_map = if spec.units_map.is_empty() {
        DEFAULT_UNITS
            .iter()
            .map(|u| (u.to_string(), permission.to_string()))
            .collect()
    } else {
        spec.units_map.clone()
    };
    DesiredTeam {
        name: spec.name.clone(),
        description: spec.description.clone(),
        permission,
        units_map,
        includes_all_repositories: spec.includes_all_repositories,
        can_create_org_repo: spec.can_create_org_repo,
    }
}

/// Only the units the spec names are compared: Forgejo returns every unit,
/// and an unnamed one is "no opinion", not "none".
fn team_differs(d: &DesiredTeam, r: &RemoteTeam) -> bool {
    d.name != r.name
        || differs(&d.description, &r.description)
        || d.permission != r.permission
        || d.includes_all_repositories != r.includes_all_repositories
        || d.can_create_org_repo != r.can_create_org_repo
        || d.units_map
            .iter()
            .any(|(unit, access)| r.units_map.get(unit) != Some(access))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::DesiredOrganization;
    use crate::test_support::FakeForgejo;

    fn spec(name: &str) -> ForgejoTeamSpec {
        ForgejoTeamSpec {
            instance_ref: None,
            organization_ref: api::common::ObjectRef {
                name: "weebo".into(),
            },
            name: name.into(),
            description: None,
            permission: TeamPermission::Write,
            units_map: [("repo.code".to_string(), "write".to_string())].into(),
            includes_all_repositories: false,
            can_create_org_repo: false,
            member_refs: vec![],
            deletion_policy: DeletionPolicy::Delete,
        }
    }

    async fn forgejo_with_orgs(orgs: &[&str]) -> FakeForgejo {
        let fj = FakeForgejo::default();
        for org in orgs {
            fj.create_organization(
                None,
                &DesiredOrganization {
                    name: org.to_string(),
                    visibility: "public",
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        fj
    }

    async fn run(
        spec: &ForgejoTeamSpec,
        current: Option<ForgejoRef>,
        org: &str,
        members: Vec<Member>,
        allow_disruptive_update: bool,
        fj: &FakeForgejo,
    ) -> Outcome {
        let input = TeamInput {
            spec,
            current,
            organization: org.into(),
            organization_id: fj.org(org).map(|o| o.remote.id),
            members,
            allow_disruptive_update,
        };
        reconcile_team(input, fj).await
    }

    #[tokio::test]
    async fn creates_the_team_and_syncs_members_both_ways() {
        let fj = forgejo_with_orgs(&["weebo"]).await;
        fj.insert_user("alice");
        fj.insert_user("mallory");
        let s = spec("devs");

        let created = run(
            &s,
            None,
            "weebo",
            vec![Member::Ready("alice".into())],
            false,
            &fj,
        )
        .await
        .forgejo
        .unwrap();
        fj.insert_team_member(created.id, "mallory");

        run(
            &s,
            Some(created.clone()),
            "weebo",
            vec![Member::Ready("alice".into())],
            false,
            &fj,
        )
        .await;
        assert_eq!(fj.team(created.id).unwrap().members, vec!["alice"]);
    }

    #[tokio::test]
    async fn pending_members_are_advisory_and_the_rest_still_syncs() {
        let fj = forgejo_with_orgs(&["weebo"]).await;
        fj.insert_user("alice");
        let members = vec![
            Member::Ready("alice".into()),
            Member::Pending {
                name: "carol".into(),
                why: "UserNotFound".into(),
                login: Some("carol".into()),
            },
        ];
        let outcome = run(&spec("devs"), None, "weebo", members, false, &fj).await;

        assert!(outcome.ready.is_ok());
        assert_eq!(outcome.advisories[0].reason, ReasonCode::MemberPending);
        let id = outcome.forgejo.unwrap().id;
        assert_eq!(fj.team(id).unwrap().members, vec!["alice"]);
    }

    /// A member whose `ForgejoUser` is only briefly not `Ready` (instance
    /// hiccup, first reconcile after an import) stays in the team.
    #[tokio::test]
    async fn a_pending_member_already_in_the_team_is_kept() {
        let fj = forgejo_with_orgs(&["weebo"]).await;
        fj.insert_user("alice");
        let ready = vec![Member::Ready("alice".into())];
        let created = run(&spec("devs"), None, "weebo", ready, false, &fj).await;
        let current = created.forgejo.clone();
        fj.clear_calls();

        let pending = vec![Member::Pending {
            name: "alice".into(),
            why: "ReferenceNotReady".into(),
            login: Some("alice".into()),
        }];
        let outcome = run(&spec("devs"), current, "weebo", pending, false, &fj).await;
        assert!(outcome.ready.is_ok());
        let id = outcome.forgejo.unwrap().id;
        assert_eq!(fj.team(id).unwrap().members, vec!["alice"]);
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn empty_units_default_to_every_unit_at_the_team_permission() {
        let fj = forgejo_with_orgs(&["weebo"]).await;
        let mut s = spec("devs");
        s.units_map.clear();
        let id = run(&s, None, "weebo", vec![], false, &fj)
            .await
            .forgejo
            .unwrap()
            .id;
        let units = fj.team(id).unwrap().remote.units_map;
        assert_eq!(units.len(), DEFAULT_UNITS.len());
        assert!(units.values().all(|v| v == "write"));
    }

    #[tokio::test]
    async fn no_drift_means_no_patch() {
        let fj = forgejo_with_orgs(&["weebo"]).await;
        let s = spec("devs");
        let created = run(&s, None, "weebo", vec![], false, &fj).await.forgejo;
        fj.clear_calls();
        run(&s, created, "weebo", vec![], false, &fj).await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn moving_organization_needs_the_annotation() {
        let fj = forgejo_with_orgs(&["weebo", "labs"]).await;
        let s = spec("devs");
        let created = run(&s, None, "weebo", vec![], false, &fj).await.forgejo;

        let refused = run(&s, created.clone(), "labs", vec![], false, &fj).await;
        assert_eq!(refused.reason(), ReasonCode::DisruptiveUpdateRefused);
        assert_eq!(refused.forgejo, created);

        let moved = run(&s, created.clone(), "labs", vec![], true, &fj).await;
        assert!(moved.ready.is_ok());
        let new = moved.forgejo.unwrap();
        assert_ne!(Some(new.clone()), created);
        assert_eq!(fj.team(new.id).unwrap().remote.organization, "labs");
    }

    /// The organization's CR may still carry the old name in its status
    /// while Forgejo already renamed it: same id, so no move.
    #[tokio::test]
    async fn renamed_organization_is_not_a_move() {
        let fj = forgejo_with_orgs(&["weebo"]).await;
        let s = spec("devs");
        let org_id = fj.org("weebo").unwrap().remote.id;
        let created = run(&s, None, "weebo", vec![], true, &fj).await.forgejo;
        fj.rename_organization("weebo", "weebo-labs").await.unwrap();
        fj.clear_calls();

        let input = TeamInput {
            spec: &s,
            current: created.clone(),
            organization: "weebo".into(),
            organization_id: Some(org_id),
            members: vec![],
            allow_disruptive_update: true,
        };
        let outcome = reconcile_team(input, &fj).await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");
        assert_eq!(outcome.forgejo.map(|f| f.id), created.map(|c| c.id));
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }
}
