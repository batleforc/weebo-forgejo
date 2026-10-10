//! Resolution of `*Ref` fields to the Forgejo objects behind them, over
//! the [`ReferenceReader`] port. A ref is usable once the referenced CR
//! has a `status.forgejoId` and is `Ready` — controllers watch the
//! referenced kinds, so a ref that becomes ready re-triggers the
//! referencing CR right away.

use domain::error::ReasonCode;

use crate::ports::{ClusterError, ForgejoRef, RefKind, ReferenceReader};
use crate::use_cases::Failure;
use crate::use_cases::reconcile_team::Member;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefState {
    Ready(ForgejoRef),
    NotFound,
    /// Exists but isn't usable yet; carries the referenced CR's `Ready`
    /// reason (e.g. `UserNotFound` for an observed OIDC user).
    NotReady(String),
    /// Targets another `ForgejoInstance` than the referencing CR: an id
    /// from one instance means nothing on another.
    OtherInstance(Option<String>),
}

/// `namespace`/`our_instance` are the referencing CR's namespace and
/// `spec.instanceRef`.
pub async fn resolve(
    reader: &dyn ReferenceReader,
    kind: RefKind,
    namespace: &str,
    name: &str,
    our_instance: Option<&str>,
) -> Result<RefState, ClusterError> {
    let Some(cr) = reader.referenced(kind, namespace, name).await? else {
        return Ok(RefState::NotFound);
    };
    if !same_instance(reader, cr.instance_ref.as_deref(), our_instance).await? {
        return Ok(RefState::OtherInstance(cr.instance_ref));
    }
    Ok(match (cr.forgejo, cr.ready) {
        (Some(r), Some((true, _))) => RefState::Ready(r),
        (_, Some((_, reason))) => RefState::NotReady(reason),
        (_, None) => RefState::NotReady("NotReconciledYet".to_string()),
    })
}

/// `status.forgejoName` of the referenced CR whatever its readiness, for a
/// finalizer cleanup: it must still address what was created while the
/// referenced CR is itself not ready or being deleted.
pub async fn recorded_name(
    reader: &dyn ReferenceReader,
    kind: RefKind,
    namespace: &str,
    name: &str,
    our_instance: Option<&str>,
) -> Result<Option<String>, ClusterError> {
    let Some(cr) = reader.referenced(kind, namespace, name).await? else {
        return Ok(None);
    };
    if !same_instance(reader, cr.instance_ref.as_deref(), our_instance).await? {
        return Ok(None);
    }
    Ok(cr.forgejo_name)
}

/// Two `instanceRef`s designate the same instance: equal, or one empty
/// while the other names the cluster's only instance.
async fn same_instance(
    reader: &dyn ReferenceReader,
    theirs: Option<&str>,
    ours: Option<&str>,
) -> Result<bool, ClusterError> {
    Ok(match (theirs, ours) {
        (a, b) if a == b => true,
        (Some(named), None) | (None, Some(named)) => {
            reader.default_instance().await?.as_deref() == Some(named)
        }
        _ => false,
    })
}

/// A single required ref: anything but `Ready` fails the reconcile.
pub fn require(kind: RefKind, name: &str, state: RefState) -> Result<ForgejoRef, Failure> {
    let kind = kind.as_str();
    match state {
        RefState::Ready(r) => Ok(r),
        RefState::NotFound => Err(Failure::new(
            ReasonCode::ReferenceNotFound,
            format!("{kind} {name:?} does not exist"),
        )),
        RefState::NotReady(why) => Err(Failure::new(
            ReasonCode::ReferenceNotReady,
            format!("{kind} {name:?} is not ready yet ({why})"),
        )),
        RefState::OtherInstance(theirs) => Err(Failure::new(
            ReasonCode::InvalidSpec,
            format!(
                "{kind} {name:?} targets ForgejoInstance {:?}, not this CR's",
                theirs.as_deref().unwrap_or("<default>")
            ),
        )),
    }
}

/// [`resolve`] then [`require`].
pub async fn resolve_required(
    reader: &dyn ReferenceReader,
    kind: RefKind,
    namespace: &str,
    name: &str,
    our_instance: Option<&str>,
) -> Result<Result<ForgejoRef, Failure>, ClusterError> {
    let state = resolve(reader, kind, namespace, name, our_instance).await?;
    Ok(require(kind, name, state))
}

/// A repository's `teamRefs` entry: a team of `organization`, the
/// repository's owner (`None` for a user-owned repository, which no team
/// can be granted on).
pub async fn resolve_team(
    reader: &dyn ReferenceReader,
    name: &str,
    organization: Option<&str>,
    our_instance: Option<&str>,
) -> Result<Result<ForgejoRef, Failure>, ClusterError> {
    let team = match resolve_required(reader, RefKind::Team, "", name, our_instance).await? {
        Ok(t) => t,
        Err(f) => return Ok(Err(f)),
    };
    // Ready implies the CR exists; its org must be the repository's.
    let theirs = reader
        .referenced(RefKind::Team, "", name)
        .await?
        .and_then(|cr| cr.organization_ref);
    if theirs.as_deref() != organization {
        return Ok(Err(Failure::new(
            ReasonCode::InvalidSpec,
            format!(
                "ForgejoTeam {name:?} belongs to ForgejoOrganization {:?}, not this repository's owner",
                theirs.unwrap_or_default()
            ),
        )));
    }
    Ok(Ok(team))
}

/// A team's `memberRefs` entry. A member not ready yet doesn't fail the
/// team (it is [`Member::Pending`]); one on another instance does.
pub async fn resolve_member(
    reader: &dyn ReferenceReader,
    name: &str,
    our_instance: Option<&str>,
) -> Result<Result<Member, Failure>, ClusterError> {
    Ok(Ok(
        match resolve(reader, RefKind::User, "", name, our_instance).await? {
            RefState::Ready(r) => Member::Ready(r.name),
            RefState::NotFound => Member::Pending {
                name: name.to_string(),
                why: "no such ForgejoUser".into(),
                login: None,
            },
            RefState::NotReady(why) => Member::Pending {
                name: name.to_string(),
                why,
                login: reader
                    .referenced(RefKind::User, "", name)
                    .await?
                    .and_then(|cr| cr.spec_name),
            },
            other @ RefState::OtherInstance(_) => {
                return Ok(Err(require(RefKind::User, name, other).unwrap_err()));
            }
        },
    ))
}

/// One key of a `Secret` in `namespace`, as UTF-8. Missing Secret/key or
/// non-UTF-8 content is a `ReferenceNotFound` failure, not a cluster error.
pub async fn read_secret_key(
    reader: &dyn ReferenceReader,
    namespace: &str,
    name: &str,
    key: &str,
) -> Result<Result<String, Failure>, ClusterError> {
    let value = reader
        .secret_key(namespace, name, key)
        .await?
        .and_then(|v| String::from_utf8(v).ok());
    Ok(value.ok_or_else(|| {
        Failure::new(
            ReasonCode::ReferenceNotFound,
            format!("Secret {namespace}/{name} has no UTF-8 key {key:?}"),
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ReferencedCr;
    use crate::test_support::FakeCluster;

    fn ready(id: i64, name: &str) -> ReferencedCr {
        ReferencedCr {
            forgejo: Some(ForgejoRef {
                id,
                name: name.into(),
            }),
            forgejo_name: Some(name.into()),
            ready: Some((true, "Reconciled".into())),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn resolution_states() {
        let cluster = FakeCluster::default();
        cluster.put(RefKind::User, "", "alice", ready(1, "alice"));
        cluster.put(
            RefKind::User,
            "",
            "oidc",
            ReferencedCr {
                ready: Some((false, "UserNotFound".into())),
                ..Default::default()
            },
        );
        cluster.put(RefKind::User, "", "fresh", ReferencedCr::default());
        cluster.put(
            RefKind::User,
            "",
            "elsewhere",
            ReferencedCr {
                instance_ref: Some("other".into()),
                ..ready(2, "elsewhere")
            },
        );
        let state = |name: &'static str| {
            let cluster = &cluster;
            async move {
                resolve(cluster, RefKind::User, "ns", name, None)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            state("alice").await,
            RefState::Ready(ForgejoRef {
                id: 1,
                name: "alice".into()
            })
        );
        assert_eq!(state("missing").await, RefState::NotFound);
        assert_eq!(
            state("oidc").await,
            RefState::NotReady("UserNotFound".into())
        );
        assert_eq!(
            state("fresh").await,
            RefState::NotReady("NotReconciledYet".into())
        );
        assert_eq!(
            state("elsewhere").await,
            RefState::OtherInstance(Some("other".into()))
        );
    }

    #[tokio::test]
    async fn namespaced_kinds_are_looked_up_in_the_referencing_namespace() {
        let cluster = FakeCluster::default();
        cluster.put(RefKind::Repository, "team-a", "app", ready(3, "weebo/app"));
        let found = resolve_required(&cluster, RefKind::Repository, "team-a", "app", None)
            .await
            .unwrap();
        assert_eq!(found.unwrap().id, 3);
        let other_ns = resolve_required(&cluster, RefKind::Repository, "team-b", "app", None)
            .await
            .unwrap();
        assert_eq!(other_ns.unwrap_err().reason, ReasonCode::ReferenceNotFound);
    }

    #[tokio::test]
    async fn recorded_name_ignores_readiness_but_not_the_instance() {
        let cluster = FakeCluster::default();
        cluster.put(
            RefKind::User,
            "",
            "bob",
            ReferencedCr {
                forgejo_name: Some("bob".into()),
                ready: Some((false, "Deleting".into())),
                ..Default::default()
            },
        );
        let name = recorded_name(&cluster, RefKind::User, "ns", "bob", None);
        assert_eq!(name.await.unwrap().as_deref(), Some("bob"));
        let name = recorded_name(&cluster, RefKind::User, "ns", "bob", Some("other"));
        assert_eq!(name.await.unwrap(), None);
    }

    #[tokio::test]
    async fn teams_must_belong_to_the_repository_owner() {
        let cluster = FakeCluster::default();
        cluster.put(
            RefKind::Team,
            "",
            "dev",
            ReferencedCr {
                organization_ref: Some("weebo".into()),
                ..ready(4, "Dev")
            },
        );
        let team = |org| resolve_team(&cluster, "dev", org, None);
        assert_eq!(team(Some("weebo")).await.unwrap().unwrap().name, "Dev");
        for org in [Some("other"), None] {
            let err = team(org).await.unwrap().unwrap_err();
            assert_eq!(err.reason, ReasonCode::InvalidSpec);
        }
    }

    #[tokio::test]
    async fn members_not_ready_are_pending_with_their_login() {
        let cluster = FakeCluster::default();
        cluster.put(
            RefKind::User,
            "",
            "alice",
            ReferencedCr {
                ready: Some((false, "UserNotFound".into())),
                spec_name: Some("Alice".into()),
                ..Default::default()
            },
        );
        let member = resolve_member(&cluster, "alice", None).await.unwrap();
        assert_eq!(
            member.unwrap(),
            Member::Pending {
                name: "alice".into(),
                why: "UserNotFound".into(),
                login: Some("Alice".into()),
            }
        );
        let missing = resolve_member(&cluster, "ghost", None).await.unwrap();
        assert!(matches!(
            missing.unwrap(),
            Member::Pending { login: None, .. }
        ));
        cluster.put(
            RefKind::User,
            "",
            "elsewhere",
            ReferencedCr {
                instance_ref: Some("other".into()),
                ..Default::default()
            },
        );
        let other = resolve_member(&cluster, "elsewhere", None).await.unwrap();
        assert_eq!(other.unwrap_err().reason, ReasonCode::InvalidSpec);
    }

    #[tokio::test]
    async fn secret_keys_must_be_utf8() {
        let cluster = FakeCluster::default();
        cluster.put_secret("ns", "s", "ok", b"value".to_vec());
        cluster.put_secret("ns", "s", "bin", vec![0xff, 0xfe]);
        let read = |key: &'static str| read_secret_key(&cluster, "ns", "s", key);
        assert_eq!(read("ok").await.unwrap().unwrap(), "value");
        for key in ["bin", "missing"] {
            let err = read(key).await.unwrap().unwrap_err();
            assert_eq!(err.reason, ReasonCode::ReferenceNotFound);
        }
    }

    #[tokio::test]
    async fn cluster_errors_are_not_failures() {
        let cluster = FakeCluster::default();
        cluster.fail_with("apiserver down");
        assert!(
            resolve(&cluster, RefKind::Team, "ns", "t", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_empty_instance_ref_matches_the_only_instance_by_name() {
        let cluster = FakeCluster::default();
        cluster.put(
            RefKind::Organization,
            "",
            "weebo",
            ReferencedCr {
                instance_ref: Some("main".into()),
                ..ready(1, "weebo")
            },
        );
        // Several instances: an empty ref is no instance in particular.
        let state = resolve(&cluster, RefKind::Organization, "", "weebo", None)
            .await
            .unwrap();
        assert!(matches!(state, RefState::OtherInstance(_)), "{state:?}");
        cluster.set_default_instance(Some("main"));
        let state = resolve(&cluster, RefKind::Organization, "", "weebo", None)
            .await
            .unwrap();
        assert!(matches!(state, RefState::Ready(_)), "{state:?}");
    }
}
