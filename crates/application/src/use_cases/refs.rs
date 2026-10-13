//! Resolution of `*Ref` fields to the Forgejo objects behind them, over
//! the [`ReferenceReader`] port. A ref is usable once the referenced CR
//! has a `status.forgejoId` and is `Ready` — controllers watch the
//! referenced kinds, so a ref that becomes ready re-triggers the
//! referencing CR right away. A user, organization or team may also be
//! referenced across namespaces (enabled and shared), or by its Forgejo
//! name (`remoteName`).

use domain::error::ReasonCode;

use api::common::IdentityRef;
use weebo_kit_application::refs::{RefError, Referenced};
use weebo_kit_application::sharing::shares_with;

use crate::ports::{
    BoundInstance, ClusterError, ForgejoGateway, ForgejoRef, RefKind, ReferenceReader,
    ReferencedCr, SecretKey,
};
use crate::use_cases::Failure;
use crate::use_cases::reconcile_team::Member;

/// The kit's ref state, over a Forgejo id + name: `Ready`, `NotFound`,
/// `NotReady(reason)`, `OtherInstance(theirs)`.
pub type RefState = weebo_kit_application::refs::RefState<ForgejoRef>;

/// `namespace`/`ours` are the referencing CR's namespace and resolved
/// instance: the referenced CR must be bound to the same one.
pub async fn resolve(
    reader: &dyn ReferenceReader,
    kind: RefKind,
    namespace: &str,
    name: &str,
    ours: &BoundInstance,
) -> Result<RefState, ClusterError> {
    let Some(cr) = reader.referenced(kind, namespace, name).await? else {
        return Ok(RefState::NotFound);
    };
    Ok(RefState::of(
        Some(Referenced {
            instance: cr.instance,
            remote: cr.forgejo,
            ready: cr.ready,
        }),
        ours,
    ))
}

/// `status.forgejoName` of the referenced CR whatever its readiness, for a
/// finalizer cleanup: it must still address what was created while the
/// referenced CR is itself not ready or being deleted.
pub async fn recorded_name(
    reader: &dyn ReferenceReader,
    kind: RefKind,
    namespace: &str,
    name: &str,
    ours: &BoundInstance,
) -> Result<Option<String>, ClusterError> {
    let Some(cr) = reader.referenced(kind, namespace, name).await? else {
        return Ok(None);
    };
    if cr
        .instance
        .as_ref()
        .is_some_and(|theirs| !weebo_kit_application::refs::same_instance(theirs, ours))
    {
        return Ok(None);
    }
    Ok(cr.forgejo_name)
}

/// A single required ref: anything but `Ready` fails the reconcile.
pub fn require(kind: RefKind, name: &str, state: RefState) -> Result<ForgejoRef, Failure> {
    state.require().map_err(|e| {
        let reason = match e {
            RefError::NotFound => ReasonCode::ReferenceNotFound,
            RefError::NotReconciled | RefError::NotReady(_) => ReasonCode::ReferenceNotReady,
            RefError::OtherInstance(_) => ReasonCode::InvalidSpec,
        };
        Failure::new(reason, e.describe(kind.as_str(), name))
    })
}

/// [`resolve`] then [`require`].
pub async fn resolve_required(
    reader: &dyn ReferenceReader,
    kind: RefKind,
    namespace: &str,
    name: &str,
    ours: &BoundInstance,
) -> Result<Result<ForgejoRef, Failure>, ClusterError> {
    let state = resolve(reader, kind, namespace, name, ours).await?;
    Ok(require(kind, name, state))
}

/// Where a reference to a user, organization or team ([`IdentityRef`]) is
/// followed from.
pub struct Referrer<'a> {
    pub reader: &'a dyn ReferenceReader,
    /// The referencing CR's namespace.
    pub namespace: &'a str,
    /// The referencing CR's instance: a referenced CR must be bound to it.
    pub instance: &'a BoundInstance,
    /// Whether the operator allows cross-namespace references
    /// (`references.crossNamespace`).
    pub cross_namespace: bool,
    /// Checks that a `remoteName` exists on the instance; `None` (a
    /// finalizer cleanup) takes it as is.
    pub gateway: Option<&'a dyn ForgejoGateway>,
}

/// The state of an [`IdentityRef`]: a CR of the referencing namespace, a
/// CR of another one (cross-namespace references enabled, and shared by
/// the target with this namespace — else `ReferenceNotAllowed`), or a
/// `remoteName` that must exist on the instance (a team's isn't looked up:
/// Forgejo addresses a repository's teams by name, and refuses an unknown
/// one itself).
pub async fn resolve_identity(
    from: &Referrer<'_>,
    kind: RefKind,
    r: &IdentityRef,
) -> Result<Result<RefState, Failure>, ClusterError> {
    let Some((namespace, name)) = r.target(from.namespace) else {
        let remote = r.remote_name.clone().unwrap_or_default();
        return Ok(resolve_remote(from.gateway, kind, &remote).await);
    };
    let Some(cr) = from.reader.referenced(kind, namespace, name).await? else {
        return Ok(Ok(RefState::NotFound));
    };
    if namespace != from.namespace
        && let Err(f) = check_shared(from, kind, r, &cr).await?
    {
        return Ok(Err(f));
    }
    Ok(Ok(RefState::of(
        Some(Referenced {
            instance: cr.instance,
            remote: cr.forgejo,
            ready: cr.ready,
        }),
        from.instance,
    )))
}

/// A CR of another namespace: only with cross-namespace references enabled,
/// and when it shares itself with the referencing namespace.
async fn check_shared(
    from: &Referrer<'_>,
    kind: RefKind,
    r: &IdentityRef,
    cr: &ReferencedCr,
) -> Result<Result<(), Failure>, ClusterError> {
    if !from.cross_namespace {
        return Ok(Err(Failure::new(
            ReasonCode::ReferenceNotAllowed,
            format!(
                "{} {r} is in another namespace and this operator doesn't allow cross-namespace \
                 references (references.crossNamespace)",
                kind.as_str()
            ),
        )));
    }
    let by_selector = cr
        .shared_with
        .as_ref()
        .is_some_and(|s| s.namespace_selector.is_some());
    let labels = match by_selector {
        true => from.reader.namespace_labels(from.namespace).await?,
        false => None,
    };
    if shares_with(
        cr.shared_with.as_ref(),
        Some(from.namespace),
        labels.as_ref(),
    ) {
        return Ok(Ok(()));
    }
    Ok(Err(Failure::new(
        ReasonCode::ReferenceNotAllowed,
        format!(
            "{} {r} doesn't share itself with namespace {:?} (its spec.sharedWith)",
            kind.as_str(),
            from.namespace
        ),
    )))
}

async fn resolve_remote(
    gateway: Option<&dyn ForgejoGateway>,
    kind: RefKind,
    name: &str,
) -> Result<RefState, Failure> {
    let unchecked = || ForgejoRef {
        id: 0,
        name: name.to_string(),
    };
    let Some(gateway) = gateway else {
        return Ok(RefState::Ready(unchecked()));
    };
    let found = match kind {
        RefKind::User => gateway.get_user(name).await?.map(|u| ForgejoRef {
            id: u.id,
            name: u.login,
        }),
        RefKind::Organization => gateway.get_organization(name).await?.map(|o| ForgejoRef {
            id: o.id,
            name: o.name,
        }),
        RefKind::Team | RefKind::Repository => Some(unchecked()),
    };
    Ok(found.map_or(RefState::NotFound, RefState::Ready))
}

/// [`resolve_identity`] then [`require`].
pub async fn resolve_identity_required(
    from: &Referrer<'_>,
    kind: RefKind,
    r: &IdentityRef,
) -> Result<Result<ForgejoRef, Failure>, ClusterError> {
    Ok(match resolve_identity(from, kind, r).await? {
        Ok(state) => require(kind, &r.to_string(), state),
        Err(f) => Err(f),
    })
}

/// `status.forgejoName` of the referenced user, organization or team
/// whatever its readiness (a finalizer cleanup), or its `remoteName`.
pub async fn recorded_identity(
    reader: &dyn ReferenceReader,
    kind: RefKind,
    namespace: &str,
    r: &IdentityRef,
    ours: &BoundInstance,
) -> Result<Option<String>, ClusterError> {
    match r.target(namespace) {
        Some((namespace, name)) => recorded_name(reader, kind, namespace, name, ours).await,
        None => Ok(r.remote_name.clone()),
    }
}

/// The Forgejo name an [`IdentityRef`] stands for — what the namespace
/// policy's `allowedUsers`/`allowedOrganizations` match: a `remoteName`,
/// else the referenced CR's recorded name, else the one its spec asks for,
/// else (no such CR) its CR name.
pub async fn forgejo_name(
    reader: &dyn ReferenceReader,
    kind: RefKind,
    namespace: &str,
    r: &IdentityRef,
) -> Result<String, ClusterError> {
    let Some((namespace, name)) = r.target(namespace) else {
        return Ok(r.remote_name.clone().unwrap_or_default());
    };
    let cr = reader.referenced(kind, namespace, name).await?;
    Ok(cr
        .and_then(|cr| cr.forgejo_name.or(cr.spec_name))
        .unwrap_or_else(|| name.to_string()))
}

/// A repository's `teamRefs` entry: a team of `organization` (the Forgejo
/// name of the repository's owner; `None` for a user-owned repository,
/// which no team can be granted on).
pub async fn resolve_team(
    from: &Referrer<'_>,
    r: &IdentityRef,
    organization: Option<&str>,
) -> Result<Result<ForgejoRef, Failure>, ClusterError> {
    let team = match resolve_identity_required(from, RefKind::Team, r).await? {
        Ok(t) => t,
        Err(f) => return Ok(Err(f)),
    };
    let Some((namespace, name)) = r.target(from.namespace) else {
        // By name: Forgejo looks it up in the owner organization.
        return Ok(match organization {
            Some(_) => Ok(team),
            None => Err(Failure::new(
                ReasonCode::InvalidSpec,
                format!("team {r} can't be granted on a user-owned repository"),
            )),
        });
    };
    // Ready implies the CR exists; its org must be the repository's.
    let theirs = from
        .reader
        .referenced(RefKind::Team, namespace, name)
        .await?
        .and_then(|cr| cr.organization);
    if organization.is_none() || theirs.as_deref() != organization {
        return Ok(Err(Failure::new(
            ReasonCode::InvalidSpec,
            format!(
                "ForgejoTeam {r} belongs to organization {:?}, not this repository's owner",
                theirs.unwrap_or_default()
            ),
        )));
    }
    Ok(Ok(team))
}

/// A team's `memberRefs` entry. A member not ready yet doesn't fail the
/// team (it is [`Member::Pending`]); one on another instance, or not
/// allowed, does.
pub async fn resolve_member(
    from: &Referrer<'_>,
    r: &IdentityRef,
) -> Result<Result<Member, Failure>, ClusterError> {
    let state = match resolve_identity(from, RefKind::User, r).await? {
        Ok(state) => state,
        Err(f) => return Ok(Err(f)),
    };
    let shown = r.to_string();
    Ok(Ok(match state {
        RefState::Ready(r) => Member::Ready(r.name),
        RefState::NotFound => Member::Pending {
            name: shown,
            why: match &r.remote_name {
                Some(_) => "no such user in Forgejo".into(),
                None => "no such ForgejoUser".into(),
            },
            login: r.remote_name.clone(),
        },
        state @ (RefState::NotReconciled | RefState::NotReady(_)) => {
            let why = match state {
                RefState::NotReady(why) => why,
                _ => "not reconciled yet".into(),
            };
            let login = match r.target(from.namespace) {
                Some((namespace, name)) => from
                    .reader
                    .referenced(RefKind::User, namespace, name)
                    .await?
                    .and_then(|cr| cr.spec_name),
                None => None,
            };
            Member::Pending {
                name: shown,
                why,
                login,
            }
        }
        other @ RefState::OtherInstance(_) => {
            return Ok(Err(require(RefKind::User, &shown, other).unwrap_err()));
        }
    }))
}

/// One key of a credential `Secret` in `namespace`, as UTF-8. Missing
/// Secret/key or non-UTF-8 content is a `ReferenceNotFound` failure, an
/// unlabelled Secret `SecretNotAllowed`, not a cluster error.
pub async fn read_secret_key(
    reader: &dyn ReferenceReader,
    namespace: &str,
    name: &str,
    key: &str,
) -> Result<Result<String, Failure>, ClusterError> {
    let value = match reader.secret_key(namespace, name, key).await? {
        SecretKey::Value(v) => String::from_utf8(v).ok(),
        SecretKey::Missing => None,
        SecretKey::NotLabelled => {
            return Ok(Err(Failure::new(
                ReasonCode::SecretNotAllowed,
                format!(
                    "Secret {namespace}/{name} is not labelled {}=\"true\": only a Secret \
                     labelled for it is handed to Forgejo",
                    api::CREDENTIAL_LABEL
                ),
            )));
        }
    };
    Ok(value.ok_or_else(|| {
        Failure::new(
            ReasonCode::ReferenceNotFound,
            format!("Secret {namespace}/{name} has no UTF-8 key {key:?}"),
        )
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::ports::{ReferencedCr, SharedWith};

    fn main() -> BoundInstance {
        BoundInstance::cluster("main")
    }

    fn other() -> Option<BoundInstance> {
        Some(BoundInstance::cluster("other"))
    }
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
        cluster.put(RefKind::User, "ns", "alice", ready(1, "alice"));
        cluster.put(
            RefKind::User,
            "ns",
            "oidc",
            ReferencedCr {
                ready: Some((false, "UserNotFound".into())),
                ..Default::default()
            },
        );
        cluster.put(RefKind::User, "ns", "fresh", ReferencedCr::default());
        cluster.put(
            RefKind::User,
            "ns",
            "elsewhere",
            ReferencedCr {
                instance: other(),
                ..ready(2, "elsewhere")
            },
        );
        let state = |name: &'static str| {
            let cluster = &cluster;
            async move {
                resolve(cluster, RefKind::User, "ns", name, &main())
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
        assert_eq!(state("fresh").await, RefState::NotReconciled);
        assert_eq!(
            state("elsewhere").await,
            RefState::OtherInstance(BoundInstance::cluster("other"))
        );
    }

    #[tokio::test]
    async fn namespaced_kinds_are_looked_up_in_the_referencing_namespace() {
        let cluster = FakeCluster::default();
        cluster.put(RefKind::Repository, "team-a", "app", ready(3, "weebo/app"));
        let found = resolve_required(&cluster, RefKind::Repository, "team-a", "app", &main())
            .await
            .unwrap();
        assert_eq!(found.unwrap().id, 3);
        let other_ns = resolve_required(&cluster, RefKind::Repository, "team-b", "app", &main())
            .await
            .unwrap();
        assert_eq!(other_ns.unwrap_err().reason, ReasonCode::ReferenceNotFound);
    }

    #[tokio::test]
    async fn recorded_name_ignores_readiness_but_not_the_instance() {
        let cluster = FakeCluster::default();
        cluster.put(
            RefKind::User,
            "ns",
            "bob",
            ReferencedCr {
                forgejo_name: Some("bob".into()),
                ready: Some((false, "Deleting".into())),
                ..Default::default()
            },
        );
        let ours = main();
        let name = recorded_name(&cluster, RefKind::User, "ns", "bob", &ours);
        assert_eq!(name.await.unwrap().as_deref(), Some("bob"));
        cluster.put(
            RefKind::User,
            "ns",
            "carol",
            ReferencedCr {
                forgejo_name: Some("carol".into()),
                instance: other(),
                ..Default::default()
            },
        );
        let name = recorded_name(&cluster, RefKind::User, "ns", "carol", &ours);
        assert_eq!(name.await.unwrap(), None);
    }

    fn from<'a>(cluster: &'a FakeCluster, ours: &'a BoundInstance) -> Referrer<'a> {
        Referrer {
            reader: cluster,
            namespace: "team-a",
            instance: ours,
            cross_namespace: false,
            gateway: None,
        }
    }

    #[tokio::test]
    async fn teams_must_belong_to_the_repository_owner() {
        let cluster = FakeCluster::default();
        cluster.put(
            RefKind::Team,
            "team-a",
            "dev",
            ReferencedCr {
                organization: Some("weebo".into()),
                ..ready(4, "Dev")
            },
        );
        let ours = main();
        let from = from(&cluster, &ours);
        let dev = IdentityRef::named("dev");
        let team = |org| resolve_team(&from, &dev, org);
        assert_eq!(team(Some("weebo")).await.unwrap().unwrap().name, "Dev");
        for org in [Some("other"), None] {
            let err = team(org).await.unwrap().unwrap_err();
            assert_eq!(err.reason, ReasonCode::InvalidSpec);
        }
        // By name: Forgejo resolves it in the owner organization.
        let remote = IdentityRef::remote("Dev");
        let team = resolve_team(&from, &remote, Some("weebo")).await;
        assert_eq!(team.unwrap().unwrap().name, "Dev");
    }

    #[tokio::test]
    async fn members_not_ready_are_pending_with_their_login() {
        let cluster = FakeCluster::default();
        cluster.put(
            RefKind::User,
            "team-a",
            "alice",
            ReferencedCr {
                ready: Some((false, "UserNotFound".into())),
                spec_name: Some("Alice".into()),
                ..Default::default()
            },
        );
        let ours = main();
        let from = from(&cluster, &ours);
        let member = resolve_member(&from, &IdentityRef::named("alice"))
            .await
            .unwrap();
        assert_eq!(
            member.unwrap(),
            Member::Pending {
                name: "alice".into(),
                why: "UserNotFound".into(),
                login: Some("Alice".into()),
            }
        );
        let missing = resolve_member(&from, &IdentityRef::named("ghost"))
            .await
            .unwrap();
        assert!(matches!(
            missing.unwrap(),
            Member::Pending { login: None, .. }
        ));
        cluster.put(
            RefKind::User,
            "team-a",
            "elsewhere",
            ReferencedCr {
                instance: other(),
                ..Default::default()
            },
        );
        let other = resolve_member(&from, &IdentityRef::named("elsewhere"))
            .await
            .unwrap();
        assert_eq!(other.unwrap_err().reason, ReasonCode::InvalidSpec);
    }

    #[tokio::test]
    async fn another_namespace_needs_the_operator_and_the_target_to_agree() {
        let cluster = FakeCluster::default();
        let shared = |with: SharedWith| ReferencedCr {
            shared_with: Some(with),
            ..ready(7, "platform")
        };
        cluster.put(
            RefKind::Organization,
            "ids",
            "open",
            shared(SharedWith {
                namespaces: vec!["team-a".into()],
                ..Default::default()
            }),
        );
        cluster.put(RefKind::Organization, "ids", "closed", ready(8, "closed"));
        let selector = k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
            match_labels: Some(BTreeMap::from([("tier".into(), "front".into())])),
            ..Default::default()
        };
        cluster.put(
            RefKind::Organization,
            "ids",
            "labelled",
            shared(SharedWith {
                namespace_selector: Some(selector),
                ..Default::default()
            }),
        );
        let ours = main();
        let mut from = from(&cluster, &ours);
        async fn state(from: &Referrer<'_>, name: &str) -> Result<RefState, Failure> {
            let r = IdentityRef {
                namespace: Some("ids".into()),
                ..IdentityRef::named(name)
            };
            resolve_identity(from, RefKind::Organization, &r)
                .await
                .unwrap()
        }
        // Disabled for the operator: refused whatever the target says.
        let refused = state(&from, "open").await.unwrap_err();
        assert_eq!(refused.reason, ReasonCode::ReferenceNotAllowed);
        from.cross_namespace = true;
        assert!(matches!(state(&from, "open").await, Ok(RefState::Ready(_))));
        let refused = state(&from, "closed").await.unwrap_err();
        assert_eq!(refused.reason, ReasonCode::ReferenceNotAllowed);
        assert!(state(&from, "labelled").await.is_err());
        cluster.set_namespace_labels("team-a", BTreeMap::from([("tier".into(), "front".into())]));
        assert!(state(&from, "labelled").await.is_ok());
    }

    #[tokio::test]
    async fn a_remote_name_must_exist_on_the_instance() {
        let cluster = FakeCluster::default();
        let forgejo = crate::test_support::FakeForgejo::default();
        let id = forgejo.insert_user("ops");
        let ours = main();
        let mut from = from(&cluster, &ours);
        from.gateway = Some(&forgejo);
        let found = resolve_identity_required(&from, RefKind::User, &IdentityRef::remote("ops"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            found,
            ForgejoRef {
                id,
                name: "ops".into()
            }
        );
        let missing =
            resolve_identity_required(&from, RefKind::User, &IdentityRef::remote("ghost"))
                .await
                .unwrap()
                .unwrap_err();
        assert_eq!(missing.reason, ReasonCode::ReferenceNotFound);
        // The policy sees the Forgejo name, whatever the CR name.
        cluster.put(
            RefKind::User,
            "team-a",
            "bot",
            ReferencedCr {
                spec_name: Some("ci-bot".into()),
                ..Default::default()
            },
        );
        let (bot, ops) = (IdentityRef::named("bot"), IdentityRef::remote("ops"));
        let named = forgejo_name(&cluster, RefKind::User, "team-a", &bot);
        assert_eq!(named.await.unwrap(), "ci-bot");
        let remote = forgejo_name(&cluster, RefKind::User, "team-a", &ops);
        assert_eq!(remote.await.unwrap(), "ops");
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
    async fn an_unlabelled_secret_is_never_read() {
        let cluster = FakeCluster::default();
        cluster.put_unlabelled_secret("ns", "s", "token", b"value".to_vec());
        let err = read_secret_key(&cluster, "ns", "s", "token")
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.reason, ReasonCode::SecretNotAllowed);
        assert!(!err.message.contains("value"), "{}", err.message);
    }

    #[tokio::test]
    async fn cluster_errors_are_not_failures() {
        let cluster = FakeCluster::default();
        cluster.fail_with("apiserver down");
        assert!(
            resolve(&cluster, RefKind::Team, "ns", "t", &main())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_local_instance_of_the_same_name_is_another_instance() {
        let cluster = FakeCluster::default();
        cluster.put(
            RefKind::Organization,
            "",
            "weebo",
            ReferencedCr {
                instance: Some(BoundInstance::local("team-a", "main")),
                ..ready(1, "weebo")
            },
        );
        let state = resolve(&cluster, RefKind::Organization, "", "weebo", &main())
            .await
            .unwrap();
        assert!(matches!(state, RefState::OtherInstance(_)), "{state:?}");
        let ours = BoundInstance::local("team-a", "main");
        let state = resolve(&cluster, RefKind::Organization, "", "weebo", &ours)
            .await
            .unwrap();
        assert!(matches!(state, RefState::Ready(_)), "{state:?}");
    }
}
