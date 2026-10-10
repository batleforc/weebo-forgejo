use std::sync::Arc;
use std::time::Instant;

use api::repository::ForgejoRepositorySpec;
use api::{ForgejoOrganization, ForgejoRepository, ForgejoTeam, ForgejoUser};
use application::ports::{GenerateOptions, MigrateOptions, RefKind};
use application::use_cases::admission::enforce;
use application::use_cases::reconcile_repository::{
    Owner, RepositoryInput, Source, cleanup_repository, init_options, reconcile_repository,
    validate,
};
use application::use_cases::refs::{read_secret_key, resolve_required, resolve_team};
use application::use_cases::{Failure, Outcome};
use domain::error::ReasonCode;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Client, ResourceExt};

use super::status::current_ref;
use super::{Ctx, Error, FINALIZER, allows_disruptive_update, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoRepository";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let client_for_policies = client.clone();
    let controller = super::controller(Api::<ForgejoRepository>::all(client.clone()));
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    // Re-trigger on anything a repository references: its owner, its
    // teams, and its template (another repository in the same namespace).
    let by_org = controller.store();
    let by_user = controller.store();
    let by_team = controller.store();
    let by_template = controller.store();
    let results = controller
        .watches(
            Api::<ForgejoOrganization>::all(client.clone()),
            watcher::Config::default(),
            move |org| {
                let name = org.name_any();
                by_org
                    .state()
                    .into_iter()
                    .filter(|r| {
                        r.spec
                            .organization_ref
                            .as_ref()
                            .is_some_and(|o| o.name == name)
                    })
                    .map(|r| ObjectRef::from_obj(r.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<ForgejoUser>::all(client.clone()),
            watcher::Config::default(),
            move |user| {
                let name = user.name_any();
                by_user
                    .state()
                    .into_iter()
                    .filter(|r| r.spec.user_ref.as_ref().is_some_and(|u| u.name == name))
                    .map(|r| ObjectRef::from_obj(r.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<ForgejoTeam>::all(client.clone()),
            watcher::Config::default(),
            move |team| {
                let name = team.name_any();
                by_team
                    .state()
                    .into_iter()
                    .filter(|r| r.spec.team_refs.iter().any(|t| t.name == name))
                    .map(|r| ObjectRef::from_obj(r.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<ForgejoRepository>::all(client),
            watcher::Config::default(),
            move |template| {
                let (name, ns) = (template.name_any(), template.namespace());
                by_template
                    .state()
                    .into_iter()
                    .filter(|r| {
                        r.namespace() == ns
                            && r.spec
                                .from_template
                                .as_ref()
                                .is_some_and(|t| t.repository_ref.name == name)
                    })
                    .map(|r| ObjectRef::from_obj(r.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<api::ForgejoNamespacePolicy>::all(client_for_policies),
            watcher::Config::default(),
            move |_| {
                by_policy
                    .state()
                    .into_iter()
                    .map(|o| ObjectRef::from_obj(o.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<ForgejoRepository>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if super::import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoRepository> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(repo) => apply(&api, &repo, &ctx).await,
            FinalizerEvent::Cleanup(repo) => {
                super::finalize(repo.as_ref(), &ctx, cleanup(&repo, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

async fn apply(
    api: &Api<ForgejoRepository>,
    repo: &ForgejoRepository,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&repo.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);

    let namespace = current.namespace().unwrap_or_default();
    let outcome = match enforce(
        ctx.policies.as_ref(),
        ctx.refs.as_ref(),
        &namespace,
        &current,
    )
    .await?
    {
        // Re-checked here too: a policy may have changed since admission.
        Err(f) => Outcome::failed(current_ref(&current), f),
        Ok(()) => match resolve_inputs(&current, owned.is_none(), ctx).await? {
            Err(f) => Outcome::failed(owned, f),
            Ok((owner, source, teams)) => {
                match ctx
                    .gateways
                    .gateway_for(current.spec.instance_ref.as_deref())
                    .await
                {
                    Ok(gateway) => {
                        let input = RepositoryInput {
                            spec: &current.spec,
                            current: owned,
                            owner,
                            source,
                            teams,
                            allow_disruptive_update: allows_disruptive_update(&current.metadata),
                        };
                        reconcile_repository(input, gateway.as_ref()).await
                    }
                    Err(e) => Outcome::failed(owned, Failure::new(e.reason(), e.to_string())),
                }
            }
        },
    };

    record_reconcile("ForgejoRepository", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

type Inputs = (Owner, Result<Source, Failure>, Vec<String>);

async fn resolve_inputs(
    repo: &ForgejoRepository,
    creating: bool,
    ctx: &Ctx,
) -> Result<Result<Inputs, Failure>, Error> {
    let spec = &repo.spec;
    if let Err(f) = validate(spec) {
        return Ok(Err(f));
    }
    let instance = spec.instance_ref.as_deref();
    let ns = repo.namespace().unwrap_or_default();
    let refs = ctx.refs.as_ref();

    let owner = if let Some(org) = &spec.organization_ref {
        match resolve_required(refs, RefKind::Organization, &ns, &org.name, instance).await? {
            Ok(r) => Owner::Organization(r.name),
            Err(f) => return Ok(Err(f)),
        }
    } else {
        let user = spec
            .user_ref
            .as_ref()
            .expect("validated: exactly one owner");
        match resolve_required(refs, RefKind::User, &ns, &user.name, instance).await? {
            Ok(r) => Owner::User(r.name),
            Err(f) => return Ok(Err(f)),
        }
    };

    // Resolved even when a repository is owned, in case it was deleted out
    // of band; only a create needs it to succeed. An owned repository
    // keeps being reconciled while its source is unreadable (a template
    // CR not ready, a migrate Secret forbidden or an apiserver hiccup).
    let source = match source(spec, &ns, ctx).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(f)) if creating => return Ok(Err(f)),
        Err(e) if creating => return Err(e),
        Ok(Err(f)) => Err(f),
        Err(e) => {
            tracing::warn!(
                repository = %repo.name_any(),
                error = %e,
                "source of an owned repository unreadable; only needed to recreate it"
            );
            Err(Failure::new(ReasonCode::ReferenceNotReady, e.to_string()))
        }
    };

    let mut teams = Vec::with_capacity(spec.team_refs.len());
    let org = spec.organization_ref.as_ref().map(|o| o.name.as_str());
    for team_ref in &spec.team_refs {
        match resolve_team(refs, &team_ref.name, org, instance).await? {
            Ok(team) => teams.push(team.name),
            Err(f) => return Ok(Err(f)),
        }
    }
    Ok(Ok((owner, source, teams)))
}

async fn source(
    spec: &ForgejoRepositorySpec,
    ns: &str,
    ctx: &Ctx,
) -> Result<Result<Source, Failure>, Error> {
    if let Some(t) = &spec.from_template {
        let name = &t.repository_ref.name;
        let instance = spec.instance_ref.as_deref();
        let template = resolve_required(ctx.refs.as_ref(), RefKind::Repository, ns, name, instance);
        return Ok(template.await?.map(|r| {
            Source::Template(
                r.name,
                GenerateOptions {
                    git_content: t.git_content,
                    topics: t.topics,
                    labels: t.labels,
                    webhooks: t.webhooks,
                    protected_branches: t.protected_branches,
                    git_hooks: t.git_hooks,
                    avatar: t.avatar,
                },
            )
        }));
    }
    if let Some(m) = &spec.migrate {
        let mut options = MigrateOptions {
            clone_addr: m.clone_addr.clone(),
            service: m.service.clone(),
            mirror: m.mirror,
            mirror_interval: m.mirror_interval.clone(),
            lfs: m.lfs,
            wiki: m.wiki,
            issues: m.issues,
            pull_requests: m.pull_requests,
            releases: m.releases,
            labels: m.labels,
            milestones: m.milestones,
            ..Default::default()
        };
        if let Some(auth) = &m.auth_secret_ref {
            for (key, slot) in [
                (&auth.username_key, &mut options.auth_username),
                (&auth.password_key, &mut options.auth_password),
                (&auth.token_key, &mut options.auth_token),
            ] {
                if let Some(key) = key {
                    match read_secret_key(ctx.refs.as_ref(), ns, &auth.name, key).await? {
                        Ok(v) => *slot = Some(v),
                        Err(f) => return Ok(Err(f)),
                    }
                }
            }
        }
        return Ok(Ok(Source::Migrate(options)));
    }
    Ok(Ok(Source::Empty(init_options(spec))))
}

async fn cleanup(repo: &ForgejoRepository, ctx: &Ctx) -> Result<Action, Error> {
    let gateway = super::cleanup_gateway(ctx, repo.spec.instance_ref.as_deref()).await;
    cleanup_repository(&repo.spec, current_ref(repo).as_ref(), gateway.as_deref())
        .await
        .map_err(Error::Cleanup)?;
    Ok(Action::await_change())
}
