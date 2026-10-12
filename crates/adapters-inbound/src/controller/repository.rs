use std::sync::Arc;
use std::time::Instant;

use api::repository::ForgejoRepositorySpec;
use api::{ForgejoOrganization, ForgejoRepository, ForgejoTeam, ForgejoUser};
use application::ports::{BoundInstance, ForgejoGateway, GenerateOptions, MigrateOptions, RefKind};
use application::use_cases::admission::enforce_on;
use application::use_cases::reconcile_repository::{
    Owner, RepositoryInput, Source, cleanup_repository, init_options, reconcile_repository,
    validate,
};
use application::use_cases::refs::{
    read_secret_key, resolve_identity_required, resolve_required, resolve_team,
};
use application::use_cases::{Failure, Outcome};
use domain::error::ReasonCode;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};

use super::status::current_ref;
use super::{
    Ctx, Error, FINALIZER, ScopedWatches, allows_disruptive_update, error_policy, requeue_after,
    status,
};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoRepository";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(
        ctx.scope.api::<ForgejoRepository>(client.clone()),
        &ctx.scope,
    );
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    // Re-trigger on anything a repository references: its owner, its
    // teams, and its template (another repository in the same namespace,
    // or one in any namespace whose Forgejo name it generates from).
    let by_org = controller.store();
    let by_user = controller.store();
    let by_team = controller.store();
    let by_template = controller.store();
    let results = controller
        .watches_in::<ForgejoOrganization, _>(&ctx, &client, move |org| {
            let (name, ns) = (org.name_any(), org.namespace());
            by_org
                .state()
                .into_iter()
                .filter(|r| {
                    r.spec.organization_ref.as_ref().is_some_and(|o| {
                        o.points_at(r.namespace().as_deref(), ns.as_deref(), &name)
                    })
                })
                .map(|r| ObjectRef::from_obj(r.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<ForgejoUser, _>(&ctx, &client, move |user| {
            let (name, ns) = (user.name_any(), user.namespace());
            by_user
                .state()
                .into_iter()
                .filter(|r| {
                    r.spec.user_ref.as_ref().is_some_and(|u| {
                        u.points_at(r.namespace().as_deref(), ns.as_deref(), &name)
                    })
                })
                .map(|r| ObjectRef::from_obj(r.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<ForgejoTeam, _>(&ctx, &client, move |team| {
            let (name, ns) = (team.name_any(), team.namespace());
            by_team
                .state()
                .into_iter()
                .filter(|r| {
                    let repo_ns = r.namespace();
                    r.spec
                        .team_refs
                        .iter()
                        .any(|t| t.points_at(repo_ns.as_deref(), ns.as_deref(), &name))
                })
                .map(|r| ObjectRef::from_obj(r.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<ForgejoRepository, _>(&ctx, &client, move |template| {
            let (name, ns) = (template.name_any(), template.namespace());
            let forgejo_name = template
                .status
                .as_ref()
                .and_then(|s| s.forgejo_name.clone());
            by_template
                .state()
                .into_iter()
                .filter(|r| {
                    r.spec.from_template.as_ref().is_some_and(|t| {
                        let by_ref = t.repository_ref.as_ref().is_some_and(|t| t.name == name);
                        (by_ref && r.namespace() == ns)
                            || (t.repository.is_some() && t.repository == forgejo_name)
                    })
                })
                .map(|r| ObjectRef::from_obj(r.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<api::ForgejoNamespacePolicy, _>(&ctx, &client, move |_| {
            by_policy
                .state()
                .into_iter()
                .map(|o| ObjectRef::from_obj(o.as_ref()))
                .collect::<Vec<_>>()
        })
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
    let outcome = match super::instance_of(ctx, &current).await {
        Err(f) => Outcome::failed(current_ref(&current), f),
        Ok(bound) => match enforce_on(
            ctx.policies.as_ref(),
            ctx.refs.as_ref(),
            &namespace,
            &current,
            Some(&bound),
        )
        .await?
        {
            // Re-checked here too: a policy may have changed since admission.
            Err(f) => Outcome::failed(current_ref(&current), f),
            Ok(()) => match ctx.gateways.gateway_for(&bound).await {
                Err(e) => Outcome::failed(owned, Failure::new(e.reason(), e.to_string())),
                Ok(gateway) => {
                    match resolve_inputs(&current, owned.is_none(), &bound, gateway.as_ref(), ctx)
                        .await?
                    {
                        Ok((owner, source, teams)) => {
                            let input = RepositoryInput {
                                spec: &current.spec,
                                current: owned,
                                owner,
                                source,
                                teams,
                                allow_disruptive_update: allows_disruptive_update(
                                    &current.metadata,
                                ),
                            };
                            reconcile_repository(input, gateway.as_ref()).await
                        }
                        Err(f) => Outcome::failed(owned, f),
                    }
                }
            },
        }
        .on(bound),
    };

    record_reconcile("ForgejoRepository", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

type Inputs = (Owner, Result<Source, Failure>, Vec<String>);

async fn resolve_inputs(
    repo: &ForgejoRepository,
    creating: bool,
    instance: &BoundInstance,
    gateway: &dyn ForgejoGateway,
    ctx: &Ctx,
) -> Result<Result<Inputs, Failure>, Error> {
    let spec = &repo.spec;
    if let Err(f) = validate(spec) {
        return Ok(Err(f));
    }
    let ns = repo.namespace().unwrap_or_default();
    let from = super::referrer(ctx, &ns, instance, Some(gateway));

    let owner = if let Some(org) = &spec.organization_ref {
        match resolve_identity_required(&from, RefKind::Organization, org).await? {
            Ok(r) => Owner::Organization(r.name),
            Err(f) => return Ok(Err(f)),
        }
    } else {
        let user = spec
            .user_ref
            .as_ref()
            .expect("validated: exactly one owner");
        match resolve_identity_required(&from, RefKind::User, user).await? {
            Ok(r) => Owner::User(r.name),
            Err(f) => return Ok(Err(f)),
        }
    };

    // Resolved even when a repository is owned, in case it was deleted out
    // of band; only a create needs it to succeed. An owned repository
    // keeps being reconciled while its source is unreadable (a template
    // CR not ready, a migrate Secret forbidden or an apiserver hiccup).
    let source = match source(spec, &ns, instance, ctx).await {
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
    let org = match &owner {
        Owner::Organization(name) => Some(name.as_str()),
        Owner::User(_) => None,
    };
    for team_ref in &spec.team_refs {
        match resolve_team(&from, team_ref, org).await? {
            Ok(team) => teams.push(team.name),
            Err(f) => return Ok(Err(f)),
        }
    }
    Ok(Ok((owner, source, teams)))
}

async fn source(
    spec: &ForgejoRepositorySpec,
    ns: &str,
    instance: &BoundInstance,
    ctx: &Ctx,
) -> Result<Result<Source, Failure>, Error> {
    if let Some(t) = &spec.from_template {
        let options = GenerateOptions {
            git_content: t.git_content,
            topics: t.topics,
            labels: t.labels,
            webhooks: t.webhooks,
            protected_branches: t.protected_branches,
            git_hooks: t.git_hooks,
            avatar: t.avatar,
        };
        // By name: Forgejo itself says whether it exists and is a template.
        let Some(template_ref) = &t.repository_ref else {
            let name = t
                .repository
                .clone()
                .expect("validated: one template source");
            return Ok(Ok(Source::Template(name, options)));
        };
        let refs = ctx.refs.as_ref();
        let template =
            resolve_required(refs, RefKind::Repository, ns, &template_ref.name, instance);
        return Ok(template.await?.map(|r| Source::Template(r.name, options)));
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
    let instance = super::cleanup_instance(ctx, repo).await;
    let gateway = super::cleanup_gateway(ctx, &instance).await;
    cleanup_repository(&repo.spec, current_ref(repo).as_ref(), gateway.as_deref())
        .await
        .map_err(Error::Cleanup)?;
    Ok(Action::await_change())
}
