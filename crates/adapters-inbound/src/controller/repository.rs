use std::sync::Arc;
use std::time::Instant;

use api::repository::ForgejoRepositorySpec;
use api::{ForgejoOrganization, ForgejoRepository, ForgejoTeam, ForgejoUser};
use application::ports::{GenerateOptions, MigrateOptions, RepositoryInitOptions};
use application::use_cases::reconcile_repository::{
    Owner, RepositoryInput, Source, cleanup_repository, reconcile_repository, validate,
};
use application::use_cases::{Failure, Outcome};
use domain::error::ReasonCode;
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{Controller, watcher};
use kube::{Client, ResourceExt};

use super::refs::{read_secret_key, require, resolve};
use super::status::current_ref;
use super::{Ctx, Error, FINALIZER, allows_disruptive_update, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let client_for_policies = client.clone();
    let controller = Controller::new(
        Api::<ForgejoRepository>::all(client.clone()),
        watcher::Config::default(),
    );
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    // Re-trigger on anything a repository references: its owner, its
    // teams, and its template (another repository in the same namespace).
    let by_org = controller.store();
    let by_user = controller.store();
    let by_team = controller.store();
    let by_template = controller.store();
    controller
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
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(err) = res {
                tracing::debug!(error = %err, "ForgejoRepository reconcile failed");
            }
        })
        .await;
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
            FinalizerEvent::Cleanup(repo) => cleanup(&repo, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(e.to_string()))
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
    let outcome = match crate::admission::enforce(&ctx.client, &namespace, &current).await? {
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

type Inputs = (Owner, Option<Source>, Vec<String>);

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

    let owner = if let Some(org) = &spec.organization_ref {
        let orgs: Api<ForgejoOrganization> = Api::all(ctx.client.clone());
        match require(
            "ForgejoOrganization",
            &org.name,
            resolve(&orgs, &org.name, instance).await?,
        ) {
            Ok(r) => Owner::Organization(r.name),
            Err(f) => return Ok(Err(f)),
        }
    } else {
        let user = spec
            .user_ref
            .as_ref()
            .expect("validated: exactly one owner");
        let users: Api<ForgejoUser> = Api::all(ctx.client.clone());
        match require(
            "ForgejoUser",
            &user.name,
            resolve(&users, &user.name, instance).await?,
        ) {
            Ok(r) => Owner::User(r.name),
            Err(f) => return Ok(Err(f)),
        }
    };

    let source = if creating {
        match source(spec, &ns, ctx).await? {
            Ok(s) => Some(s),
            Err(f) => return Ok(Err(f)),
        }
    } else {
        None
    };

    let mut teams = Vec::with_capacity(spec.team_refs.len());
    let teams_api: Api<ForgejoTeam> = Api::all(ctx.client.clone());
    for team_ref in &spec.team_refs {
        let state = resolve(&teams_api, &team_ref.name, instance).await?;
        let team = match require("ForgejoTeam", &team_ref.name, state) {
            Ok(t) => t,
            Err(f) => return Ok(Err(f)),
        };
        // Ready implies the CR exists; its org must be the repository's.
        let cr = teams_api.get(&team_ref.name).await?;
        let org = spec.organization_ref.as_ref().map(|o| o.name.as_str());
        if Some(cr.spec.organization_ref.name.as_str()) != org {
            return Ok(Err(Failure::new(
                ReasonCode::InvalidSpec,
                format!(
                    "ForgejoTeam {:?} belongs to ForgejoOrganization {:?}, not this repository's owner",
                    team_ref.name, cr.spec.organization_ref.name
                ),
            )));
        }
        teams.push(team.name);
    }
    Ok(Ok((owner, source, teams)))
}

async fn source(
    spec: &ForgejoRepositorySpec,
    ns: &str,
    ctx: &Ctx,
) -> Result<Result<Source, Failure>, Error> {
    if let Some(t) = &spec.from_template {
        let repos: Api<ForgejoRepository> = Api::namespaced(ctx.client.clone(), ns);
        let state = resolve(&repos, &t.repository_ref.name, spec.instance_ref.as_deref()).await?;
        return Ok(
            require("ForgejoRepository", &t.repository_ref.name, state).map(|r| {
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
            }),
        );
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
                    match read_secret_key(&ctx.client, ns, &auth.name, key).await? {
                        Ok(v) => *slot = Some(v),
                        Err(f) => return Ok(Err(f)),
                    }
                }
            }
        }
        return Ok(Ok(Source::Migrate(options)));
    }
    let init = spec.init.clone().unwrap_or_default();
    Ok(Ok(Source::Empty(RepositoryInitOptions {
        auto_init: spec.init.is_some() && init.auto_init,
        gitignores: init.gitignores,
        license: init.license,
        readme: init.readme,
        object_format: init.object_format,
    })))
}

async fn cleanup(repo: &ForgejoRepository, ctx: &Ctx) -> Result<Action, Error> {
    let gateway = ctx
        .gateways
        .gateway_for(repo.spec.instance_ref.as_deref())
        .await
        .map_err(|e| Error::Cleanup(e.to_string()))?;
    cleanup_repository(&repo.spec, current_ref(repo).as_ref(), gateway.as_ref())
        .await
        .map_err(|f| Error::Cleanup(f.message))?;
    Ok(Action::await_change())
}
