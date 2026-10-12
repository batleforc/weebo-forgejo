use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoNamespacePolicy, ForgejoOrganization, ForgejoTeam, ForgejoUser};
use application::ports::{BoundInstance, ForgejoGateway, ForgejoRef, RefKind};
use application::use_cases::admission::enforce_on;
use application::use_cases::reconcile_team::{Member, TeamInput, cleanup_team, reconcile_team};
use application::use_cases::refs::{resolve_identity_required, resolve_member};
use application::use_cases::{Failure, Outcome};
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

const KIND: &str = "ForgejoTeam";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(ctx.scope.api::<ForgejoTeam>(client.clone()), &ctx.scope);
    // Teams react to their organization and members changing state: an
    // observed OIDC user appearing in Forgejo joins its teams right away.
    let by_org = controller.store();
    let by_member = controller.store();
    // A policy change may allow or forbid any CR of this kind.
    let by_policy = controller.store();
    let results = controller
        .watches_in::<ForgejoOrganization, _>(&ctx, &client, move |org| {
            let (name, ns) = (org.name_any(), org.namespace());
            by_org
                .state()
                .into_iter()
                .filter(|t| {
                    let team_ns = t.namespace();
                    t.spec
                        .organization_ref
                        .points_at(team_ns.as_deref(), ns.as_deref(), &name)
                })
                .map(|t| ObjectRef::from_obj(t.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<ForgejoUser, _>(&ctx, &client, move |user| {
            let (name, ns) = (user.name_any(), user.namespace());
            by_member
                .state()
                .into_iter()
                .filter(|t| {
                    let team_ns = t.namespace();
                    t.spec
                        .member_refs
                        .iter()
                        .any(|m| m.points_at(team_ns.as_deref(), ns.as_deref(), &name))
                })
                .map(|t| ObjectRef::from_obj(t.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<ForgejoNamespacePolicy, _>(&ctx, &client, move |_| {
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

async fn reconcile(obj: Arc<ForgejoTeam>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if super::import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoTeam> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(team) => apply(&api, &team, &ctx).await,
            FinalizerEvent::Cleanup(team) => {
                super::finalize(team.as_ref(), &ctx, cleanup(&team, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

async fn apply(api: &Api<ForgejoTeam>, team: &ForgejoTeam, ctx: &Ctx) -> Result<Action, Error> {
    let current = api.get(&team.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);

    let outcome = match super::instance_of(ctx, &current).await {
        Err(f) => Outcome::failed(owned, f),
        Ok(bound) => match resolve_inputs(&current, owned.is_none(), &bound, ctx).await? {
            Err(f) => Outcome::failed(owned, f),
            Ok((gateway, organization, members)) => {
                let input = TeamInput {
                    spec: &current.spec,
                    current: owned,
                    organization: organization.name,
                    organization_id: Some(organization.id),
                    members,
                    allow_disruptive_update: allows_disruptive_update(&current.metadata),
                };
                reconcile_team(input, gateway.as_ref()).await
            }
        }
        .on(bound),
    };

    record_reconcile("ForgejoTeam", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

type Inputs = (Arc<dyn ForgejoGateway>, ForgejoRef, Vec<Member>);

/// The namespace policy, then the organization, which must be ready;
/// members may be pending (they become `MemberPending` advisories), but a
/// member on another instance is a spec error. Before the team is created,
/// its unique claim (`organization/team` on the server).
async fn resolve_inputs(
    team: &ForgejoTeam,
    creating: bool,
    instance: &BoundInstance,
    ctx: &Ctx,
) -> Result<Result<Inputs, Failure>, Error> {
    let ns = team.namespace().unwrap_or_default();
    let (policies, refs) = (ctx.policies.as_ref(), ctx.refs.as_ref());
    if let Err(f) = enforce_on(policies, refs, &ns, team, Some(instance)).await? {
        return Ok(Err(f));
    }
    let gateway = match ctx.gateways.gateway_for(instance).await {
        Ok(gateway) => gateway,
        Err(e) => return Ok(Err(Failure::new(e.reason(), e.to_string()))),
    };
    let from = super::referrer(ctx, &ns, instance, Some(gateway.as_ref()));
    let org_ref = &team.spec.organization_ref;
    let org = match resolve_identity_required(&from, RefKind::Organization, org_ref).await? {
        Ok(org) => org,
        Err(f) => return Ok(Err(f)),
    };
    if creating {
        let me = format!("{KIND}/{ns}/{}", team.name_any());
        let full = format!("{}/{}", org.name, team.spec.name);
        if let Some(f) = super::claimed_elsewhere(ctx, RefKind::Team, &full, instance, &me).await? {
            return Ok(Err(f));
        }
    }

    let mut members = Vec::with_capacity(team.spec.member_refs.len());
    for member in &team.spec.member_refs {
        match resolve_member(&from, member).await? {
            Ok(member) => members.push(member),
            Err(f) => return Ok(Err(f)),
        }
    }
    Ok(Ok((gateway, org, members)))
}

async fn cleanup(team: &ForgejoTeam, ctx: &Ctx) -> Result<Action, Error> {
    let instance = super::cleanup_instance(ctx, team).await;
    let gateway = super::cleanup_gateway(ctx, &instance).await;
    cleanup_team(&team.spec, current_ref(team).as_ref(), gateway.as_deref())
        .await
        .map_err(Error::Cleanup)?;
    Ok(Action::await_change())
}
