use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoOrganization, ForgejoTeam, ForgejoUser};
use application::ports::{ForgejoRef, RefKind};
use application::use_cases::reconcile_team::{Member, TeamInput, cleanup_team, reconcile_team};
use application::use_cases::refs::{resolve_member, resolve_required};
use application::use_cases::{Failure, Outcome};
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{Controller, watcher};
use kube::{Client, ResourceExt};

use super::status::current_ref;
use super::{Ctx, Error, FINALIZER, allows_disruptive_update, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let controller = Controller::new(
        Api::<ForgejoTeam>::all(client.clone()),
        watcher::Config::default(),
    );
    // Teams react to their organization and members changing state: an
    // observed OIDC user appearing in Forgejo joins its teams right away.
    let by_org = controller.store();
    let by_member = controller.store();
    controller
        .watches(
            Api::<ForgejoOrganization>::all(client.clone()),
            watcher::Config::default(),
            move |org| {
                let name = org.name_any();
                by_org
                    .state()
                    .into_iter()
                    .filter(|t| t.spec.organization_ref.name == name)
                    .map(|t| ObjectRef::from_obj(t.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<ForgejoUser>::all(client),
            watcher::Config::default(),
            move |user| {
                let name = user.name_any();
                by_member
                    .state()
                    .into_iter()
                    .filter(|t| t.spec.member_refs.iter().any(|m| m.name == name))
                    .map(|t| ObjectRef::from_obj(t.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(err) = res {
                tracing::debug!(error = %err, "ForgejoTeam reconcile failed");
            }
        })
        .await;
}

async fn reconcile(obj: Arc<ForgejoTeam>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if super::import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let api: Api<ForgejoTeam> = Api::all(ctx.client.clone());
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(team) => apply(&api, &team, &ctx).await,
            FinalizerEvent::Cleanup(team) => cleanup(&team, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(e.to_string()))
}

async fn apply(api: &Api<ForgejoTeam>, team: &ForgejoTeam, ctx: &Ctx) -> Result<Action, Error> {
    let current = api.get(&team.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);

    let outcome = match resolve_inputs(&current, ctx).await? {
        Err(f) => Outcome::failed(owned, f),
        Ok((organization, members)) => {
            match ctx
                .gateways
                .gateway_for(current.spec.instance_ref.as_deref())
                .await
            {
                Ok(gateway) => {
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
                Err(e) => Outcome::failed(owned, Failure::new(e.reason(), e.to_string())),
            }
        }
    };

    record_reconcile("ForgejoTeam", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

/// The organization must be ready; members may be pending (they become
/// `MemberPending` advisories), but a member on another instance is a spec
/// error.
async fn resolve_inputs(
    team: &ForgejoTeam,
    ctx: &Ctx,
) -> Result<Result<(ForgejoRef, Vec<Member>), Failure>, Error> {
    let instance = team.spec.instance_ref.as_deref();
    let refs = ctx.refs.as_ref();
    let org_name = &team.spec.organization_ref.name;
    let org = match resolve_required(refs, RefKind::Organization, "", org_name, instance).await? {
        Ok(org) => org,
        Err(f) => return Ok(Err(f)),
    };

    let mut members = Vec::with_capacity(team.spec.member_refs.len());
    for member in &team.spec.member_refs {
        match resolve_member(refs, &member.name, instance).await? {
            Ok(member) => members.push(member),
            Err(f) => return Ok(Err(f)),
        }
    }
    Ok(Ok((org, members)))
}

async fn cleanup(team: &ForgejoTeam, ctx: &Ctx) -> Result<Action, Error> {
    let gateway = super::cleanup_gateway(ctx, team.spec.instance_ref.as_deref()).await;
    cleanup_team(&team.spec, current_ref(team).as_ref(), gateway.as_deref())
        .await
        .map_err(|f| Error::Cleanup(f.message))?;
    Ok(Action::await_change())
}
