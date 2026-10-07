use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoOrganization, ForgejoUser};
use application::use_cases::reconcile_organization::{
    OrganizationInput, cleanup_organization, reconcile_organization,
};
use application::use_cases::{Failure, Outcome};
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{Controller, watcher};
use kube::{Client, ResourceExt};

use super::refs::{require, resolve};
use super::status::current_ref;
use super::{Ctx, Error, FINALIZER, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let controller = Controller::new(
        Api::<ForgejoOrganization>::all(client.clone()),
        watcher::Config::default(),
    );
    // An org waiting on its ownerRef is re-reconciled as soon as that user
    // changes (e.g. becomes Ready), instead of on the 30 s retry.
    let orgs = controller.store();
    controller
        .watches(
            Api::<ForgejoUser>::all(client),
            watcher::Config::default(),
            move |user| {
                let name = user.name_any();
                orgs.state()
                    .into_iter()
                    .filter(|o| o.spec.owner_ref.as_ref().is_some_and(|r| r.name == name))
                    .map(|o| ObjectRef::from_obj(o.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(err) = res {
                tracing::debug!(error = %err, "ForgejoOrganization reconcile failed");
            }
        })
        .await;
}

async fn reconcile(obj: Arc<ForgejoOrganization>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if super::import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let api: Api<ForgejoOrganization> = Api::all(ctx.client.clone());
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(org) => apply(&api, &org, &ctx).await,
            FinalizerEvent::Cleanup(org) => cleanup(&org, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(e.to_string()))
}

async fn apply(
    api: &Api<ForgejoOrganization>,
    org: &ForgejoOrganization,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&org.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);

    let outcome = match owner(&current, owned.is_some(), ctx).await? {
        Err(f) => Outcome::failed(owned, f),
        Ok(owner) => match ctx
            .gateways
            .gateway_for(current.spec.instance_ref.as_deref())
            .await
        {
            Ok(gateway) => {
                let input = OrganizationInput {
                    spec: &current.spec,
                    current: owned,
                    owner,
                };
                reconcile_organization(input, gateway.as_ref()).await
            }
            Err(e) => Outcome::failed(owned, Failure::new(e.reason(), e.to_string())),
        },
    };

    record_reconcile("ForgejoOrganization", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

/// The owner's login — only needed (and only waited for) before the
/// organization exists: `ownerRef` is a creation-time setting.
async fn owner(
    org: &ForgejoOrganization,
    exists: bool,
    ctx: &Ctx,
) -> Result<Result<Option<String>, Failure>, Error> {
    let Some(owner_ref) = org.spec.owner_ref.as_ref().filter(|_| !exists) else {
        return Ok(Ok(None));
    };
    let users: Api<ForgejoUser> = Api::all(ctx.client.clone());
    let state = resolve(&users, &owner_ref.name, org.spec.instance_ref.as_deref()).await?;
    Ok(require("ForgejoUser", &owner_ref.name, state).map(|r| Some(r.name)))
}

async fn cleanup(org: &ForgejoOrganization, ctx: &Ctx) -> Result<Action, Error> {
    let gateway = super::cleanup_gateway(ctx, org.spec.instance_ref.as_deref()).await;
    cleanup_organization(&org.spec, current_ref(org).as_ref(), gateway.as_deref())
        .await
        .map_err(|f| Error::Cleanup(f.message))?;
    Ok(Action::await_change())
}
