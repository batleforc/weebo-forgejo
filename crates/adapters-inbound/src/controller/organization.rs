use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoNamespacePolicy, ForgejoOrganization, ForgejoUser};
use application::ports::{BoundInstance, ForgejoGateway, RefKind};
use application::use_cases::admission::enforce_on;
use application::use_cases::reconcile_organization::{
    OrganizationInput, cleanup_organization, reconcile_organization,
};
use application::use_cases::refs::resolve_identity_required;
use application::use_cases::{Failure, Outcome, RemoteWrite};
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};
use weebo_kit_runtime::shared::WatchesIn;

use super::status::current_ref;
use super::{Ctx, Error, FINALIZER, error_policy, requeue_after, status};
use crate::metrics::{record_reconcile, record_write};

const KIND: &str = "ForgejoOrganization";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::primary::<ForgejoOrganization>(&ctx, &client);
    // An org waiting on its ownerRef is re-reconciled as soon as that user
    // changes (e.g. becomes Ready), instead of on the 30 s retry.
    let orgs = controller.store();
    // A policy change may allow or forbid any CR of this kind.
    let by_policy = controller.store();
    let results = controller
        .watches_in::<ForgejoUser, _>(&ctx.watches, &ctx.scope, &client, move |user| {
            let (name, ns) = (user.name_any(), user.namespace());
            orgs.state()
                .into_iter()
                .filter(|o| {
                    o.spec.owner_ref.as_ref().is_some_and(|r| {
                        r.points_at(o.namespace().as_deref(), ns.as_deref(), &name)
                    })
                })
                .map(|o| ObjectRef::from_obj(o.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<ForgejoNamespacePolicy, _>(&ctx.watches, &ctx.scope, &client, move |_| {
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

async fn reconcile(obj: Arc<ForgejoOrganization>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if super::import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoOrganization> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(org) => apply(&api, &org, &ctx).await,
            FinalizerEvent::Cleanup(org) => {
                super::finalize(org.as_ref(), &ctx, cleanup(&org, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

async fn apply(
    api: &Api<ForgejoOrganization>,
    org: &ForgejoOrganization,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&org.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);
    let namespace = current.namespace().unwrap_or_default();

    let outcome = match super::instance_of(ctx, &current).await {
        Err(f) => Outcome::failed(owned, f),
        Ok(bound) => match checked(&current, &namespace, owned.is_some(), &bound, ctx).await? {
            Err(f) => Outcome::failed(owned, f),
            Ok(gateway) => {
                match owner(&current, owned.is_some(), &bound, gateway.as_ref(), ctx).await? {
                    Err(f) => Outcome::failed(owned, f),
                    Ok(owner) => {
                        let input = OrganizationInput {
                            spec: &current.spec,
                            current: owned,
                            owner,
                        };
                        reconcile_organization(input, gateway.as_ref()).await
                    }
                }
            }
        }
        .on(bound),
    };

    record_reconcile("ForgejoOrganization", &outcome, started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

/// The namespace policy, the instance's gateway, and — before the
/// organization is created — its unique claim.
async fn checked(
    org: &ForgejoOrganization,
    namespace: &str,
    exists: bool,
    bound: &BoundInstance,
    ctx: &Ctx,
) -> Result<Result<Arc<dyn ForgejoGateway>, Failure>, Error> {
    let (policies, refs) = (ctx.policies.as_ref(), ctx.refs.as_ref());
    if let Err(f) = enforce_on(policies, refs, namespace, org, Some(bound)).await? {
        return Ok(Err(f));
    }
    let gateway = match ctx.gateways.gateway_for(bound).await {
        Ok(gateway) => gateway,
        Err(e) => return Ok(Err(Failure::new(e.reason(), e.to_string()))),
    };
    if !exists {
        let me = format!("{KIND}/{namespace}/{}", org.name_any());
        let claimed =
            super::claimed_elsewhere(ctx, RefKind::Organization, &org.spec.name, bound, &me);
        if let Some(f) = claimed.await? {
            return Ok(Err(f));
        }
    }
    Ok(Ok(gateway))
}

/// The owner's login — only needed (and only waited for) before the
/// organization exists: `ownerRef` is a creation-time setting.
async fn owner(
    org: &ForgejoOrganization,
    exists: bool,
    instance: &BoundInstance,
    gateway: &dyn ForgejoGateway,
    ctx: &Ctx,
) -> Result<Result<Option<String>, Failure>, Error> {
    let Some(owner_ref) = org.spec.owner_ref.as_ref().filter(|_| !exists) else {
        return Ok(Ok(None));
    };
    let ns = org.namespace().unwrap_or_default();
    let from = super::referrer(ctx, &ns, instance, Some(gateway));
    let user = resolve_identity_required(&from, RefKind::User, owner_ref);
    Ok(user.await?.map(|r| Some(r.name)))
}

async fn cleanup(org: &ForgejoOrganization, ctx: &Ctx) -> Result<Action, Error> {
    let instance = super::cleanup_instance(ctx, org).await;
    let gateway = super::cleanup_gateway(ctx, &instance).await;
    let deleted = cleanup_organization(&org.spec, current_ref(org).as_ref(), gateway.as_deref())
        .await
        .map_err(Error::Cleanup)?;
    if deleted {
        record_write("ForgejoOrganization", RemoteWrite::Deleted);
    }
    Ok(Action::await_change())
}
