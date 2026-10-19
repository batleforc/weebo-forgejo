use std::sync::Arc;
use std::time::Instant;

use api::common::IdentityRef;
use api::{ForgejoOrganization, ForgejoRepository, ForgejoWebhook};
use application::ports::{BoundInstance, ForgejoGateway, HookTarget, RefKind};
use application::use_cases::admission::enforce_on;
use application::use_cases::reconcile_webhook::{
    WebhookInput, cleanup_webhook, reconcile_webhook, validate,
};
use application::use_cases::refs::{
    read_secret_key, recorded_identity, resolve_identity_required, resolve_required,
};
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

const KIND: &str = "ForgejoWebhook";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::primary::<ForgejoWebhook>(&ctx, &client);
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    let by_repo = controller.store();
    let by_org = controller.store();
    let results = controller
        .watches_in::<ForgejoRepository, _>(&ctx.watches, &ctx.scope, &client, move |repo| {
            let (name, ns) = (repo.name_any(), repo.namespace());
            by_repo
                .state()
                .into_iter()
                .filter(|h| {
                    h.namespace() == ns
                        && h.spec
                            .repository_ref
                            .as_ref()
                            .is_some_and(|r| r.name == name)
                })
                .map(|h| ObjectRef::from_obj(h.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<ForgejoOrganization, _>(&ctx.watches, &ctx.scope, &client, move |org| {
            let (name, ns) = (org.name_any(), org.namespace());
            by_org
                .state()
                .into_iter()
                .filter(|h| {
                    h.spec.organization_ref.as_ref().is_some_and(|o| {
                        o.points_at(h.namespace().as_deref(), ns.as_deref(), &name)
                    })
                })
                .map(|h| ObjectRef::from_obj(h.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<api::ForgejoNamespacePolicy, _>(
            &ctx.watches,
            &ctx.scope,
            &client,
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

async fn reconcile(obj: Arc<ForgejoWebhook>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if super::import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoWebhook> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(hook) => apply(&api, &hook, &ctx).await,
            FinalizerEvent::Cleanup(hook) => {
                super::finalize(hook.as_ref(), &ctx, cleanup(&hook, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

async fn apply(
    api: &Api<ForgejoWebhook>,
    hook: &ForgejoWebhook,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&hook.name_any()).await?;
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
                Ok(gateway) => match resolve_inputs(&current, &bound, gateway.as_ref(), ctx).await?
                {
                    Err(f) => Outcome::failed(owned, f),
                    Ok((target, secret, authorization_header)) => {
                        let input = WebhookInput {
                            spec: &current.spec,
                            current: owned,
                            target,
                            secret,
                            authorization_header,
                            applied_secret_hash: current
                                .status
                                .as_ref()
                                .and_then(|s| s.applied_secret_hash.clone()),
                        };
                        reconcile_webhook(input, gateway.as_ref()).await
                    }
                },
            },
        }
        .on(bound),
    };

    record_reconcile("ForgejoWebhook", &outcome, started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

type Inputs = (HookTarget, Option<String>, Option<String>);

async fn resolve_inputs(
    hook: &ForgejoWebhook,
    instance: &BoundInstance,
    gateway: &dyn ForgejoGateway,
    ctx: &Ctx,
) -> Result<Result<Inputs, Failure>, Error> {
    let spec = &hook.spec;
    if let Err(f) = validate(spec) {
        return Ok(Err(f));
    }
    let ns = hook.namespace().unwrap_or_default();
    let refs = ctx.refs.as_ref();

    let target = if let Some(repo) = &spec.repository_ref {
        match resolve_required(refs, RefKind::Repository, &ns, &repo.name, instance).await? {
            Ok(r) => {
                let (owner, name) = r.name.split_once('/').unwrap_or(("", &r.name));
                HookTarget::Repository {
                    owner: owner.to_string(),
                    name: name.to_string(),
                }
            }
            Err(f) => return Ok(Err(f)),
        }
    } else {
        let org = spec
            .organization_ref
            .as_ref()
            .expect("validated: exactly one target");
        let from = super::referrer(ctx, &ns, instance, Some(gateway));
        match resolve_identity_required(&from, RefKind::Organization, org).await? {
            Ok(r) => HookTarget::Organization(r.name),
            Err(f) => return Ok(Err(f)),
        }
    };

    let mut values = [None, None];
    for (slot, secret_ref) in values
        .iter_mut()
        .zip([&spec.secret_ref, &spec.authorization_header_secret_ref])
    {
        if let Some(r) = secret_ref {
            match read_secret_key(refs, &ns, &r.name, &r.key).await? {
                Ok(v) => *slot = Some(v),
                Err(f) => return Ok(Err(f)),
            }
        }
    }
    let [secret, authorization_header] = values;
    Ok(Ok((target, secret, authorization_header)))
}

async fn cleanup(hook: &ForgejoWebhook, ctx: &Ctx) -> Result<Action, Error> {
    let instance = super::cleanup_instance(ctx, hook).await;
    let ns = hook.namespace().unwrap_or_default();
    // Where the target lives now (a rename since the last reconcile).
    let now = match (&hook.spec.repository_ref, &hook.spec.organization_ref) {
        (Some(r), _) => recorded(
            ctx,
            RefKind::Repository,
            &ns,
            &IdentityRef::named(&r.name),
            &instance,
        )
        .await?
        .and_then(|full| {
            let (owner, name) = full.split_once('/')?;
            Some(HookTarget::Repository {
                owner: owner.to_string(),
                name: name.to_string(),
            })
        }),
        (None, Some(o)) => recorded(ctx, RefKind::Organization, &ns, o, &instance)
            .await?
            .map(HookTarget::Organization),
        (None, None) => None,
    };
    let gateway = super::cleanup_gateway(ctx, &instance).await;
    let deleted = cleanup_webhook(
        &hook.spec,
        current_ref(hook).as_ref(),
        now,
        gateway.as_deref(),
    )
    .await
    .map_err(Error::Cleanup)?;
    if deleted {
        record_write("ForgejoWebhook", RemoteWrite::Deleted);
    }
    Ok(Action::await_change())
}

/// `status.forgejoName` of the referenced CR on the hook's instance; none
/// when that instance can't be resolved.
async fn recorded(
    ctx: &Ctx,
    kind: RefKind,
    ns: &str,
    r: &IdentityRef,
    instance: &Result<BoundInstance, Failure>,
) -> Result<Option<String>, Error> {
    Ok(match instance {
        Ok(bound) => recorded_identity(ctx.refs.as_ref(), kind, ns, r, bound).await?,
        Err(_) => None,
    })
}
