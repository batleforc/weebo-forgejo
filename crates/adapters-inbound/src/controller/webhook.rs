use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoOrganization, ForgejoRepository, ForgejoWebhook};
use application::ports::{HookTarget, RefKind};
use application::use_cases::admission::enforce;
use application::use_cases::reconcile_webhook::{
    WebhookInput, cleanup_webhook, reconcile_webhook, validate,
};
use application::use_cases::refs::{read_secret_key, recorded_name, resolve_required};
use application::use_cases::{Failure, Outcome};
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Client, ResourceExt};

use super::status::current_ref;
use super::{Ctx, Error, FINALIZER, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoWebhook";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let client_for_policies = client.clone();
    let controller = super::controller(Api::<ForgejoWebhook>::all(client.clone()));
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    let by_repo = controller.store();
    let by_org = controller.store();
    let results = controller
        .watches(
            Api::<ForgejoRepository>::all(client.clone()),
            watcher::Config::default(),
            move |repo| {
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
            },
        )
        .watches(
            Api::<ForgejoOrganization>::all(client),
            watcher::Config::default(),
            move |org| {
                let name = org.name_any();
                by_org
                    .state()
                    .into_iter()
                    .filter(|h| {
                        h.spec
                            .organization_ref
                            .as_ref()
                            .is_some_and(|o| o.name == name)
                    })
                    .map(|h| ObjectRef::from_obj(h.as_ref()))
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
    .map_err(|e| Error::Finalizer(e.to_string()))
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
        Ok(()) => match resolve_inputs(&current, ctx).await? {
            Err(f) => Outcome::failed(owned, f),
            Ok((target, secret, authorization_header)) => {
                match ctx
                    .gateways
                    .gateway_for(current.spec.instance_ref.as_deref())
                    .await
                {
                    Ok(gateway) => {
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
                    Err(e) => Outcome::failed(owned, Failure::new(e.reason(), e.to_string())),
                }
            }
        },
    };

    record_reconcile("ForgejoWebhook", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

type Inputs = (HookTarget, Option<String>, Option<String>);

async fn resolve_inputs(
    hook: &ForgejoWebhook,
    ctx: &Ctx,
) -> Result<Result<Inputs, Failure>, Error> {
    let spec = &hook.spec;
    if let Err(f) = validate(spec) {
        return Ok(Err(f));
    }
    let ns = hook.namespace().unwrap_or_default();
    let instance = spec.instance_ref.as_deref();
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
        match resolve_required(refs, RefKind::Organization, &ns, &org.name, instance).await? {
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
    let instance = hook.spec.instance_ref.as_deref();
    let ns = hook.namespace().unwrap_or_default();
    // Where the target lives now (a rename since the last reconcile).
    let now = match (&hook.spec.repository_ref, &hook.spec.organization_ref) {
        (Some(r), _) => recorded_name(
            ctx.refs.as_ref(),
            RefKind::Repository,
            &ns,
            &r.name,
            instance,
        )
        .await?
        .and_then(|full| {
            let (owner, name) = full.split_once('/')?;
            Some(HookTarget::Repository {
                owner: owner.to_string(),
                name: name.to_string(),
            })
        }),
        (None, Some(o)) => recorded_name(
            ctx.refs.as_ref(),
            RefKind::Organization,
            &ns,
            &o.name,
            instance,
        )
        .await?
        .map(HookTarget::Organization),
        (None, None) => None,
    };
    let gateway = super::cleanup_gateway(ctx, instance).await;
    cleanup_webhook(
        &hook.spec,
        current_ref(hook).as_ref(),
        now,
        gateway.as_deref(),
    )
    .await
    .map_err(|f| Error::Cleanup(f.message))?;
    Ok(Action::await_change())
}
