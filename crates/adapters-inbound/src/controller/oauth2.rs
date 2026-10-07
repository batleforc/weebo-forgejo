use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoOAuth2Application, ForgejoUser};
use application::ports::ForgejoRef;
use application::use_cases::reconcile_oauth2::{OAuth2Input, cleanup_oauth2, reconcile_oauth2};
use application::use_cases::{Failure, Outcome};
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{Controller, watcher};
use kube::{Client, ResourceExt};

use super::refs::{require, resolve};
use super::status::{current_ref, owner_id, secret_pending};
use super::{
    Ctx, Error, FINALIZER, allows_disruptive_update, error_policy, requeue_after, rotate_nonce,
    status,
};
use crate::metrics::record_reconcile;

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let client_for_policies = client.clone();
    let controller = Controller::new(
        Api::<ForgejoOAuth2Application>::all(client.clone()),
        watcher::Config::default(),
    );
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    let apps = controller.store();
    controller
        .watches(
            Api::<ForgejoUser>::all(client),
            watcher::Config::default(),
            move |user| {
                let name = user.name_any();
                apps.state()
                    .into_iter()
                    .filter(|a| a.spec.owner_ref.as_ref().is_some_and(|o| o.name == name))
                    .map(|a| ObjectRef::from_obj(a.as_ref()))
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
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(err) = res {
                tracing::debug!(error = %err, "ForgejoOAuth2Application reconcile failed");
            }
        })
        .await;
}

async fn reconcile(obj: Arc<ForgejoOAuth2Application>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoOAuth2Application> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(app) => apply(&api, &app, &ctx).await,
            FinalizerEvent::Cleanup(app) => cleanup(&app, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(e.to_string()))
}

/// The owner, or `None` for the admin account.
async fn owner(
    app: &ForgejoOAuth2Application,
    ctx: &Ctx,
) -> Result<Result<Option<ForgejoRef>, Failure>, Error> {
    let Some(owner_ref) = &app.spec.owner_ref else {
        return Ok(Ok(None));
    };
    let users: Api<ForgejoUser> = Api::all(ctx.client.clone());
    let state = resolve(&users, &owner_ref.name, app.spec.instance_ref.as_deref()).await?;
    Ok(require("ForgejoUser", &owner_ref.name, state).map(Some))
}

async fn apply(
    api: &Api<ForgejoOAuth2Application>,
    app: &ForgejoOAuth2Application,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&app.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);
    let (name, ns) = (current.name_any(), current.namespace().unwrap_or_default());

    let namespace = current.namespace().unwrap_or_default();
    let outcome = match crate::admission::enforce(&ctx.client, &namespace, &current).await? {
        // Re-checked here too: a policy may have changed since admission.
        Err(f) => Outcome::failed(current_ref(&current), f),
        Ok(()) => match owner(&current, ctx).await? {
            Err(f) => Outcome::failed(owned, f),
            Ok(owner) => match super::backends(ctx, current.spec.instance_ref.as_deref()).await {
                Ok((gateway, secrets)) => {
                    let input = OAuth2Input {
                        spec: &current.spec,
                        cr_name: &name,
                        namespace: &ns,
                        owner_id: owner.as_ref().map(|o| o.id),
                        owner: owner.map(|o| o.name),
                        current: owned,
                        current_owner_id: owner_id(&current.status),
                        secret_pending: secret_pending(&current.status),
                        rotate_nonce: rotate_nonce(&current.metadata),
                        last_rotation: current
                            .status
                            .as_ref()
                            .and_then(|s| s.last_rotation.clone()),
                        allow_disruptive_update: allows_disruptive_update(&current.metadata),
                    };
                    reconcile_oauth2(input, gateway.as_ref(), secrets.as_ref()).await
                }
                Err(f) => Outcome::failed(owned, f),
            },
        },
    };

    record_reconcile(
        "ForgejoOAuth2Application",
        outcome.reason(),
        started.elapsed(),
    );
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

async fn cleanup(app: &ForgejoOAuth2Application, ctx: &Ctx) -> Result<Action, Error> {
    let instance = app.spec.instance_ref.as_deref();
    let gateway = super::cleanup_gateway(ctx, instance).await;
    let secrets = super::cleanup_secrets(ctx, instance).await;
    cleanup_oauth2(
        &app.spec,
        &app.name_any(),
        &app.namespace().unwrap_or_default(),
        current_ref(app).as_ref(),
        owner_id(&app.status),
        gateway.as_deref(),
        secrets.as_ref(),
    )
    .await
    .map_err(|f| Error::Cleanup(f.message))?;
    Ok(Action::await_change())
}
