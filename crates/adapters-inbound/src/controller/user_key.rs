use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoUser, ForgejoUserKey};
use application::use_cases::reconcile_key::{KeyInput, KeyOwner, cleanup_key, reconcile_key};
use application::use_cases::{Failure, Outcome};
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{Controller, watcher};
use kube::{Client, ResourceExt};

use super::refs::{recorded_name, require, resolve};
use super::status::current_ref;
use super::{Ctx, Error, FINALIZER, error_policy, requeue_after, rotate_nonce, status};
use crate::metrics::record_reconcile;

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let controller = Controller::new(
        Api::<ForgejoUserKey>::all(client.clone()),
        watcher::Config::default(),
    );
    let keys = controller.store();
    controller
        .watches(
            Api::<ForgejoUser>::all(client),
            watcher::Config::default(),
            move |user| {
                let name = user.name_any();
                keys.state()
                    .into_iter()
                    .filter(|k| k.spec.user_ref.name == name)
                    .map(|k| ObjectRef::from_obj(k.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(err) = res {
                tracing::debug!(error = %err, "ForgejoUserKey reconcile failed");
            }
        })
        .await;
}

async fn reconcile(obj: Arc<ForgejoUserKey>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<ForgejoUserKey> = Api::all(ctx.client.clone());
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(key) => apply(&api, &key, &ctx).await,
            FinalizerEvent::Cleanup(key) => cleanup(&key, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(e.to_string()))
}

async fn user(key: &ForgejoUserKey, ctx: &Ctx) -> Result<Result<String, Failure>, Error> {
    let users: Api<ForgejoUser> = Api::all(ctx.client.clone());
    let name = &key.spec.user_ref.name;
    let state = resolve(&users, name, key.spec.instance_ref.as_deref()).await?;
    Ok(require("ForgejoUser", name, state).map(|r| r.name))
}

async fn apply(
    api: &Api<ForgejoUserKey>,
    key: &ForgejoUserKey,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&key.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);

    let mut resolved = None;
    let outcome = match user(&current, ctx).await? {
        Err(f) => Outcome::failed(owned, f),
        Ok(login) => match super::backends(ctx, current.spec.instance_ref.as_deref()).await {
            Ok((gateway, secrets)) => {
                resolved = Some(login.clone());
                let input = KeyInput {
                    owner: KeyOwner::User(login),
                    title: current
                        .spec
                        .title
                        .clone()
                        .unwrap_or_else(|| current.name_any()),
                    read_only: false,
                    source: &current.spec.key,
                    namespace: None,
                    current: owned,
                    rotate_nonce: rotate_nonce(&current.metadata),
                    last_rotation: current
                        .status
                        .as_ref()
                        .and_then(|s| s.last_rotation.clone()),
                };
                reconcile_key(input, gateway.as_ref(), secrets.as_ref()).await
            }
            Err(f) => Outcome::failed(owned, f),
        },
    };

    if let (Some(owner), Some(_)) = (&resolved, &outcome.forgejo) {
        super::record_key_owner(api, &current, owner).await?;
    }
    record_reconcile("ForgejoUserKey", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

async fn cleanup(key: &ForgejoUserKey, ctx: &Ctx) -> Result<Action, Error> {
    let instance = key.spec.instance_ref.as_deref();
    // The user CR may be not ready or already gone (an `Orphan` user):
    // fall back to the owner recorded when the key was created.
    let users: Api<ForgejoUser> = Api::all(ctx.client.clone());
    let owner = recorded_name(&users, &key.spec.user_ref.name, instance)
        .await?
        .or_else(|| super::key_owner(&key.metadata).map(str::to_string))
        .map(KeyOwner::User);
    if owner.is_none()
        && current_ref(key).is_some()
        && key.spec.deletion_policy == api::common::DeletionPolicy::Delete
    {
        tracing::warn!(
            key = %key.name_any(),
            "ForgejoUserKey: no record of the key's owner, the Forgejo key can't be deleted"
        );
    }
    let gateway = super::cleanup_gateway(ctx, instance).await;
    let secrets = super::cleanup_secrets(ctx, instance).await;
    cleanup_key(
        owner.as_ref(),
        &key.spec.key,
        None,
        key.spec.deletion_policy,
        current_ref(key).as_ref(),
        gateway.as_deref(),
        secrets.as_ref(),
    )
    .await
    .map_err(|f| Error::Cleanup(f.message))?;
    Ok(Action::await_change())
}
