//! Leader election over a `coordination.k8s.io` `Lease`: only one replica
//! may reconcile — two would both attempt-create the same Forgejo object.
//! Split out of `main` so the acquire/lose behaviour is testable.

use std::future::Future;
use std::time::Duration;

use kube::Client;
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};
use tokio::time::Instant;

pub fn lease(
    client: Client,
    namespace: &str,
    name: &str,
    holder_id: String,
    ttl: Duration,
) -> LeaseLock {
    LeaseLock::new(
        client,
        namespace,
        LeaseLockParams {
            holder_id,
            lease_name: name.to_string(),
            lease_ttl: ttl,
        },
    )
}

/// Blocks until this replica holds the lease.
pub async fn acquire(lease: &LeaseLock, retry: Duration) {
    loop {
        match lease.try_acquire_or_renew().await {
            Ok(LeaseLockResult::Acquired(_)) => return,
            Ok(LeaseLockResult::NotAcquired(_)) => {}
            Err(err) => tracing::error!(error = %err, "leader lease acquisition failed, retrying"),
        }
        tokio::time::sleep(retry).await;
    }
}

/// Renews the lease every `renew` and returns as soon as it may be lost —
/// taken over, or not renewed for so long that another replica could hold
/// it by now: the caller must stop reconciling at once. A failed or hanging
/// renewal alone is retried until then, so an apiserver hiccup shorter
/// than the lease's `ttl` doesn't depose the leader.
pub async fn hold(lease: &LeaseLock, renew: Duration, ttl: Duration) -> String {
    hold_with(
        || async {
            match lease.try_acquire_or_renew().await {
                Ok(LeaseLockResult::Acquired(_)) => Ok(true),
                Ok(LeaseLockResult::NotAcquired(_)) => Ok(false),
                Err(err) => Err(err.to_string()),
            }
        },
        renew,
        ttl,
    )
    .await
}

/// `renew_once`: `Ok(true)` renewed, `Ok(false)` someone else holds it.
async fn hold_with<F, Fut>(mut renew_once: F, renew: Duration, ttl: Duration) -> String
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool, String>>,
{
    // Another replica may take over `ttl` after the last successful renewal
    // (counted from when it was sent — its `renewTime` can't be earlier).
    // Half a renew interval of slack absorbs clock skew between replicas.
    let window = ttl.saturating_sub(renew / 2);
    // A failed renewal is retried sooner than the next regular one.
    let retry = renew / 5;
    let mut renewed_at = Instant::now();
    let mut next = renewed_at + renew;
    loop {
        let deadline = renewed_at + window;
        tokio::time::sleep_until(next.min(deadline)).await;
        if Instant::now() >= deadline {
            return "could not renew the leader lease before it could expire".to_string();
        }
        let sent = Instant::now();
        match tokio::time::timeout_at(deadline, renew_once()).await {
            Ok(Ok(true)) => {
                renewed_at = sent;
                next = sent + renew;
            }
            Ok(Ok(false)) => return "lost the leader lease".to_string(),
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "leader lease renewal failed, retrying");
                next = Instant::now() + retry;
            }
            Err(_) => {
                return "the leader lease renewal did not complete before the lease could expire"
                    .to_string();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::pending;

    use super::*;

    const TTL: Duration = Duration::from_secs(15);
    const RENEW: Duration = Duration::from_secs(5);

    #[tokio::test(start_paused = true)]
    async fn transient_renewal_failures_are_tolerated() {
        let calls = Cell::new(0);
        let held = tokio::time::timeout(
            Duration::from_secs(120),
            hold_with(
                || {
                    calls.set(calls.get() + 1);
                    // Two failures in a row, then fine again.
                    let ok = !matches!(calls.get(), 2 | 3);
                    async move {
                        if ok {
                            Ok(true)
                        } else {
                            Err("apiserver hiccup".into())
                        }
                    }
                },
                RENEW,
                TTL,
            ),
        )
        .await;
        assert!(held.is_err(), "gave up the lease: {:?}", held.unwrap());
        assert!(calls.get() > 5);
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_failures_end_before_the_lease_can_expire() {
        let start = Instant::now();
        let why = hold_with(|| async { Err("apiserver down".into()) }, RENEW, TTL).await;
        assert!(why.contains("expire"), "{why}");
        assert!(start.elapsed() < TTL, "{:?}", start.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn a_hanging_renewal_ends_before_the_lease_can_expire() {
        let start = Instant::now();
        let why = hold_with(pending::<Result<bool, String>>, RENEW, TTL).await;
        assert!(why.contains("expire"), "{why}");
        assert!(start.elapsed() < TTL, "{:?}", start.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn a_taken_over_lease_ends_at_once() {
        let start = Instant::now();
        let why = hold_with(|| async { Ok(false) }, RENEW, TTL).await;
        assert!(why.contains("lost"), "{why}");
        assert!(start.elapsed() <= RENEW);
    }
}
