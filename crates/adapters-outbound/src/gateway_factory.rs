use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api::ForgejoInstance;
use api::instance::TlsOptions;
use application::ports::{ForgejoGateway, GatewayFactory, GatewayFactoryError};
use kube::runtime::reflector::Store;
use kube::{Client, ResourceExt};

use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::forgejo_http::ForgejoHttpGateway;
use crate::instance_resolver::InstanceResolver;
use crate::metered::{MeteredGateway, max_inflight};
use weebo_kit_adapters::SelectError;
use weebo_kit_adapters::read_secret_key;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Forgejo clones synchronously inside `POST /repos/migrate` (and
/// `generate`): a timeout there would leave a half-imported repository the
/// next reconcile collides with, so it gets a generous budget.
const MIGRATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Builds a [`ForgejoHttpGateway`] per call from the selected
/// `ForgejoInstance`, wrapped in a [`MeteredGateway`]. The token `Secret`
/// (and CA) are re-read on every call — a rotation needs no restart — but
/// the HTTP clients (connection pools, TLS sessions) are reused per
/// instance until its TLS settings or CA content change, and every gateway
/// of one instance shares its in-flight limit.
pub struct ForgejoGatewayFactory {
    client: Client,
    instances: InstanceResolver,
    cache: Mutex<HashMap<String, CachedClients>>,
}

/// What the HTTP clients of an instance were built from.
#[derive(Clone, PartialEq, Eq)]
struct ClientKey {
    insecure_skip_verify: bool,
    ca_digest: Option<Vec<u8>>,
}

struct CachedClients {
    key: ClientKey,
    http: reqwest::Client,
    slow: reqwest::Client,
    permits: Arc<Semaphore>,
}

impl ForgejoGatewayFactory {
    /// `store`: the reflector `operator::main` keeps live; `None` reads
    /// instances from the API on each call.
    pub fn new(client: Client, store: Option<Store<ForgejoInstance>>) -> Self {
        Self {
            instances: InstanceResolver::new(client.clone(), store),
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The instance's cached clients, rebuilt when what they were built
    /// from changed.
    fn clients(
        &self,
        instance: &ForgejoInstance,
        ca_pem: Option<&[u8]>,
    ) -> Result<(reqwest::Client, reqwest::Client, Arc<Semaphore>), GatewayFactoryError> {
        let key = ClientKey {
            insecure_skip_verify: instance.spec.tls.insecure_skip_verify,
            ca_digest: ca_pem.map(|pem| Sha256::digest(pem).to_vec()),
        };
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let name = instance.name_any();
        if let Some(c) = cache.get(&name)
            && c.key == key
        {
            return Ok((c.http.clone(), c.slow.clone(), c.permits.clone()));
        }
        let http = build_http_client(&instance.spec.tls, ca_pem, REQUEST_TIMEOUT)?;
        let slow = build_http_client(&instance.spec.tls, ca_pem, MIGRATION_TIMEOUT)?;
        // A TLS change keeps the in-flight limit: calls still running on
        // the old clients count against it.
        let permits = cache
            .get(&name)
            .map(|c| c.permits.clone())
            .unwrap_or_else(|| Arc::new(Semaphore::new(max_inflight())));
        cache.insert(
            name,
            CachedClients {
                key,
                http: http.clone(),
                slow: slow.clone(),
                permits: permits.clone(),
            },
        );
        Ok((http, slow, permits))
    }

    pub async fn build(
        &self,
        instance: &ForgejoInstance,
    ) -> Result<Arc<dyn ForgejoGateway>, GatewayFactoryError> {
        let token_ref = &instance.spec.token_secret_ref;
        let token = read_secret_key(&self.client, token_ref)
            .await
            .map_err(GatewayFactoryError::Kubernetes)?
            .ok_or_else(|| {
                GatewayFactoryError::TokenSecret(format!(
                    "secret {}/{} has no key {:?}",
                    token_ref.namespace, token_ref.name, token_ref.key
                ))
            })?;
        let token = String::from_utf8(token)
            .map_err(|_| GatewayFactoryError::TokenSecret("token is not UTF-8".into()))?;

        let ca_pem = match &instance.spec.tls.ca_secret_ref {
            Some(ca_ref) => Some(
                read_secret_key(&self.client, ca_ref)
                    .await
                    .map_err(GatewayFactoryError::Kubernetes)?
                    .ok_or_else(|| {
                        GatewayFactoryError::ResolutionFailed(format!(
                            "tls.caSecretRef {}/{} has no key {:?}",
                            ca_ref.namespace, ca_ref.name, ca_ref.key
                        ))
                    })?,
            ),
            None => None,
        };
        let (http, slow, permits) = self.clients(instance, ca_pem.as_deref())?;

        let (api_base, web_url) = api::instance::split_urls(&instance.spec.url);
        let gateway = ForgejoHttpGateway::new(api_base, web_url, token.trim().to_string(), http)
            .with_slow_client(slow);
        Ok(Arc::new(MeteredGateway::new(Arc::new(gateway), permits)))
    }
}

#[async_trait::async_trait]
impl GatewayFactory for ForgejoGatewayFactory {
    async fn gateway_for(
        &self,
        instance_ref: Option<&str>,
    ) -> Result<Arc<dyn ForgejoGateway>, GatewayFactoryError> {
        let instances = self
            .instances
            .list()
            .await
            .map_err(GatewayFactoryError::Kubernetes)?;
        let instance = select(&instances, instance_ref)?;
        self.build(instance).await
    }
}

/// `instance_ref` names one instance; without it the cluster must have
/// exactly one (`.prompt/plan.md`, "Instance par défaut").
pub(crate) fn select<'a>(
    instances: &'a [ForgejoInstance],
    instance_ref: Option<&str>,
) -> Result<&'a ForgejoInstance, GatewayFactoryError> {
    weebo_kit_adapters::select(instances, instance_ref).map_err(|e| match e {
        SelectError::NotFound { name, .. } => GatewayFactoryError::InstanceNotFound(name),
        SelectError::NoInstance { .. } => GatewayFactoryError::InstanceNotFound(e.to_string()),
        SelectError::Ambiguous { .. } => GatewayFactoryError::AmbiguousDefault(e.to_string()),
    })
}

/// `ca_pem` is added on top of the platform trust store. A configured CA
/// that holds no certificate is an error, never a silent fallback to the
/// platform roots.
fn build_http_client(
    tls: &TlsOptions,
    ca_pem: Option<&[u8]>,
    timeout: Duration,
) -> Result<reqwest::Client, GatewayFactoryError> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(pem) = ca_pem {
        let certs = reqwest::Certificate::from_pem_bundle(pem).map_err(|e| {
            GatewayFactoryError::ResolutionFailed(format!("parsing tls.caSecretRef: {e}"))
        })?;
        if certs.is_empty() {
            return Err(GatewayFactoryError::ResolutionFailed(
                "tls.caSecretRef contains no PEM certificate".to_string(),
            ));
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    if tls.insecure_skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().map_err(|e| {
        GatewayFactoryError::ResolutionFailed(format!("building the Forgejo HTTP client: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use api::common::SecretKeyRef;
    use api::instance::ForgejoInstanceSpec;
    use kube::api::ObjectMeta;

    use super::*;

    fn instance(name: &str) -> ForgejoInstance {
        ForgejoInstance {
            metadata: ObjectMeta {
                name: Some(name.into()),
                ..Default::default()
            },
            spec: ForgejoInstanceSpec {
                url: "https://git.example.com".into(),
                token_secret_ref: SecretKeyRef {
                    name: "t".into(),
                    namespace: "n".into(),
                    key: "token".into(),
                },
                tls: Default::default(),
                secret_store: Default::default(),
            },
            status: None,
        }
    }

    #[test]
    fn default_instance_needs_exactly_one() {
        assert!(matches!(
            select(&[], None),
            Err(GatewayFactoryError::InstanceNotFound(_))
        ));
        assert_eq!(select(&[instance("a")], None).unwrap().name_any(), "a");
        assert!(matches!(
            select(&[instance("a"), instance("b")], None),
            Err(GatewayFactoryError::AmbiguousDefault(_))
        ));
    }

    #[test]
    fn named_instance_is_found_among_many() {
        let all = [instance("a"), instance("b")];
        assert_eq!(select(&all, Some("b")).unwrap().name_any(), "b");
        assert!(matches!(
            select(&all, Some("c")),
            Err(GatewayFactoryError::InstanceNotFound(_))
        ));
    }

    #[test]
    fn garbage_ca_is_refused() {
        assert!(build_http_client(&TlsOptions::default(), Some(b"nope"), REQUEST_TIMEOUT).is_err());
        assert!(build_http_client(&TlsOptions::default(), None, REQUEST_TIMEOUT).is_ok());
    }
}
