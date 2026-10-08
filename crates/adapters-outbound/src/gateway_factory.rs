use std::sync::Arc;
use std::time::Duration;

use api::ForgejoInstance;
use api::instance::TlsOptions;
use application::ports::{ForgejoGateway, GatewayFactory, GatewayFactoryError};
use kube::runtime::reflector::Store;
use kube::{Client, ResourceExt};

use crate::forgejo_http::ForgejoHttpGateway;
use crate::instance_resolver::InstanceResolver;
use weebo_kit_adapters::read_secret_key;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Forgejo clones synchronously inside `POST /repos/migrate` (and
/// `generate`): a timeout there would leave a half-imported repository the
/// next reconcile collides with, so it gets a generous budget.
const MIGRATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Builds a [`ForgejoHttpGateway`] per call from the selected
/// `ForgejoInstance`. Nothing is cached: the token `Secret` is re-read on
/// every call (rotation needs no restart), and an edited `spec.tls` or
/// rotated CA applies on the next reconcile.
pub struct ForgejoGatewayFactory {
    client: Client,
    instances: InstanceResolver,
}

impl ForgejoGatewayFactory {
    /// `store`: the reflector `operator::main` keeps live; `None` reads
    /// instances from the API on each call.
    pub fn new(client: Client, store: Option<Store<ForgejoInstance>>) -> Self {
        Self {
            instances: InstanceResolver::new(client.clone(), store),
            client,
        }
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
        let http = build_http_client(&instance.spec.tls, ca_pem.as_deref(), REQUEST_TIMEOUT)?;
        let slow = build_http_client(&instance.spec.tls, ca_pem.as_deref(), MIGRATION_TIMEOUT)?;

        let (api_base, web_url) = api::instance::split_urls(&instance.spec.url);
        Ok(Arc::new(
            ForgejoHttpGateway::new(api_base, web_url, token.trim().to_string(), http)
                .with_slow_client(slow),
        ))
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
    match instance_ref {
        Some(name) => instances
            .iter()
            .find(|i| i.name_any() == name)
            .ok_or_else(|| GatewayFactoryError::InstanceNotFound(name.to_string())),
        None => match instances {
            [only] => Ok(only),
            [] => Err(GatewayFactoryError::InstanceNotFound(
                "no ForgejoInstance exists".to_string(),
            )),
            many => Err(GatewayFactoryError::AmbiguousDefault(format!(
                "{} ForgejoInstances exist; set spec.instanceRef",
                many.len()
            ))),
        },
    }
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
