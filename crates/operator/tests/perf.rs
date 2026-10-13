//! What the operator costs a cluster (weebo-kit-perf): the release binary
//! against envtest and a fake Forgejo. A warm-up cycle, an idle baseline,
//! then a measured cycle — a burst of `ForgejoOrganization`s, an idle
//! window with all of them in place, a spec churn on all of them, their
//! deletion (`deletionPolicy: Delete`) — and a final idle window, checked
//! against the kit's small-cluster budget.
//!
//! `task perf` runs it. Tunable: `PERF_OBJECTS` (default 200),
//! `PERF_IDLE_SECS` (default 30); `WEEBO_PERF_REPORT_ONLY=1` reports
//! without failing; `WEEBO_PERF_BASELINE=<previous json>` adds the change
//! from a previous run. The report lands in `target/perf/`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use api::{ForgejoInstance, ForgejoOrganization};
use kube::api::{Api, PostParams};
use serde_json::{Value, json};
use testkit::envtest::EnvTestCluster;
use weebo_kit_perf::{BASELINE, Budget, FINAL, OperatorMetrics, PerfRun, Workload, names};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The organizations of the fake Forgejo, by lowercased name.
#[derive(Default)]
struct Orgs {
    by_name: Mutex<HashMap<String, Value>>,
    next_id: AtomicI64,
}

impl Orgs {
    fn name_in(request: &Request) -> String {
        request
            .url
            .path()
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_lowercase()
    }
}

/// `POST /orgs`: a new organization with a fresh id.
struct Create(std::sync::Arc<Orgs>);

impl Respond for Create {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let name = body["username"].as_str().unwrap_or_default().to_string();
        let mut orgs = self.0.by_name.lock().unwrap();
        if orgs.contains_key(&name.to_lowercase()) {
            return ResponseTemplate::new(422).set_body_json(json!({"message": "exists"}));
        }
        let id = self.0.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        body["id"] = id.into();
        body["name"] = name.clone().into();
        orgs.insert(name.to_lowercase(), body.clone());
        ResponseTemplate::new(201).set_body_json(body)
    }
}

/// `GET`, `PATCH` and `DELETE /orgs/<name>`.
struct One(std::sync::Arc<Orgs>);

impl Respond for One {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let name = Orgs::name_in(request);
        let mut orgs = self.0.by_name.lock().unwrap();
        match request.method.as_str() {
            "GET" => match orgs.get(&name) {
                Some(org) => ResponseTemplate::new(200).set_body_json(org.clone()),
                None => ResponseTemplate::new(404),
            },
            "PATCH" => match orgs.get_mut(&name) {
                Some(org) => {
                    let edit: Value = serde_json::from_slice(&request.body).unwrap_or_default();
                    if let (Some(org), Some(edit)) = (org.as_object_mut(), edit.as_object()) {
                        for (k, v) in edit {
                            org.insert(k.clone(), v.clone());
                        }
                    }
                    ResponseTemplate::new(200).set_body_json(org.clone())
                }
                None => ResponseTemplate::new(404),
            },
            "DELETE" => {
                orgs.remove(&name);
                ResponseTemplate::new(204)
            }
            _ => ResponseTemplate::new(405),
        }
    }
}

async fn fake_forgejo() -> MockServer {
    let server = MockServer::start().await;
    let orgs = std::sync::Arc::new(Orgs::default());
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": "16.0.5"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id": 1, "login": "root", "is_admin": true})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs"))
        .respond_with(Create(orgs.clone()))
        .mount(&server)
        .await;
    Mock::given(path_regex(r"^/api/v1/orgs/[^/]+$"))
        .respond_with(One(orgs))
        .mount(&server)
        .await;
    server
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn organization(name: &str) -> ForgejoOrganization {
    serde_json::from_value(json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoOrganization",
        "metadata": {"name": name},
        "spec": {"name": name, "deletionPolicy": "Delete"},
    }))
    .unwrap()
}

/// `Ready: True` for the current generation.
fn converged(o: &ForgejoOrganization) -> bool {
    let Some(status) = &o.status else {
        return false;
    };
    status.observed_generation == o.metadata.generation
        && status
            .conditions
            .iter()
            .any(|c| c.type_ == "Ready" && c.status == "True")
}

async fn burst(
    orgs: &Workload<ForgejoOrganization>,
    names: &[String],
    timeout: Duration,
) -> Duration {
    let objects: Vec<_> = names.iter().map(|n| organization(n)).collect();
    let started = Instant::now();
    orgs.create(&objects).await;
    orgs.wait_all(names, timeout, converged).await;
    started.elapsed()
}

async fn churn(
    orgs: &Workload<ForgejoOrganization>,
    names: &[String],
    round: u32,
    timeout: Duration,
) -> Duration {
    let started = Instant::now();
    orgs.patch_all(
        names,
        |_| json!({"spec": {"description": format!("round {round}")}}),
    )
    .await;
    orgs.wait_all(names, timeout, converged).await;
    started.elapsed()
}

async fn delete(
    orgs: &Workload<ForgejoOrganization>,
    names: &[String],
    timeout: Duration,
) -> Duration {
    let started = Instant::now();
    orgs.delete_all(names).await;
    orgs.wait_gone(names, timeout).await;
    started.elapsed()
}

/// Creates every object, idles with them in place (`loaded`, when `idle`
/// is set), changes every spec, deletes them all.
async fn cycle(
    run: &mut PerfRun,
    orgs: &Workload<ForgejoOrganization>,
    all: &[String],
    label: &str,
    round: u32,
    idle: Option<Duration>,
    timeout: Duration,
) {
    let n = all.len();
    run.load(&format!("{label} burst"), n, burst(orgs, all, timeout))
        .await;
    if let Some(idle) = idle {
        run.idle(&format!("{label} loaded"), idle).await;
    }
    run.load(
        &format!("{label} churn"),
        n,
        churn(orgs, all, round, timeout),
    )
    .await;
    run.load(&format!("{label} delete"), n, delete(orgs, all, timeout))
        .await;
}

#[tokio::test]
#[ignore = "a perf run (minutes, release build): `task perf`"]
async fn the_operator_fits_a_small_cluster() {
    let objects = env_or("PERF_OBJECTS", 200) as usize;
    let idle = Duration::from_secs(env_or("PERF_IDLE_SECS", 30));
    let timeout = Duration::from_secs(300);

    let cluster = EnvTestCluster::start().await;
    let forgejo = fake_forgejo().await;
    let client = cluster.client();

    Api::<k8s_openapi::api::core::v1::Secret>::namespaced(client.clone(), "default")
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "metadata": {"name": "forgejo-admin"}, "stringData": {"token": "t0ken"},
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    Api::<ForgejoInstance>::all(client.clone())
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoInstance",
                "metadata": {"name": "main"},
                "spec": {"url": forgejo.uri(),
                         "tokenSecretRef": {"name": "forgejo-admin", "namespace": "default",
                                            "key": "token"}},
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_operator"));
    command.env("RUST_LOG", "warn");
    let mut run = PerfRun::start(
        "weebo-forgejo",
        &cluster,
        command,
        OperatorMetrics::new("weebo_forgejo"),
    )
    .await;
    let orgs = run.workload(Api::<ForgejoOrganization>::namespaced(
        client.clone(),
        "default",
    ));

    run.idle("startup", idle).await;
    // The warm-up is a whole cycle at full size: the baseline must follow a
    // process that already filled its caches, pools and allocator arenas to
    // what this load needs, or the next cycle's fill reads as a leak.
    let all = names("org", objects);
    cycle(&mut run, &orgs, &all, "warm-up", 1, None, timeout).await;
    run.idle(BASELINE, idle).await;
    cycle(&mut run, &orgs, &all, "cycle", 2, Some(idle), timeout).await;
    run.idle(FINAL, idle).await;

    run.finish().await.assert_within(&Budget::small_cluster());
}
