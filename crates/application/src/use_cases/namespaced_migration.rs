//! The plan of `migrate-to-namespaced`: moving the CRs of the kinds that
//! used to be cluster-scoped (`ForgejoUser`, `ForgejoOrganization`,
//! `ForgejoTeam`, `ForgejoUserKey`) into namespaces. Pure: it works on the
//! objects as JSON, read from the cluster by the binary, and says what to
//! recreate where and which references to rewrite — the binary does it.
//!
//! - Each CR goes to the namespace its mapping names
//!   (`ForgejoUser/alice: team-a`), else the default one.
//! - Its spec is kept; its status's binding to Forgejo (`forgejoId`,
//!   `forgejoName`, the resolved `instance`…) is seeded on the new CR.
//! - A reference (moved CRs among themselves, and the namespaced CRs
//!   already there: repositories, webhooks, OAuth2 applications, tokens)
//!   whose target lands in another namespace gets that `namespace`, and the
//!   target lists the referencing namespace in its `sharedWith` — such a
//!   cross-namespace reference also needs `references.crossNamespace`.
//! - The `Secret`s and Vault values the moved CRs emitted are recorded
//!   under their old owner id (`ForgejoUser/alice`): the plan lists the
//!   renames (`ForgejoUser/team-a/alice`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

/// The kinds that move, and the references they hold.
pub const MOVED: [&str; 4] = [
    "ForgejoUser",
    "ForgejoOrganization",
    "ForgejoTeam",
    "ForgejoUserKey",
];

/// The namespaced kinds whose references may need a namespace.
pub const REFERRING: [&str; 4] = [
    "ForgejoRepository",
    "ForgejoWebhook",
    "ForgejoOAuth2Application",
    "ForgejoAccessToken",
];

/// The kinds that can share themselves (`spec.sharedWith`).
const SHARING: [&str; 3] = ["ForgejoUser", "ForgejoOrganization", "ForgejoTeam"];

/// `(spec field, target kind, is a list)` of every user/organization/team
/// reference of `kind`.
fn references(kind: &str) -> &'static [(&'static str, &'static str, bool)] {
    match kind {
        "ForgejoOrganization" => &[("ownerRef", "ForgejoUser", false)],
        "ForgejoTeam" => &[
            ("organizationRef", "ForgejoOrganization", false),
            ("memberRefs", "ForgejoUser", true),
        ],
        "ForgejoUserKey" => &[("userRef", "ForgejoUser", false)],
        "ForgejoRepository" => &[
            ("organizationRef", "ForgejoOrganization", false),
            ("userRef", "ForgejoUser", false),
            ("teamRefs", "ForgejoTeam", true),
        ],
        "ForgejoWebhook" => &[("organizationRef", "ForgejoOrganization", false)],
        "ForgejoOAuth2Application" => &[("ownerRef", "ForgejoUser", false)],
        "ForgejoAccessToken" => &[("userRef", "ForgejoUser", false)],
        _ => &[],
    }
}

/// Where each CR goes.
#[derive(Debug, Clone, Default)]
pub struct Targets {
    /// `Kind/name` → namespace.
    pub mapping: BTreeMap<String, String>,
    /// For the CRs the mapping doesn't name.
    pub default_namespace: Option<String>,
}

/// One cluster-scoped CR, recreated in its namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct Move {
    pub kind: String,
    pub name: String,
    pub namespace: String,
    /// The new CR (no status): `apiVersion`, `kind`, `metadata` (name,
    /// namespace, labels, annotations), `spec`.
    pub manifest: Value,
    /// The status fields binding it to Forgejo, to seed (`forgejoId`,
    /// `forgejoName`, `instance`, …); `None` when it owned nothing yet.
    pub seed: Option<Value>,
}

impl Move {
    /// The Forgejo id the CR owns (`""` for none).
    pub fn forgejo_id(&self) -> String {
        self.seed
            .as_ref()
            .and_then(|s| s.get("forgejoId"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }
}

/// A namespaced CR whose `spec` must be rewritten.
#[derive(Debug, Clone, PartialEq)]
pub struct Rewrite {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    /// The fields to merge into `spec`.
    pub spec: Value,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    pub moves: Vec<Move>,
    pub rewrites: Vec<Rewrite>,
    /// Some reference now crosses namespaces: the release needs
    /// `references.crossNamespace`.
    pub cross_namespace: bool,
    /// Old owner id of emitted secrets → new one (`ForgejoUser/alice` →
    /// `ForgejoUser/team-a/alice`).
    pub owner_renames: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

/// What can't be planned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("no target namespace for {0}: map it or pass a default namespace")]
pub struct Unmapped(pub String);

/// The plan for `old` (the cluster-scoped CRs, as read from the cluster)
/// and `namespaced` (the CRs of [`REFERRING`] already there).
pub fn plan(old: &[Value], namespaced: &[Value], targets: &Targets) -> Result<Plan, Unmapped> {
    let mut plan = Plan::default();
    // Kind/name → its new namespace.
    let mut placed: BTreeMap<(String, String), String> = BTreeMap::new();
    for cr in old {
        let (kind, name) = (kind_of(cr), name_of(cr));
        let key = format!("{kind}/{name}");
        let namespace = targets
            .mapping
            .get(&key)
            .or(targets.default_namespace.as_ref())
            .ok_or_else(|| Unmapped(key.clone()))?
            .clone();
        placed.insert((kind.clone(), name.clone()), namespace);
    }
    // Namespaces each moved target must share itself with.
    let mut shared: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();

    for cr in old {
        let (kind, name) = (kind_of(cr), name_of(cr));
        let namespace = placed[&(kind.clone(), name.clone())].clone();
        let mut spec = cr.get("spec").cloned().unwrap_or_else(|| json!({}));
        let changed = rewrite_refs(&kind, &namespace, &mut spec, &placed, &mut shared);
        plan.cross_namespace |= changed;
        for target in secret_targets(&kind, &spec) {
            if target != namespace {
                plan.warnings.push(format!(
                    "{kind}/{name} moves to {namespace:?} but writes a secret into {target:?}: \
                     it will be refused (CrossNamespaceReference) until the target moves"
                ));
            }
        }
        let emits_secrets = kind == "ForgejoUser" || kind == "ForgejoUserKey";
        if emits_secrets {
            plan.owner_renames.push((
                format!("{kind}/{name}"),
                format!("{kind}/{namespace}/{name}"),
            ));
        }
        let metadata = cr.get("metadata").cloned().unwrap_or_default();
        let mut meta = Map::new();
        meta.insert("name".into(), name.clone().into());
        meta.insert("namespace".into(), namespace.clone().into());
        for field in ["labels", "annotations"] {
            if let Some(v) = metadata.get(field) {
                let v = without_last_applied(v);
                if v.as_object().is_some_and(|m| !m.is_empty()) {
                    meta.insert(field.into(), v);
                }
            }
        }
        // Its secrets were recorded under its cluster-scoped id: the
        // operator takes them back (Vault values included, which this tool
        // can't reach) and rewrites them under the new one.
        if emits_secrets {
            let annotations = meta
                .entry("annotations")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .expect("annotations is an object");
            annotations.insert(
                api::ANNOTATIONS.key(weebo_kit_api::annotations::PREVIOUS_OWNER),
                format!("{kind}/{name}").into(),
            );
        }
        plan.moves.push(Move {
            manifest: json!({
                "apiVersion": cr.get("apiVersion").cloned().unwrap_or_default(),
                "kind": kind,
                "metadata": meta,
                "spec": spec,
            }),
            seed: seed_of(cr),
            kind,
            name,
            namespace,
        });
    }

    for cr in namespaced {
        let kind = kind_of(cr);
        let namespace = cr
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let original = cr.get("spec").cloned().unwrap_or_else(|| json!({}));
        let mut spec = original.clone();
        if rewrite_refs(&kind, &namespace, &mut spec, &placed, &mut shared) {
            plan.cross_namespace = true;
        }
        if spec != original {
            let fields = references(&kind)
                .iter()
                .filter_map(|(field, _, _)| {
                    spec.get(*field).map(|v| ((*field).to_string(), v.clone()))
                })
                .collect::<Map<_, _>>();
            plan.rewrites.push(Rewrite {
                kind,
                namespace,
                name: name_of(cr),
                spec: Value::Object(fields),
            });
        }
    }

    // Seed `sharedWith` on the targets referenced from elsewhere.
    for m in &mut plan.moves {
        let Some(namespaces) = shared.get(&(m.kind.clone(), m.name.clone())) else {
            continue;
        };
        if !SHARING.contains(&m.kind.as_str()) {
            continue;
        }
        let spec = m.manifest["spec"].as_object_mut().expect("a spec object");
        let entry = spec
            .entry("sharedWith")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("sharedWith is an object");
        let mut listed: BTreeSet<String> = entry
            .get("namespaces")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        listed.extend(namespaces.iter().cloned());
        entry.insert("namespaces".into(), json!(listed));
    }
    Ok(plan)
}

fn kind_of(cr: &Value) -> String {
    cr.get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn name_of(cr: &Value) -> String {
    cr.pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Adds `namespace` to every reference of `spec` (a CR of `kind` in
/// `namespace`) whose target moves to another namespace, and records the
/// sharing the target needs. Returns whether one crosses namespaces.
fn rewrite_refs(
    kind: &str,
    namespace: &str,
    spec: &mut Value,
    placed: &BTreeMap<(String, String), String>,
    shared: &mut BTreeMap<(String, String), BTreeSet<String>>,
) -> bool {
    let mut crosses = false;
    for (field, target_kind, list) in references(kind) {
        let Some(value) = spec.get_mut(*field) else {
            continue;
        };
        let refs: Vec<&mut Value> = match (list, value) {
            (true, Value::Array(items)) => items.iter_mut().collect(),
            (false, v @ Value::Object(_)) => vec![v],
            _ => continue,
        };
        for r in refs {
            // Already namespaced, or a `remoteName`: left alone.
            if r.get("namespace").is_some() {
                continue;
            }
            let Some(name) = r.get("name").and_then(Value::as_str).map(str::to_string) else {
                continue;
            };
            let Some(target_ns) = placed.get(&((*target_kind).to_string(), name.clone())) else {
                continue;
            };
            if target_ns == namespace {
                continue;
            }
            r["namespace"] = target_ns.clone().into();
            shared
                .entry(((*target_kind).to_string(), name))
                .or_default()
                .insert(namespace.to_string());
            crosses = true;
        }
    }
    crosses
}

/// The namespaces `spec`'s secret targets write into.
fn secret_targets(kind: &str, spec: &Value) -> Vec<String> {
    let targets = match kind {
        "ForgejoUser" => spec.get("secretTargets"),
        "ForgejoUserKey" => spec.get("secretTargets"),
        _ => None,
    };
    targets
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| {
            t.get("namespace")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

/// The status fields binding a CR to Forgejo — not its conditions nor its
/// observed generation, which the operator rebuilds.
fn seed_of(cr: &Value) -> Option<Value> {
    let status = cr.get("status")?.as_object()?;
    let seed: Map<String, Value> = status
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "conditions" | "observedGeneration"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    seed.contains_key("forgejoId")
        .then_some(Value::Object(seed))
}

fn without_last_applied(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(m) = v.as_object_mut() {
        m.remove("kubectl.kubernetes.io/last-applied-configuration");
    }
    v
}

/// A line of the mapping file that isn't `Kind/name: namespace`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: expected `Kind/name: namespace` with Kind one of {}", MOVED.join(", "))]
pub struct BadMapping {
    pub line: usize,
}

/// The mapping file: `Kind/name: namespace` lines (a YAML map).
pub fn parse_mapping(text: &str) -> Result<BTreeMap<String, String>, BadMapping> {
    let mut mapping = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let bad = || BadMapping {
            line: n.saturating_add(1),
        };
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() || line == "---" {
            continue;
        }
        let (key, ns) = line.split_once(':').ok_or_else(bad)?;
        let (key, ns) = (key.trim(), ns.trim().trim_matches(['"', '\'']));
        let kind = key.split('/').next().unwrap_or_default();
        if !MOVED.contains(&kind) || !key.contains('/') || ns.is_empty() {
            return Err(bad());
        }
        mapping.insert(key.to_string(), ns.to_string());
    }
    Ok(mapping)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cr(kind: &str, name: &str, ns: Option<&str>, spec: Value, status: Value) -> Value {
        json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": kind,
            "metadata": {"name": name, "namespace": ns, "labels": {"team": "a"},
                         "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"}},
            "spec": spec, "status": status,
        })
    }

    fn targets(mapping: &[(&str, &str)], default: Option<&str>) -> Targets {
        Targets {
            mapping: mapping
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            default_namespace: default.map(str::to_string),
        }
    }

    #[test]
    fn crs_move_with_their_binding_and_refs_follow_them() {
        let old = [
            cr(
                "ForgejoUser",
                "alice",
                None,
                json!({"username": "alice", "email": "a@x", "secretTargets": [{"name": "s", "namespace": "ops"}]}),
                json!({"forgejoId": "3", "forgejoName": "alice", "conditions": [], "observedGeneration": 2}),
            ),
            cr(
                "ForgejoOrganization",
                "weebo",
                None,
                json!({"name": "weebo", "ownerRef": {"name": "alice"}}),
                json!({"forgejoId": "9", "forgejoName": "weebo"}),
            ),
            cr(
                "ForgejoTeam",
                "devs",
                None,
                json!({"organizationRef": {"name": "weebo"}, "memberRefs": [{"name": "alice"}, {"remoteName": "bob"}], "name": "devs"}),
                json!({}),
            ),
        ];
        let namespaced = [
            cr(
                "ForgejoRepository",
                "app",
                Some("team-b"),
                json!({"organizationRef": {"name": "weebo"}, "teamRefs": [{"name": "devs"}], "name": "app"}),
                json!({}),
            ),
            cr(
                "ForgejoAccessToken",
                "t",
                Some("team-a"),
                json!({"userRef": {"name": "alice"}, "scopes": ["read:user"]}),
                json!({}),
            ),
        ];
        let plan = plan(
            &old,
            &namespaced,
            &targets(&[("ForgejoUser/alice", "team-a")], Some("ids")),
        )
        .unwrap();

        let alice = &plan.moves[0];
        assert_eq!(alice.namespace, "team-a");
        assert_eq!(alice.forgejo_id(), "3");
        assert_eq!(
            alice.seed,
            Some(json!({"forgejoId": "3", "forgejoName": "alice"}))
        );
        assert_eq!(alice.manifest["metadata"]["labels"], json!({"team": "a"}));
        // Only what the migration adds: its secrets' former owner.
        assert_eq!(
            alice.manifest["metadata"]["annotations"],
            json!({"forgejo.weebo.io/previous-owner": "ForgejoUser/alice"})
        );
        // Referenced from `ids` (the org's owner, the team's member).
        assert_eq!(
            alice.manifest["spec"]["sharedWith"],
            json!({"namespaces": ["ids"]})
        );

        let org = &plan.moves[1];
        assert_eq!(org.namespace, "ids");
        assert_eq!(
            org.manifest["spec"]["ownerRef"],
            json!({"name": "alice", "namespace": "team-a"})
        );
        assert_eq!(
            org.manifest["spec"]["sharedWith"],
            json!({"namespaces": ["team-b"]})
        );

        let team = &plan.moves[2];
        assert_eq!(team.seed, None, "owned nothing yet");
        assert_eq!(
            team.manifest["spec"]["memberRefs"],
            json!([{"name": "alice", "namespace": "team-a"}, {"remoteName": "bob"}])
        );
        assert_eq!(
            team.manifest["spec"]["organizationRef"],
            json!({"name": "weebo"})
        );

        // The repository in team-b now points at ids; the token in team-a
        // at its own namespace's user: unchanged.
        assert_eq!(plan.rewrites.len(), 1);
        let repo = &plan.rewrites[0];
        assert_eq!(
            (repo.kind.as_str(), repo.name.as_str()),
            ("ForgejoRepository", "app")
        );
        assert_eq!(
            repo.spec,
            json!({"organizationRef": {"name": "weebo", "namespace": "ids"},
                   "teamRefs": [{"name": "devs", "namespace": "ids"}]})
        );
        assert!(plan.cross_namespace);
        assert_eq!(
            plan.owner_renames,
            vec![(
                "ForgejoUser/alice".into(),
                "ForgejoUser/team-a/alice".into()
            )]
        );
        assert_eq!(plan.warnings.len(), 1, "{:?}", plan.warnings);
        assert!(plan.warnings[0].contains("\"ops\""));
    }

    #[test]
    fn everything_in_one_namespace_crosses_nothing() {
        let old = [
            cr(
                "ForgejoUser",
                "alice",
                None,
                json!({"username": "alice"}),
                json!({}),
            ),
            cr(
                "ForgejoUserKey",
                "k",
                None,
                json!({"userRef": {"name": "alice"}}),
                json!({}),
            ),
        ];
        let repo = cr(
            "ForgejoRepository",
            "app",
            Some("ids"),
            json!({"userRef": {"name": "alice"}}),
            json!({}),
        );
        let plan = plan(&old, &[repo], &targets(&[], Some("ids"))).unwrap();
        assert!(!plan.cross_namespace);
        assert!(plan.rewrites.is_empty());
        assert!(
            plan.moves
                .iter()
                .all(|m| m.manifest["spec"].get("sharedWith").is_none())
        );
    }

    #[test]
    fn an_unmapped_cr_without_default_is_an_error() {
        let old = [cr("ForgejoUser", "alice", None, json!({}), json!({}))];
        assert_eq!(
            plan(&old, &[], &targets(&[], None)),
            Err(Unmapped("ForgejoUser/alice".into()))
        );
    }

    #[test]
    fn the_mapping_file_is_a_flat_yaml_map() {
        let mapping = parse_mapping(
            "# who goes where\nForgejoUser/alice: team-a\nForgejoTeam/devs: \"ids\"\n\n",
        )
        .unwrap();
        assert_eq!(mapping["ForgejoUser/alice"], "team-a");
        assert_eq!(mapping["ForgejoTeam/devs"], "ids");
        assert!(parse_mapping("ForgejoRepository/app: x").is_err());
        assert!(parse_mapping("alice team-a").is_err());
    }
}
