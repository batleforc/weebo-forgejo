// Input of `weebo-crd-docs` (@weebo/operator-docs), run by `task recu` /
// `npm run gen:crds`: what the CRD reference pages say beyond the CRDs
// themselves. Paths default to the expected tree (../deploy/crd →
// content/docs/crds + public/crd-schemas).
import { defineConfig } from "@weebo/operator-docs/crd-docs";

export default defineConfig({
  // `ForgejoRepository` → example named `my-repository`.
  kindPrefix: "Forgejo",
  indexIntro: `Each page lists a kind's \`spec\` fields, shows a minimal example, and has a
form that builds a ready-to-apply manifest. These pages are generated from
the CRDs themselves, so they always match the installed version. For the
ideas behind the fields, start with [Concepts](/docs/concepts).`,
  // Sidebar order follows the order you'd create things in, not the alphabet.
  order: [
    "ForgejoInstance",
    "ForgejoLocalInstance",
    "ForgejoUser",
    "ForgejoUserKey",
    "ForgejoOrganization",
    "ForgejoTeam",
    "ForgejoNamespacePolicy",
    "ForgejoRepository",
    "ForgejoWebhook",
    "ForgejoDeployKey",
    "ForgejoOAuth2Application",
    "ForgejoAccessToken",
  ],
  // The guide that explains each kind, linked from its reference page.
  guides: {
    ForgejoInstance: ["Connect a Forgejo", "/docs/guides/connect-instance"],
    ForgejoLocalInstance: [
      "A namespace's own instance",
      "/docs/guides/connect-instance#a-namespaces-own-instance",
    ],
    ForgejoUser: ["Users, OIDC and teams", "/docs/guides/users-and-oidc"],
    ForgejoUserKey: ["Users, OIDC and teams", "/docs/guides/users-and-oidc#ssh-keys-for-a-user"],
    ForgejoOrganization: ["Users, OIDC and teams", "/docs/guides/users-and-oidc#organizations-and-teams"],
    ForgejoTeam: ["Users, OIDC and teams", "/docs/guides/users-and-oidc#organizations-and-teams"],
    ForgejoRepository: ["Repositories", "/docs/guides/repositories"],
    ForgejoWebhook: ["Repositories", "/docs/guides/repositories#webhooks"],
    ForgejoDeployKey: ["Repositories", "/docs/guides/repositories#deploy-keys"],
    ForgejoOAuth2Application: ["Credentials", "/docs/guides/credentials#oauth2-applications"],
    ForgejoAccessToken: ["Credentials", "/docs/guides/credentials#access-tokens"],
    ForgejoNamespacePolicy: ["The allow-list", "/docs/guides/allow-list"],
  },
  // A minimal, realistic `spec` per kind, checked against the schema (every
  // required field present, every key a real field): a renamed field fails
  // generation instead of shipping a stale example.
  examples: {
    ForgejoInstance: {
      url: "https://git.example.com",
      tokenSecretRef: { name: "forgejo-admin", namespace: "weebo-forgejo", key: "token" },
    },
    ForgejoLocalInstance: {
      url: "https://git.example.com",
      tokenSecretRef: { name: "forgejo-token", key: "token" },
    },
    ForgejoUser: { username: "alice", email: "alice@example.com" },
    ForgejoUserKey: {
      userRef: { name: "ci-bot" },
      title: "ci",
      secretTargets: [{ name: "ci-bot-ssh" }],
    },
    ForgejoOrganization: { name: "weebo", visibility: "private" },
    ForgejoTeam: {
      organizationRef: { name: "weebo" },
      name: "devs",
      permission: "write",
      memberRefs: [{ name: "alice" }],
    },
    ForgejoRepository: {
      organizationRef: { name: "weebo" },
      name: "app",
      private: true,
      init: { readme: "Default" },
    },
    ForgejoWebhook: {
      repositoryRef: { name: "app" },
      url: "https://ci.example.com/hooks/forgejo",
      events: ["push"],
    },
    ForgejoDeployKey: { repositoryRef: { name: "app" }, readOnly: true },
    ForgejoOAuth2Application: {
      redirectUris: ["https://grafana.example.com/login/generic_oauth"],
    },
    ForgejoAccessToken: { userRef: { name: "ci-bot" }, scopes: ["write:repository"] },
    ForgejoNamespacePolicy: {
      rules: [{ namespaces: ["team-*"], allowedKinds: ["ForgejoRepository"] }],
    },
  },
  // The operator reference pages (content/docs/reference/), generated from
  // the Rust sources: reason codes (crates/domain/src/error.rs), Events,
  // metrics & health, resource budget.
  reference: {
    metricsPrefix: "weebo_forgejo",
    // The Forgejo gateway's own metrics (crates/adapters-outbound/src/metered.rs).
    extraMetrics: [
      {
        name: "weebo_forgejo_forgejo_requests_total",
        type: "counter",
        labels: "`operation` (the gateway call, e.g. `create_repository`), `result` (`ok`, `not_found`, `already_exists`, `unreachable`, `error`)",
        description: "Forgejo API calls",
      },
      {
        name: "weebo_forgejo_forgejo_request_duration_seconds",
        type: "histogram",
        labels: "`operation`",
        description: "Forgejo API call duration",
      },
    ],
    // "What to do" per code; the meaning comes from the Rust doc comments.
    remedies: {
      Reconciled: "Nothing",
      InstanceNotFound: "[Create the instance](/docs/guides/connect-instance), or fix `instanceRef`",
      AmbiguousDefaultInstance: "Set `instanceRef`",
      InstanceNotAllowed:
        "Use an instance of the CR's namespace, or have that `ForgejoLocalInstance` list it in `sharedWith`",
      InstanceBindingChanged:
        "Set `instanceRef.kind` to the instance you want (see [A namespace's own instance](/docs/guides/connect-instance#a-namespaces-own-instance))",
      InstanceUnreachable: "Timeouts and rate limiting (408/429) land here too. Check Forgejo's health and the URL/CA; it's retried automatically",
      TokenSecretNotFound: "Fix `tokenSecretRef` or create the Secret",
      Bound: "Nothing",
      Released: "Nothing",
      InstanceInUse: "Delete the CRs bound to the instance first",
      KubernetesApiError: "Transient; retried automatically",
      ForgejoObjectAlreadyExists: "For a webhook (same URL) or an OAuth2 application (same name), it can be a twin left by a lost create response. Rename the CR's `spec.name`, delete the twin, or adopt the object with the [importer](/docs/guides/migration)",
      ForgejoApiError: "Read the message; often a missing token scope",
      ReferenceNotFound: "Create it or fix the ref",
      ReferenceNotReady: "Fix that CR first; this one follows on its own",
      UserNotFound: "Wait for their first sign-in",
      MemberPending: "Wait for those users' first sign-in; the other members are synced",
      LoginSourceNotFound: "Fix the id (Site administration → Authentication sources)",
      UnsupportedForgejoVersion: "Upgrade Forgejo",
      DisruptiveUpdateRefused: "See [Disruptive changes](/docs/guides/operations#disruptive-changes)",
      NamespaceNotAllowed: "Adjust the [allow-list](/docs/guides/allow-list); a site admin's credentials need an explicit rule",
      CrossNamespaceReference: "Typically a `secretTargets` entry in another namespace: write into the CR's own namespace",
      SecretTargetFailed:
        "Check RBAC or Vault access and the target's namespace/path (a Vault path outside `<pathPrefix>/<namespace>/` needs a `pathGrants` entry on the instance)",
      InvalidVaultPathGrants:
        "Fix `secretStore.vault.pathGrants` on the instance; the message names the entry",
      InvalidSpec: "Fix the spec (e.g. not both `organizationRef` and `userRef`); the message says what's wrong",
      ReferenceNotAllowed:
        "Reference a CR of this namespace; or enable `references.crossNamespace` on the release and list this namespace in the target's `sharedWith`",
      RemoteObjectClaimed:
        "Another CR owns that Forgejo object: reference it with `remoteName`, or rename this one",
      LeavesWatchScope:
        "Set the `force-orphan` annotation first, or move the CR to another release's selector and remove its finalizer",
    },
    // `task perf`'s report (target/perf/weebo-forgejo.json), copied here.
    perfReport: "perf/weebo-forgejo.json",
    // Refreshed every week by .github/workflows/perf.yml; the report
    // dates itself.
    perfScheduled: true,
  },
});
