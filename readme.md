# weebo-forgejo

Kubernetes operator managing Forgejo (v16+) objects — users, organizations,
teams, repositories, keys, webhooks, OAuth2 applications, access tokens —
as CRDs. Sibling of [weebo-authentik](https://github.com/batleforc/weebo-authentik).

**Documentation: <https://batleforc.github.io/weebo-forgejo>**: start with
[Getting started](https://batleforc.github.io/weebo-forgejo/docs/getting-started/).

Status: **M4** — `ForgejoInstance`, `ForgejoUser` (local, bot, external
OIDC, observed), `ForgejoOrganization`, `ForgejoTeam`, `ForgejoRepository`
(empty/template/mirror, branch protections, team access), `ForgejoWebhook`,
`ForgejoDeployKey`, `ForgejoUserKey`, `ForgejoOAuth2Application`,
`ForgejoAccessToken`, `ForgejoNamespacePolicy` (admission webhook);
secrets to Kubernetes and/or Vault. Helm chart in
[`deploy/charts/weebo-forgejo`](deploy/charts/weebo-forgejo), documentation
site in [`docs/`](docs/) (`task docs`), examples in
[`deploy/examples/`](deploy/examples/).
Design and roadmap: [`.prompt/plan.md`](.prompt/plan.md).

## Development

```bash
task init     # tools (mise), Claude plugins, git hooks
task lint
task test
task recu     # regenerate the Forgejo client + CRDs
task audit    # cargo-deny + trivy
```

The Forgejo REST client in `crates/forgejo-client` is generated from the
vendored Swagger spec in `spec/` — see `task --list` under `gen:`.

Project bootstrapped from the [weebo-base](https://github.com/batleforc/weebo-base)
template; `task template:diff` / `task template:sync` pull template updates.
