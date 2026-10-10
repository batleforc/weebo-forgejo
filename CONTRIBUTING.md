# Contributing to weebo-forgejo

Thanks for helping. This file covers the workflow; the design lives in
[`.prompt/plan.md`](.prompt/plan.md) (read it before any non-trivial change)
and the user documentation in [`docs/`](docs/)
([published site](https://batleforc.github.io/weebo-forgejo)).

## Setup

Tools come from [mise](https://mise.jdx.dev/) (`mise.toml`), commands from
[Task](https://taskfile.dev/) (`Taskfile.yaml`, `.tasks/`).

```bash
task init     # tools (mise install), Claude plugins, git hooks (cocogitto)
task doctor   # checks the envtest prerequisites: Go, libclang, etcd, kube-apiserver
```

## Everyday commands

| Command | What it does |
| --- | --- |
| `task lint` | `cargo fmt --check`, clippy `-D warnings`, hadolint, actionlint |
| `task test` | Unit and contract tests |
| `task test:all` | Plus envtest controller tests (a real API server) |
| `task test:live-forgejo` | Against a real Forgejo (`task forgejo:container:start` first) |
| `task coverage` | Every layer under llvm-cov; fails under 85 % of lines |
| `task recu` | Regenerate the Forgejo client, the CRDs, the chart's CRD templates and the docs' CRD pages |
| `task lint:helm` | helm lint plus smoke renders of the chart |
| `task e2e` | kind end to end (needs docker or podman: `ENGINE=podman`) |
| `task audit` | cargo-deny, trivy, npm audit |
| `task docs` / `task docs:build` | Documentation site dev server / build + lint |

`task --list` shows everything.

## Generated files

Never edit these by hand; change their source and run `task recu`:

- `crates/forgejo-client/`: from `spec/forgejo-v*.json` + `spec/patches/*.jq`;
- `deploy/crd/`: from the CRD types in `crates/api` (crdgen);
- `deploy/charts/weebo-forgejo/templates/crds/`: from `deploy/crd/`;
- `docs/content/docs/crds/`, `docs/public/crd-schemas/`: from `deploy/crd/`.

CI regenerates them and fails on any difference.

## Commits

- **Conventional Commits** (`feat: …`, `fix: …`, `docs: …`, `ci: …`,
  `refactor: …`), checked by cocogitto (`cog verify`) in the `commit-msg`
  hook. The version and the changelog are derived from them.
- **Signed and signed-off**: `git commit -S -s`. `main` requires signed
  commits.
- The `pre-commit` hook runs `task recu`, `task lint`, the whitespace and
  end-of-line fixers and gitleaks. Don't skip it.

## Pull requests

- One topic per PR; tests for behaviour changes (use-case tests with the
  in-memory fakes of `application::test_support`, envtest for controllers).
- Update the docs page that describes what you changed; a new chart value
  goes into `values.yaml` **and** `values.schema.json`.
- PRs touching `crates/`, `deploy/` or the Containerfiles also run the kind
  e2e.

## The shared operator kit

Plumbing shared with the sibling operators (reason codes, allow-list engine,
secret stores, telemetry, leader election, webhook TLS server, envtest)
lives in [weebo-operator-kit](https://github.com/batleforc/weebo-operator-kit),
pinned by tag in `Cargo.toml` (`weebo-kit-*` entries).

- Fix shared behaviour **in the kit**, release it (tag), then bump the `tag`
  of every `weebo-kit-*` entry here.
- For a change spanning both repositories, temporarily point the entries at
  a local checkout, `path = "../weebo-operator-kit/crates/<crate>"`. Never
  push that: CI and `cargo deny` only accept the kit from its git URL.

## Security

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## Releasing

Maintainers: see
[Releasing](https://batleforc.github.io/weebo-forgejo/docs/contributing/releasing).
