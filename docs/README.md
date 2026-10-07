# docs

The weebo-forgejo documentation site ([Fumadocs](https://fumadocs.dev) on
Next.js), published at <https://batleforc.github.io/weebo-forgejo>.

```bash
task docs          # dev server on http://localhost:3000
task docs:build    # lint + static export into out/
```

## Content

- `content/docs/{index,getting-started,concepts}.mdx`, `guides/*.mdx`,
  `contributing/*.mdx`: hand-written. Sidebar order lives in each folder's
  `meta.json`.
- `content/docs/crds/*` (pages, `index.mdx`, `meta.json`) and
  `public/crd-schemas/*.json` are **generated** from `deploy/crd/*.yaml` by
  `scripts/gen-crd-docs.mjs` (`task recu`, or
  `node docs/scripts/gen-crd-docs.mjs` for the docs alone). Never edit them by
  hand. A field without a description means its Rust doc-comment is missing;
  each kind's example spec lives in the script and is checked against the
  schema.

## Manifest builder

Every CRD page ends with a form (`src/components/crd-form/`) built from the
kind's JSON schema. Kinds with mutually exclusive ways of doing one thing
(repository: empty / template / mirror; user: local / SSO / bot…) start with
guided choices, declared in `src/lib/crd-form/choices.ts`: which spec fields
each option shows, requires or implies. Keep those field names in sync with
the CRDs when renaming a field.

## Design

The theme follows the BatleHub design system
([batlehub/batlehub `DESIGN.md`](https://github.com/batlehub/batlehub/blob/main/DESIGN.md)),
in three layers under `src/app/`:

- `tokens.css`: the BatleHub tokens, vendored verbatim; change them upstream.
- `fd-bridge.css`: the only place Fumadocs' `--color-fd-*` variables are set,
  each to a token.
- `global.css`: component rules (reading measure, headings, tables,
  callouts, the home page). No colour literals.

Light and dark both work: next-themes writes `data-theme` (what the tokens
key off) and `class` (what Fumadocs' `dark:` utilities key off).

## Publishing

The site is a static export (`output: 'export'`). `.github/workflows/docs-pages.yml`
builds it on every push to `main` that touches `docs/` or `deploy/crd/`, with
`DOCS_BASE_PATH=/weebo-forgejo` (the project-site sub-path) and
`DOCS_SITE_URL` (absolute OG image URLs), then deploys it to GitHub Pages.
Files fetched at runtime from `public/` must go through `withBasePath()`
(`src/lib/shared.ts`); `next/link` handles the prefix by itself.
