# docs

The weebo-forgejo documentation site ([Fumadocs](https://fumadocs.dev) on
Next.js).

```bash
task docs          # dev server on http://localhost:3000
task docs:build    # production build
```

- `content/docs/guides/*.mdx` — hand-written guides.
- `content/docs/crds/*.mdx` and `public/crd-schemas/*.json` — **generated**
  from `deploy/crd/*.yaml` by `scripts/gen-crd-docs.mjs` (run by
  `task recu`); never edit them by hand. A field without a description
  means its Rust doc-comment is missing.
