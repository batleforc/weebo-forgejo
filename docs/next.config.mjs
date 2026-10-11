import { withOperatorDocs } from '@weebo/operator-docs/next';

// Fully static export (see withOperatorDocs). Served from a sub-path on GitHub
// Pages (`/weebo-forgejo`); set by the docs-pages workflow. Empty locally, so
// `task docs` stays at the root.
export default withOperatorDocs({
  basePath: process.env.DOCS_BASE_PATH ?? '',
  allowedDevOrigins: ['*.cde.batleforc.fr'],
});
