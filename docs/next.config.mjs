import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

// Served from a sub-path on GitHub Pages (`/weebo-forgejo`); set by the
// docs-pages workflow. Empty locally, so `task docs` stays at the root.
const basePath = process.env.DOCS_BASE_PATH ?? '';

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  // Fully static site: every route is pre-rendered into `out/`.
  output: 'export',
  // `/docs/install/index.html` rather than `/docs/install.html`, which is what
  // a static host resolves for `/docs/install/`.
  trailingSlash: true,
  basePath,
  images: { unoptimized: true },
  env: { NEXT_PUBLIC_BASE_PATH: basePath },
  allowedDevOrigins: ['*.cde.batleforc.fr'],
};

export default withMDX(config);
