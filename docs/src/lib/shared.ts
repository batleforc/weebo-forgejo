export const appName = 'weebo-forgejo';
export const docsRoute = '/docs';
export const docsImageRoute = '/og/docs';
export const docsContentRoute = '/llms.mdx/docs';

// Prefix for the static export when it's served under a sub-path (GitHub
// Pages project site: /weebo-forgejo). Empty in dev and in a root-served build.
// next/link and next/font prefix it themselves; plain `fetch`/`<a>` URLs to
// files in `public/` and route handlers must go through `withBasePath`.
export const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';

export function withBasePath(path: string) {
  return `${basePath}${path}`;
}

export const gitConfig = {
  user: 'batleforc',
  repo: 'weebo-forgejo',
  branch: 'main',
};

export const repoUrl = `https://github.com/${gitConfig.user}/${gitConfig.repo}`;
