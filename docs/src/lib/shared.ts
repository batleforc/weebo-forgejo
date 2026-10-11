import { defineSite } from '@weebo/operator-docs/site';

// What makes this site weebo-forgejo's; everything else comes from
// @weebo/operator-docs.
export const site = defineSite({
  name: 'weebo-forgejo',
  description: 'Manage Forgejo users, organizations, repositories and credentials as Kubernetes resources.',
  git: {
    user: 'batleforc',
    repo: 'weebo-forgejo',
    branch: 'main',
    contentDir: 'docs/content/docs',
  },
});
