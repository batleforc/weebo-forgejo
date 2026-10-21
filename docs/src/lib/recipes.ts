import type { Recipe } from '@weebo/operator-docs/crd-ide';

// The CRD IDE's starting points (content/docs/ide.mdx). `<…>` marks what
// to fill in; the IDE lists each one until it is.

const TEAM_PROJECT = `apiVersion: forgejo.weebo.io/v1alpha1
kind: ForgejoLocalInstance
metadata:
  name: forgejo
spec:
  url: "<https://git.example.com>"
  tokenSecretRef: { name: "<Secret holding an admin token>", key: token }
---
apiVersion: forgejo.weebo.io/v1alpha1
kind: ForgejoUser
metadata:
  name: alice
spec:
  instanceRef: { kind: LocalInstance, name: forgejo }
  username: alice
  email: "<alice@example.com>"
---
apiVersion: forgejo.weebo.io/v1alpha1
kind: ForgejoOrganization
metadata:
  name: platform
spec:
  instanceRef: { kind: LocalInstance, name: forgejo }
  name: platform
  ownerRef: { name: alice }
---
apiVersion: forgejo.weebo.io/v1alpha1
kind: ForgejoTeam
metadata:
  name: platform-devs
spec:
  instanceRef: { kind: LocalInstance, name: forgejo }
  name: devs
  organizationRef: { name: platform }
  memberRefs:
    - { name: alice }
---
apiVersion: forgejo.weebo.io/v1alpha1
kind: ForgejoRepository
metadata:
  name: infra
spec:
  instanceRef: { kind: LocalInstance, name: forgejo }
  name: infra
  organizationRef: { name: platform }
  teamRefs:
    - { name: platform-devs }
---
apiVersion: forgejo.weebo.io/v1alpha1
kind: ForgejoAccessToken
metadata:
  name: ci
spec:
  instanceRef: { kind: LocalInstance, name: forgejo }
  userRef: { name: alice }
  scopes: [write:repository]
  repositoryRefs:
    - { name: infra }
  secretTargets:
    - name: ci-forgejo-token
`;

export const RECIPES: Recipe[] = [
  {
    id: 'team-project',
    label: 'An organization, its team, a repository and a CI token',
    description:
      'A local instance; a user who owns an organization and is in its team; a repository the team can push to; an access token restricted to that repository, written to a Secret.',
    yaml: TEAM_PROJECT,
  },
];
