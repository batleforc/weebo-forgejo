import { OperatorHome } from '@weebo/operator-docs/site';
import { site } from '@/lib/shared';

export default function HomePage() {
  return (
    <OperatorHome
      site={site}
      label="Kubernetes operator · Forgejo v16+"
      caption="Manage the inside of an existing Forgejo — users, organizations, repositories, webhooks, keys, OAuth2 applications and access tokens — as Kubernetes custom resources, with GitOps-friendly status and a namespace allow-list."
      actions={[
        { href: '/docs/getting-started', label: 'Get started', primary: true },
        { href: '/docs', label: 'Read the docs' },
        { href: '/docs/ide', label: 'Access the CRD IDE' },
      ]}
      install={`helm install weebo-forgejo \\
  oci://ghcr.io/batleforc/charts/weebo-forgejo \\
  --namespace weebo-forgejo --create-namespace`}
      example={{
        title: 'Declare a repository',
        yaml: `apiVersion: forgejo.weebo.io/v1alpha1
kind: ForgejoRepository
metadata:
  name: platform-api
  namespace: team-platform
spec:
  organizationRef: { name: platform }
  name: platform-api
  private: true`,
      }}
      features={[
        {
          title: 'Declare Forgejo',
          body: 'Users, organizations, teams, repositories, webhooks, deploy keys and branch protection are Kubernetes resources. Apply YAML, and the operator keeps Forgejo in line with it.',
          href: '/docs/getting-started',
          link: 'Quickstart',
        },
        {
          title: 'Hand out credentials',
          body: 'OAuth2 applications and access tokens are minted by the operator and written straight into Secrets (or Vault), rotated on request, never pasted by hand.',
          href: '/docs/guides/credentials',
          link: 'Credentials guide',
        },
        {
          title: 'Fence namespaces',
          body: 'An allow-list says which namespaces may manage which organizations. It is enforced by an admission webhook, before anything reaches Forgejo.',
          href: '/docs/guides/allow-list',
          link: 'Allow-list guide',
        },
      ]}
    />
  );
}
