import Link from 'next/link';
import { repoUrl } from '@/lib/shared';

// The proof sheet: one form at poster scale captioned by its facts, then
// ruled regions — no card, no glow, no gradient (DESIGN.md, Overview).

const features = [
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
];

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col px-4 sm:px-6">
      <section className="mx-auto flex w-full max-w-[1100px] flex-col gap-6 pt-10 pb-10 sm:pt-16">
        <span className="sheet-label">Kubernetes operator · Forgejo v16+</span>
        <h1 className="sheet-display">weebo-forgejo</h1>
        <p className="sheet-caption">
          Manage the inside of an existing Forgejo — users, organizations, repositories, webhooks,
          keys, OAuth2 applications and access tokens — as Kubernetes custom resources, with
          GitOps-friendly status and a namespace allow-list.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <Link href="/docs/getting-started" className="action">
            Get started
          </Link>
          <Link href="/docs" className="ctl">
            Read the docs
          </Link>
          <a href={repoUrl} className="ctl" rel="noreferrer">
            View on GitHub
          </a>
        </div>
      </section>

      <section className="sheet-region mx-auto w-full max-w-[1100px]">
        <div className="grid gap-6 md:grid-cols-2">
          <div className="flex min-w-0 flex-col gap-3">
            <span className="sheet-label">1 · Install the chart</span>
            <pre className="sheet-pre">
              <code>
                helm install weebo-forgejo \{'\n'}
                {'  '}oci://ghcr.io/batleforc/charts/weebo-forgejo \{'\n'}
                {'  '}--namespace weebo-forgejo --create-namespace
              </code>
            </pre>
          </div>
          <div className="flex min-w-0 flex-col gap-3">
            <span className="sheet-label">2 · Declare a repository</span>
            <pre className="sheet-pre">
              <code>
                <span className="k">apiVersion:</span> <span className="v">forgejo.weebo.io/v1alpha1</span>
                {'\n'}
                <span className="k">kind:</span> <span className="v">ForgejoRepository</span>
                {'\n'}
                <span className="k">metadata:</span>
                {'\n'}
                {'  '}
                <span className="k">name:</span> <span className="v">platform-api</span>
                {'\n'}
                {'  '}
                <span className="k">namespace:</span> <span className="v">team-platform</span>
                {'\n'}
                <span className="k">spec:</span>
                {'\n'}
                {'  '}
                <span className="k">organizationRef:</span> <span className="v">{'{ name: platform }'}</span>
                {'\n'}
                {'  '}
                <span className="k">name:</span> <span className="v">platform-api</span>
                {'\n'}
                {'  '}
                <span className="k">private:</span> <span className="v">true</span>
              </code>
            </pre>
          </div>
        </div>
      </section>

      <section className="sheet-region mx-auto grid w-full max-w-[1100px] md:grid-cols-3">
        {features.map((f) => (
          <div key={f.title} className="sheet-feature flex flex-col gap-3 py-6 md:px-6 md:py-0 md:first:ps-0">
            <h2>{f.title}</h2>
            <p className="text-[13px] leading-[1.6] text-fd-muted-foreground">{f.body}</p>
            <Link href={f.href}>{f.link}</Link>
          </div>
        ))}
      </section>
    </main>
  );
}
