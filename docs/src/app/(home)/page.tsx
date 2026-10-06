import Link from 'next/link';

export default function HomePage() {
  return (
    <div className="cyber-grid-bg relative flex flex-1 flex-col items-center justify-center overflow-hidden px-5 py-24 text-center">
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(ellipse 70% 60% at 50% 30%, oklch(0.70 0.19 45 / 14%), transparent)',
        }}
      />

      <div className="relative flex flex-col items-center gap-6">
        <span className="font-mono text-xs font-semibold uppercase tracking-[0.15em] text-fd-accent">
          Kubernetes Operator
        </span>

        <h1 className="glitch cyber-text-glow bg-gradient-to-br from-fd-foreground to-fd-primary bg-clip-text font-sans text-5xl font-extrabold tracking-[-0.04em] text-transparent sm:text-7xl">
          weebo-forgejo
        </h1>

        <p className="max-w-xl text-base leading-7 text-fd-muted-foreground">
          Manage Forgejo users, organizations, teams, repositories, webhooks,
          keys, OAuth2 applications and access tokens as native Kubernetes
          custom resources, with a namespace allow-list enforced by an
          admission webhook.
        </p>

        <Link
          href="/docs"
          className="cyber-glow mt-2 inline-flex items-center gap-2 border border-fd-primary/50 bg-fd-primary px-5 py-2.5 font-mono text-sm font-semibold uppercase tracking-wide text-fd-primary-foreground transition-transform hover:-translate-y-px active:translate-y-0"
        >
          Read the docs
        </Link>
      </div>
    </div>
  );
}
