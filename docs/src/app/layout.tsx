import { RootProvider } from 'fumadocs-ui/provider/next';
import type { Metadata } from 'next';
import './global.css';
import { JetBrains_Mono, Silkscreen } from 'next/font/google';
import { appName, basePath, withBasePath } from '@/lib/shared';

// The BatleHub pairing: a square-pixel display face for identity and scale,
// a mono text face for every fact. next/font self-hosts both at build time.
const silkscreen = Silkscreen({
  subsets: ['latin'],
  weight: ['400', '700'],
  variable: '--font-silkscreen',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  // Absolute OG image URLs on the published site (origin + base path, as
  // Next resolves image paths under it); unset locally.
  metadataBase: process.env.DOCS_SITE_URL
    ? new URL(`${basePath}/`, process.env.DOCS_SITE_URL)
    : undefined,
  title: { default: appName, template: `%s · ${appName}` },
  description: 'Manage Forgejo users, organizations, repositories and credentials as Kubernetes resources.',
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html
      lang="en"
      className={`${silkscreen.variable} ${jetbrainsMono.variable} font-sans`}
      suppressHydrationWarning
    >
      <body className="flex flex-col min-h-screen">
        <RootProvider
          // `data-theme` is what the BatleHub tokens key off; `class` is what
          // Fumadocs' own `dark:` utilities key off. The stored value is the
          // preference (system|light|dark), resolved before first paint.
          theme={{ attribute: ['class', 'data-theme'], defaultTheme: 'system', enableSystem: true }}
          search={{ options: { type: 'static', api: withBasePath('/api/search') } }}
        >
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
