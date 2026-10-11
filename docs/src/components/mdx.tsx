import { docsMdxComponents } from '@weebo/operator-docs/site';
import type { MDXComponents } from 'mdx/types';
import { CHOICES } from '@/lib/crd-choices';
import { GroupSyncDiagram } from './GroupSyncDiagram';
import { TeamAccessDiagram } from './TeamAccessDiagram';

export function getMDXComponents(components?: MDXComponents) {
  return {
    ...docsMdxComponents(CHOICES),
    GroupSyncDiagram,
    TeamAccessDiagram,
    ...components,
  } satisfies MDXComponents;
}

export const useMDXComponents = getMDXComponents;

declare global {
  type MDXProvidedComponents = ReturnType<typeof getMDXComponents>;
}
