import { source } from '@/lib/source';
import { createFromSource } from 'fumadocs-core/search/server';

// Static search: the index is exported once at build time and queried in the
// browser, so the site needs no server (GitHub Pages).
export const revalidate = false;

export const { staticGET: GET } = createFromSource(source, {
  // https://docs.orama.com/docs/orama-js/supported-languages
  language: 'english',
});
