import { source } from '@/lib/source';
import { llms } from 'fumadocs-core/source';

export const revalidate = false;
export const dynamic = 'force-static';

export async function GET() {
  return new Response(await llms(source).index());
}
