// Liveness probe used by Fly.io's http_service.checks. Kept intentionally
// dumb: a 200 here means "Next.js is up and serving routes", nothing more.
// Backend reachability is the API and realtime services' own concern.
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export function GET() {
  return NextResponse.json({ status: 'ok' });
}
