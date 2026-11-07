// What this deployment believes about itself, answered at request time.
//
// Two things about a console were previously impossible to check from
// outside it. Whether it considers itself a demo was decided by
// NEXT_PUBLIC_DEMO_MODE, which Next inlines when the image is built, so the
// only way to read it was to look at the rendered page and infer — and the
// banner copy is an inlined constant present in the HTML either way, which
// makes grepping for it actively misleading. And the version the bundle was
// built from is not the version of the repository an operator cloned:
// `latest` lags, so "which code am I running" had no answer either.
//
// `export const dynamic` keeps this off the static-render path so the
// environment is read per request rather than frozen at build; `runtime` is
// nodejs because AISOC_DEMO_MODE is a plain server variable with no
// NEXT_PUBLIC_ prefix and the edge runtime would not see it.
//
// Deliberately says nothing about upstream addresses. Those are internal
// topology and this route is unauthenticated — the console has to answer
// before anyone signs in. The resolved upstreams are printed at container
// start by apps/web/docker-entrypoint.sh, which is where an operator looking
// for them already is.
import { NextResponse } from 'next/server';

import { demoModeReport } from '@/lib/demoMode';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export function GET() {
  const demo = demoModeReport();

  return NextResponse.json(
    {
      demoMode: demo.enabled,
      // 'runtime' — AISOC_DEMO_MODE in this container.
      // 'build'   — NEXT_PUBLIC_DEMO_MODE, fixed when the image was built.
      // 'default' — neither was set.
      demoModeSource: demo.source,
      // Trimmed, and `||` rather than `??`. next.config.js substitutes this
      // at build time, so by the time this runs the variable is always
      // *present* and the only question is whether it has content — which is
      // what `??` gets wrong, publishing "" as though it were an answer. It
      // used to substitute "0.0.0", which made this fallback dead code and
      // put a version-shaped placeholder on two console surfaces. The trim
      // is not theoretical: a VERSION file read into a build arg can arrive
      // as whitespace, and " " is truthy.
      consoleVersion: process.env.NEXT_PUBLIC_APP_VERSION?.trim() || 'unknown',
    },
    { headers: { 'cache-control': 'no-store' } },
  );
}
