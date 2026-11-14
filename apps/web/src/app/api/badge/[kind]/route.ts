import { NextResponse } from "next/server";

/**
 * shields.io-compatible endpoint badges (v8 W3.4).
 *
 * Embed anywhere shields renders, e.g. in a README:
 *   ![AiSOC](https://img.shields.io/endpoint?url=https://tryaisoc.com/api/badge/triaged)
 *
 * Badges are backlinks that live in other people's READMEs. The GitHub Action
 * (W4) links its "triaged" badge here with a per-run `?message=` override; the
 * eval leaderboard links the "benchmark" badge; marketplace rules that pass the
 * eval gate carry the "verified-detection" badge.
 *
 * Response follows the shields "endpoint" schema:
 *   { schemaVersion: 1, label, message, color }
 * `label`, `message`, and `color` are overridable via query params so callers
 * can reflect their own numbers (kept honest by the caller, not fabricated here).
 */

interface BadgeSpec {
  label: string;
  message: string;
  color: string;
}

const DEFAULTS: Record<string, BadgeSpec> = {
  triaged: { label: "AiSOC", message: "alerts triaged", color: "7b2bbe" },
  "noise-suppressed": { label: "AiSOC noise", message: "suppressed", color: "22c55e" },
  benchmark: { label: "AiSOC benchmark", message: "see scoreboard", color: "3b82f6" },
  "verified-detection": { label: "AiSOC", message: "verified detection", color: "22c55e" },
  "self-play": { label: "AiSOC self-play", message: "nightly", color: "ec4899" },
};

const ALLOWED_COLOR = /^[0-9a-zA-Z]+$/;

export async function GET(request: Request, { params }: { params: Promise<{ kind: string }> }) {
  const { kind } = await params;
  const spec = DEFAULTS[kind];
  if (!spec) {
    return NextResponse.json(
      { schemaVersion: 1, label: "AiSOC", message: "unknown badge", color: "inactive", isError: true },
      { status: 404 },
    );
  }

  const url = new URL(request.url);
  const label = (url.searchParams.get("label") || spec.label).slice(0, 64);
  const message = (url.searchParams.get("message") || spec.message).slice(0, 64);
  const colorParam = url.searchParams.get("color");
  const color = colorParam && ALLOWED_COLOR.test(colorParam) ? colorParam : spec.color;

  return NextResponse.json(
    { schemaVersion: 1, label, message, color, namedLogo: "target", labelColor: "0b1020" },
    {
      headers: {
        // Cacheable at the CDN; shields also caches. Short enough that a
        // per-run override reflects quickly.
        "Cache-Control": "public, max-age=300, s-maxage=300",
      },
    },
  );
}
