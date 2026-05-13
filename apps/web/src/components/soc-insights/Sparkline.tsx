/**
 * Inline-SVG sparkline (T3.1).
 *
 * Deliberately dependency-free — we render a single polyline normalised
 * into a fixed 100×30 viewbox so the SVG is responsive without needing
 * a chart library. The tile cards constrain the width via Tailwind,
 * so the line stays sharp regardless of breakpoint.
 *
 * The points are values from the aggregator endpoint (24 buckets,
 * oldest → newest). Zero or one points renders a flat baseline so the
 * tile doesn't look broken on a brand-new tenant.
 */
'use client';

interface SparklineProps {
  points: number[];
  /** Width in px when rendered inline. The viewbox stays fixed at 100×30. */
  width?: number;
  height?: number;
  className?: string;
}

const VIEWBOX_WIDTH = 100;
const VIEWBOX_HEIGHT = 30;

export function Sparkline({
  points,
  width = 96,
  height = 28,
  className,
}: SparklineProps) {
  const path = pointsToPath(points);

  return (
    <svg
      viewBox={`0 0 ${VIEWBOX_WIDTH} ${VIEWBOX_HEIGHT}`}
      width={width}
      height={height}
      role="img"
      aria-label="Trend over the selected window"
      className={className}
      preserveAspectRatio="none"
    >
      <polyline
        points={path}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.4}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Helpers (exported so the smoke test can lock the math)
// ---------------------------------------------------------------------------

export function pointsToPath(points: number[]): string {
  if (!points || points.length === 0) {
    // Centre a flat baseline so the tile reads as "no data" rather
    // than broken.
    return `0,${VIEWBOX_HEIGHT / 2} ${VIEWBOX_WIDTH},${VIEWBOX_HEIGHT / 2}`;
  }
  if (points.length === 1) {
    return `0,${VIEWBOX_HEIGHT / 2} ${VIEWBOX_WIDTH},${VIEWBOX_HEIGHT / 2}`;
  }

  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;

  const stepX = VIEWBOX_WIDTH / (points.length - 1);
  // 10% padding top + bottom so peaks/troughs don't kiss the edge.
  const yScale = VIEWBOX_HEIGHT * 0.8;
  const yOffset = VIEWBOX_HEIGHT * 0.1;

  return points
    .map((value, i) => {
      const x = i * stepX;
      // SVG y axis grows downwards; we want the chart to grow up so
      // higher values render higher.
      const y = VIEWBOX_HEIGHT - (((value - min) / range) * yScale + yOffset);
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(' ');
}
