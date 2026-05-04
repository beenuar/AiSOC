import clsx from 'clsx';

interface LogoProps {
  size?: number;
  withWordmark?: boolean;
  className?: string;
}

/**
 * Inline SVG version of the AiSOC mark. We render inline (not from /public/logo.svg)
 * so the gradients can pick up Tailwind brand tokens and so individual elements
 * (the spark) can animate independently when used in the hero.
 */
export function Logo({ size = 36, withWordmark = false, className }: LogoProps) {
  return (
    <span className={clsx('inline-flex items-center gap-3', className)}>
      <svg
        viewBox="0 0 64 64"
        width={size}
        height={size}
        aria-hidden="true"
        className="shrink-0"
      >
        <defs>
          <linearGradient id="aisocLogoOutline" x1="32" y1="8" x2="32" y2="56" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#60a5fa" />
            <stop offset="100%" stopColor="#2563eb" />
          </linearGradient>
          <linearGradient id="aisocLogoBody" x1="32" y1="14" x2="32" y2="52" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#ffffff" />
            <stop offset="100%" stopColor="#cbd5f5" />
          </linearGradient>
          <radialGradient id="aisocLogoSpark" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#fde68a" />
            <stop offset="100%" stopColor="#f59e0b" />
          </radialGradient>
        </defs>
        <path
          d="M32 6 L54 18 L54 42 L32 58 L10 42 L10 18 Z"
          fill="none"
          stroke="url(#aisocLogoOutline)"
          strokeWidth="3"
          strokeLinejoin="round"
        />
        <path
          d="M32 12 L48 21 L48 39 L32 50 L16 39 L16 21 Z"
          fill="rgba(59,130,246,0.08)"
          stroke="url(#aisocLogoOutline)"
          strokeWidth="1.2"
          strokeLinejoin="round"
          opacity="0.7"
        />
        <path
          d="M21 44 L32 16 L43 44 M25.5 35.5 L38.5 35.5"
          fill="none"
          stroke="url(#aisocLogoBody)"
          strokeWidth="3.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle cx="46" cy="18" r="4" fill="url(#aisocLogoSpark)" />
        <circle cx="46" cy="18" r="6.5" fill="none" stroke="rgba(251,191,36,0.4)" strokeWidth="1.4" />
      </svg>
      {withWordmark && (
        <span className="flex items-baseline gap-2 leading-none">
          <span className="text-xl font-bold tracking-tight text-white">AiSOC</span>
          <span className="text-xs font-medium text-gray-500">open-source</span>
        </span>
      )}
    </span>
  );
}
