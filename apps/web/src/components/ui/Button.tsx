/**
 * T3.8 — AiSOC console Button primitive.
 *
 * The console already had ~40 inline ``<button className="...">``s with
 * subtly different padding, radius, and hover colours. This component
 * codifies the canonical set so the Storybook design system has a
 * single source of truth.
 *
 * Variants:
 *   - primary   — solid blue, the main CTA on a page
 *   - secondary — subtle gray, supporting actions
 *   - destructive — solid red, irreversible actions (block IP, etc.)
 *   - ghost     — transparent until hovered
 *   - outline   — bordered, for low-emphasis actions next to a primary
 *
 * Sizes follow the 4-token ladder (xs / sm / md / lg) the rest of the
 * console uses for tap-target heights.
 */
import { clsx } from 'clsx';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { forwardRef } from 'react';

export type ButtonVariant =
  | 'primary'
  | 'secondary'
  | 'destructive'
  | 'ghost'
  | 'outline';

export type ButtonSize = 'xs' | 'sm' | 'md' | 'lg';

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary:
    'bg-blue-600 text-white hover:bg-blue-500 active:bg-blue-700 disabled:bg-blue-600/40',
  secondary:
    'bg-gray-800 text-gray-200 hover:bg-gray-700 active:bg-gray-700 disabled:bg-gray-800/40 disabled:text-gray-500',
  destructive:
    'bg-red-600 text-white hover:bg-red-500 active:bg-red-700 disabled:bg-red-600/40',
  ghost:
    'bg-transparent text-gray-300 hover:bg-gray-800/60 hover:text-gray-100 disabled:text-gray-600',
  outline:
    'bg-transparent text-gray-300 border border-gray-700 hover:border-gray-600 hover:bg-gray-800/40 disabled:opacity-50',
};

const SIZE_CLASSES: Record<ButtonSize, string> = {
  xs: 'h-7 px-2 text-xs gap-1.5',
  sm: 'h-8 px-3 text-xs gap-1.5',
  md: 'h-9 px-4 text-sm gap-2',
  lg: 'h-11 px-5 text-sm font-medium gap-2',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
  /** Renders an inline spinner and disables the button. */
  loading?: boolean;
  /** Sets ``aria-pressed`` and a subtle pressed style; used for toggles. */
  pressed?: boolean;
}

/**
 * Console button primitive. Forwards its ref so popovers and tooltips
 * can anchor to it without contortions.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'primary',
    size = 'md',
    leadingIcon,
    trailingIcon,
    loading = false,
    pressed,
    disabled,
    className,
    children,
    type = 'button',
    ...rest
  },
  ref,
) {
  const isDisabled = disabled || loading;
  return (
    <button
      ref={ref}
      type={type}
      disabled={isDisabled}
      aria-pressed={pressed}
      aria-busy={loading || undefined}
      className={clsx(
        'inline-flex items-center justify-center rounded-lg font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60 disabled:cursor-not-allowed',
        VARIANT_CLASSES[variant],
        SIZE_CLASSES[size],
        pressed && 'ring-1 ring-blue-500/40',
        className,
      )}
      {...rest}
    >
      {loading ? (
        <span
          aria-hidden="true"
          className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-r-transparent"
        />
      ) : (
        leadingIcon
      )}
      <span>{children}</span>
      {!loading && trailingIcon}
    </button>
  );
});
