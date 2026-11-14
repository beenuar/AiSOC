import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Compose Tailwind classes safely: `clsx` resolves conditional inputs and
 * `tailwind-merge` collapses conflicts (e.g. `px-4` later replacing `px-2`).
 *
 * Aceternity UI, MagicUI, and shadcn/ui-style primitives all expect a `cn`
 * helper at `@/lib/utils`; this is the single source of truth so the copied
 * source files in `apps/web/src/components/{aceternity,magicui}/` can import
 * it without each shipping its own merge implementation.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
