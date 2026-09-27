'use client';

import useSWR from 'swr';

import { type Branding, brandingApi } from '@/lib/api';

/**
 * The platform appearance, used while the request is in flight and if it fails.
 *
 * This is not mock data. It is what an unbranded deployment genuinely looks
 * like, and it is the same set of values the API returns for a tenant that
 * belongs to no organisation. Rendering an empty header instead would make
 * every page load flash a nameless product.
 */
export const DEFAULT_BRANDING: Branding = {
  product_name: 'AiSOC',
  primary_color: '#2563EB',
  accent_color: '#7C3AED',
  support_email: null,
  support_url: null,
  sender_name: 'AiSOC',
  footer_text: 'AiSOC — open-source AI Security Operations Center.',
  logo_url: null,
  org_id: null,
  is_white_labelled: false,
};

export function useBranding(): { branding: Branding; isLoading: boolean } {
  const { data, isLoading } = useSWR<Branding>('branding', () => brandingApi.get(), {
    // Branding moves when an administrator moves it, which is rare.
    // Revalidating on focus would put a request behind every tab switch for
    // a value that has not changed.
    revalidateOnFocus: false,
    dedupingInterval: 300_000,
  });

  return { branding: data ?? DEFAULT_BRANDING, isLoading };
}
