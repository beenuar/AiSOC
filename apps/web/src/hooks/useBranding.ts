'use client';

import { useEffect, useState } from 'react';
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

/**
 * A displayable source for the brand logo, or `null`.
 *
 * `branding.logo_url` is a path on this deployment and the route behind it
 * authenticates a bearer token. An `<img src>` pointing at it sends cookies
 * and nothing else, so the image came back 401 and the sidebar rendered a
 * broken logo on every deployment that was not running the development auth
 * shim. The bytes are fetched with the credential and handed to the DOM as
 * an object URL.
 *
 * `null` on failure, which every renderer already treats as "use the
 * wordmark" — a missing logo is a layout this project ships.
 */
export function useBrandLogo(logoUrl: string | null): string | null {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!logoUrl) {
      setObjectUrl(null);
      return;
    }

    let cancelled = false;
    let created: string | null = null;

    brandingApi
      .logo(logoUrl)
      .then((blob) => {
        if (cancelled) return;
        created = URL.createObjectURL(blob);
        setObjectUrl(created);
      })
      .catch(() => {
        if (!cancelled) setObjectUrl(null);
      });

    return () => {
      cancelled = true;
      // An object URL pins its blob in memory until it is revoked, and the
      // shell remounts on every sign-in.
      if (created) URL.revokeObjectURL(created);
    };
  }, [logoUrl]);

  return objectUrl;
}
