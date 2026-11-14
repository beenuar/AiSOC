import { AppShell } from '@/components/layout/AppShell';

/**
 * Admin route group layout — WS-H1.
 *
 * Holds tenant-administrator surfaces (cost dashboard, future billing
 * controls, BYOK key rotation, etc.) inside the same `AppShell` chrome the
 * rest of the console uses, so navigation, command palette, and SWR config
 * all behave identically. Pages under this group remain server-rendered by
 * default; individual `*View` components opt into `'use client'` when they
 * need hooks.
 */
export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return <AppShell>{children}</AppShell>;
}
