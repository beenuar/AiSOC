import { redirect } from 'next/navigation';

interface ResponderIndexPageProps {
  searchParams: Promise<{ tab?: string | string[] }>;
}

/**
 * Keep installed shortcuts using `/responder?tab=...` working after the
 * manifest moves to the canonical child routes. Unrecognized or repeated
 * tab parameters retain the default triage destination.
 *
 * Keeping the redirect server-side avoids a flash of an empty shell.
 */
export default async function ResponderIndexPage({
  searchParams,
}: ResponderIndexPageProps): Promise<never> {
  const { tab } = await searchParams;
  switch (tab) {
    case 'cases':
      redirect('/responder/case');
    case 'oncall':
      redirect('/responder/oncall');
    default:
      redirect('/responder/triage');
  }
}
