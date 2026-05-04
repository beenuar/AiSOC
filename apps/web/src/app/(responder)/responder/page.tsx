import { redirect } from 'next/navigation';

/**
 * `/responder` is purely a navigation alias. The responder PWA opens straight
 * into the triage queue — that's the on-call view 95% of the time.
 *
 * Keeping the redirect server-side avoids a flash of an empty shell.
 */
export default function ResponderIndexPage(): never {
  redirect('/responder/triage');
}
