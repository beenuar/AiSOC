/**
 * Chronological presentation of a ranked attack chain.
 *
 * `GET /cases/{id}/attack-chain` returns its links in **relevance** order —
 * graph distance, time proximity and MITRE overlap, truncated to the most
 * relevant N. That ranking is deliberate and stays: it decides *which*
 * alerts belong in the chain.
 *
 * Reading order is a separate question, and the console answered it wrongly
 * for a long time: it rendered the ranked array as-is under a comment
 * claiming the backend had already sorted it oldest-first, and labelled row
 * 0 "seed". The seed is never in the chain at all — `compute_attack_chain`
 * scores "every non-seed candidate" — so that label named the top-ranked
 * related alert and swallowed its real distance from the seed.
 *
 * So: rank to select, time to read. These helpers do the second half, and
 * they refuse to invent what the payload does not carry — an older cached
 * response without `seed_event_time` gets an unsigned distance, not a
 * guessed direction.
 */

import type { AttackChainLink } from "./api";

function instant(iso: string): number | null {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * The chain oldest-first, as a new array. Links whose timestamp cannot be
 * parsed sort last rather than vanishing: a link we cannot place in time is
 * still evidence, and dropping it would quietly shorten the chain.
 */
export function orderChainChronologically(chain: AttackChainLink[]): AttackChainLink[] {
  return [...chain].sort((a, b) => {
    const ta = instant(a.eventTime);
    const tb = instant(b.eventTime);
    if (ta === null && tb === null) return a.alertId.localeCompare(b.alertId);
    if (ta === null) return 1;
    if (tb === null) return -1;
    if (ta !== tb) return ta - tb;
    // Stable across renders when two alerts share an instant.
    return a.alertId.localeCompare(b.alertId);
  });
}

function magnitude(seconds: number): string {
  const abs = Math.abs(seconds);
  if (abs < 60) return `${Math.max(1, Math.round(abs))}s`;
  const minutes = Math.round(abs / 60);
  if (minutes < 60) return `${minutes}m`;
  return `${(abs / 3600).toFixed(1)}h`;
}

/**
 * How far this link sits from the seed, and on which side.
 *
 * `dtSeconds` from the API is an absolute distance, so the direction comes
 * from comparing the two timestamps. With no seed timestamp available the
 * label says the distance and stops there.
 */
export function seedRelativeLabel(
  link: AttackChainLink,
  seedEventTime: string | null,
): string {
  if (!seedEventTime) {
    return `${magnitude(link.dtSeconds)} from seed`;
  }
  const seed = instant(seedEventTime);
  const at = instant(link.eventTime);
  if (seed === null || at === null) {
    return `${magnitude(link.dtSeconds)} from seed`;
  }
  const deltaSeconds = (at - seed) / 1000;
  if (Math.round(deltaSeconds) === 0) return "same moment";
  // U+2212 MINUS SIGN, so "before the seed" is not read as a hyphen.
  return `${deltaSeconds < 0 ? "\u2212" : "+"}${magnitude(deltaSeconds)}`;
}
