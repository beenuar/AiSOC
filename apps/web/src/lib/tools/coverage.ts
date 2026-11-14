/**
 * ATT&CK coverage grading for `/tools/coverage`.
 *
 * Parses one or more Sigma rules (or a plain list of technique IDs) entirely in
 * the browser, extracts referenced ATT&CK techniques, and grades coverage
 * against the curated `ATT&CK_CATALOG`. Produces a heatmap-friendly per-tactic
 * breakdown and the top highest-prevalence uncovered techniques — the number
 * analysts screenshot and post.
 */

import { ATTACK_CATALOG, parentTechnique, type AttackTechnique } from "./attack-catalog";
import { coverageGrade } from "@aisoc/report-card";

const TECHNIQUE_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;
// Sigma tags spell techniques as `attack.t1059.001`; also catch bare ids.
const SIGMA_TAG_RE = /attack\.(t\d{4}(?:\.\d{3})?)/gi;

/** Extract every ATT&CK technique id referenced in arbitrary rule text. */
export function extractTechniques(text: string): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(SIGMA_TAG_RE)) {
    if (m[1]) found.add(m[1].toUpperCase());
  }
  for (const m of text.matchAll(TECHNIQUE_RE)) {
    found.add(m[0].toUpperCase());
  }
  return [...found];
}

export interface TacticCoverage {
  tactic: string;
  covered: number;
  total: number;
}

export interface CoverageReport {
  grade: string;
  percent: number;
  covered: number;
  total: number;
  coveredIds: string[];
  byTactic: TacticCoverage[];
  topUncovered: AttackTechnique[];
}

/**
 * Grade coverage. A catalog technique counts as covered when the input
 * references it directly, or references a sub-technique whose parent it is, or
 * references the parent of a catalog sub-technique.
 */
export function gradeCoverage(ruleText: string): CoverageReport {
  const referenced = new Set(extractTechniques(ruleText));
  const referencedParents = new Set([...referenced].map(parentTechnique));

  const isCovered = (t: AttackTechnique): boolean =>
    referenced.has(t.id) || referenced.has(parentTechnique(t.id)) || referencedParents.has(t.id) || referencedParents.has(parentTechnique(t.id));

  const covered = ATTACK_CATALOG.filter(isCovered);
  const coveredIds = covered.map((t) => t.id);
  const total = ATTACK_CATALOG.length;
  const percent = total ? Math.round((covered.length / total) * 100) : 0;

  const tactics = [...new Set(ATTACK_CATALOG.map((t) => t.tactic))];
  const byTactic: TacticCoverage[] = tactics
    .map((tactic) => {
      const inTactic = ATTACK_CATALOG.filter((t) => t.tactic === tactic);
      return { tactic, covered: inTactic.filter(isCovered).length, total: inTactic.length };
    })
    .sort((a, b) => a.tactic.localeCompare(b.tactic));

  const topUncovered = ATTACK_CATALOG.filter((t) => !isCovered(t))
    .sort((a, b) => b.prevalence - a.prevalence)
    .slice(0, 10);

  return { grade: coverageGrade(percent), percent, covered: covered.length, total, coveredIds, byTactic, topUncovered };
}
