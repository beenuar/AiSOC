/**
 * /settings/business-context — Track 3, T3.5.
 *
 * Operator-facing editor for the YAML rule set that runs between the
 * fusion pipeline and the triage agent. Three panels:
 *
 *   1. Monaco YAML editor on the left (the source of truth).
 *   2. Rule-builder side-panel on the right (helper UI for analysts
 *      who don't speak YAML; lets them assemble a rule and have it
 *      appended to the editor).
 *   3. Live preview row at the bottom (POSTs the current YAML +
 *      either supplied alerts or "fetch the last 50" to /preview and
 *      renders before/after).
 *
 * The editor is debounced 300ms before it triggers a preview re-run
 * so an analyst typing a long predicate doesn't spam the API.
 */
import type { Metadata } from "next";

import { BusinessContextSettings } from "./BusinessContextSettings";

export const metadata: Metadata = {
  title: "Business Context Rules | Settings | AiSOC",
};

export default function BusinessContextSettingsPage() {
  return <BusinessContextSettings />;
}
