#!/usr/bin/env node
// Validates apps/docs/static/data/scoreboard.json against scoreboard.schema.json.
// Hand-rolled validator — no AJV / no zod dep — so the docs build pulls zero
// extra packages just to gate the scoreboard JSON. Exits 0 on success, 1 on
// any violation. Run via `pnpm --filter @aisoc/docs scoreboard:check`.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_PATH = resolve(__dirname, "../static/data/scoreboard.json");
const SCHEMA_PATH = resolve(__dirname, "../static/data/scoreboard.schema.json");

const errors = [];
const fail = (msg) => errors.push(msg);

function loadJson(p, label) {
  try {
    return JSON.parse(readFileSync(p, "utf-8"));
  } catch (e) {
    fail(`${label} (${p}) is not valid JSON: ${e.message}`);
    return null;
  }
}

const data = loadJson(DATA_PATH, "scoreboard.json");
const schema = loadJson(SCHEMA_PATH, "scoreboard.schema.json");

if (data && schema) {
  // Only validate the parts we care about end-to-end. Hand-rolled to keep the
  // docs build dep-free; if/when we adopt AJV repo-wide, swap this for
  // `new Ajv().compile(schema)(data)`.
  if (typeof data !== "object" || Array.isArray(data)) {
    fail("scoreboard.json must be an object with a `rows` array.");
  } else if (!Array.isArray(data.rows)) {
    fail("scoreboard.json.rows must be an array.");
  } else if (data.rows.length === 0) {
    fail("scoreboard.json.rows must have at least one row (seed substrate row).");
  } else {
    const allowedModes = new Set(
      schema?.properties?.rows?.items?.properties?.eval_mode?.enum ?? [
        "substrate-only",
        "wet-eval-llm-judge",
        "wet-eval-keyword-judge",
      ],
    );
    const required = schema?.properties?.rows?.items?.required ?? [
      "date",
      "agent_version",
      "commit_sha",
      "substrate",
      "eval_mode",
      "mitre_accuracy",
    ];
    const datePat = /^\d{4}-\d{2}-\d{2}$/;
    const versionPat = /^v\d+\.\d+(\.\d+)?(-[A-Za-z0-9.+-]+)?$/;
    const shaPat = /^[0-9a-f]{7,40}$/;

    data.rows.forEach((row, idx) => {
      const where = `rows[${idx}]`;
      if (typeof row !== "object" || row === null) {
        fail(`${where} must be an object`);
        return;
      }
      for (const key of required) {
        if (!(key in row)) fail(`${where} missing required field "${key}"`);
      }
      if (row.date && !datePat.test(row.date)) {
        fail(`${where}.date "${row.date}" must be ISO YYYY-MM-DD`);
      }
      if (row.agent_version && !versionPat.test(row.agent_version)) {
        fail(`${where}.agent_version "${row.agent_version}" must look like vX.Y[.Z][-suffix]`);
      }
      if (row.commit_sha && !shaPat.test(row.commit_sha)) {
        fail(`${where}.commit_sha "${row.commit_sha}" must be a 7–40 char lowercase hex SHA`);
      }
      if ("substrate" in row && typeof row.substrate !== "boolean") {
        fail(`${where}.substrate must be boolean — never elide this field, it gates the "live agent performance" labelling`);
      }
      if (row.eval_mode && !allowedModes.has(row.eval_mode)) {
        fail(`${where}.eval_mode "${row.eval_mode}" not in ${Array.from(allowedModes).join(" | ")}`);
      }
      const ratios = [
        "mitre_accuracy",
        "mitre_accuracy_per_template",
        "alert_reduction",
        "investigation_completeness",
        "response_quality",
        "playbook_completion_rate",
      ];
      for (const k of ratios) {
        const v = row[k];
        if (v === null || v === undefined) continue;
        if (typeof v !== "number" || v < 0 || v > 1 || Number.isNaN(v)) {
          fail(`${where}.${k} "${v}" must be a number in [0, 1]`);
        }
      }
      const positives = [
        "mtc_p50_seconds",
        "mtc_p95_seconds",
        "tokens_total",
        "usd_total",
        "tokens_mean_per_investigation",
        "usd_mean_per_investigation",
      ];
      for (const k of positives) {
        const v = row[k];
        if (v === null || v === undefined) continue;
        if (typeof v !== "number" || v < 0 || Number.isNaN(v)) {
          fail(`${where}.${k} "${v}" must be a non-negative number`);
        }
      }
      // Substrate rows must explicitly null out MTC — refuse a substrate row
      // that quotes a fake live timing.
      if (row.substrate === true) {
        for (const k of ["mtc_p50_seconds", "mtc_p95_seconds"]) {
          if (row[k] !== null && row[k] !== undefined) {
            fail(`${where}.${k} must be null on substrate rows — substrate runs in microseconds, not a meaningful end-to-end timing`);
          }
        }
        if (row.eval_mode !== "substrate-only") {
          fail(`${where}.eval_mode must be "substrate-only" when substrate:true`);
        }
      } else if (row.substrate === false && !String(row.eval_mode || "").startsWith("wet-eval")) {
        fail(`${where}.eval_mode must start with "wet-eval-" when substrate:false`);
      }
    });

    // Append-only invariant: dates must be strictly non-decreasing when sorted
    // by their position in the file? We don't enforce ordering — UI sorts —
    // but no two rows may share (date, commit_sha) since that's the row key.
    const seen = new Set();
    data.rows.forEach((row, idx) => {
      const key = `${row.date || "?"}::${row.commit_sha || "?"}`;
      if (seen.has(key)) {
        fail(`rows[${idx}] duplicates the (date, commit_sha) key "${key}" — scoreboard rows must be unique`);
      }
      seen.add(key);
    });
  }
}

if (errors.length > 0) {
  console.error("scoreboard:check FAILED");
  for (const e of errors) console.error("  -", e);
  process.exit(1);
}

console.log(`scoreboard:check OK — ${data.rows.length} row(s) validated`);
