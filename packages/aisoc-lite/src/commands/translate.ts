/**
 * `aisoc translate <rule>` — CLI front for the deterministic detection
 * translator. Reads a rule from a file or stdin and prints each target dialect.
 */

import { readFile } from "node:fs/promises";
import pc from "picocolors";
import { translateRule, type DetectionFormat, FORMAT_LABELS } from "../verdict/translate.js";

const FORMATS: DetectionFormat[] = ["sigma", "spl", "kql", "esql", "yara_l2", "udm"];

export interface TranslateFlags {
  from?: string;
  to?: string;
  file?: string;
  json?: boolean;
}

function parseFormat(value: string | undefined, fallback: DetectionFormat): DetectionFormat {
  const v = (value ?? "").toLowerCase();
  return (FORMATS as string[]).includes(v) ? (v as DetectionFormat) : fallback;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

export async function runTranslate(
  ruleArg: string | undefined,
  flags: TranslateFlags,
  log: (s: string) => void = console.log,
): Promise<void> {
  let source = ruleArg ?? "";
  if (flags.file) source = await readFile(flags.file, "utf8");
  if (!source.trim() && !process.stdin.isTTY) source = await readStdin();
  if (!source.trim()) {
    throw new Error("no rule provided. Pass a rule inline, via --file <path>, or pipe it on stdin.");
  }

  const from = parseFormat(flags.from, "sigma");
  const targets = flags.to
    ? flags.to.split(",").map((t) => parseFormat(t.trim(), "sigma"))
    : (FORMATS.filter((f) => f !== from) as DetectionFormat[]);

  const out = translateRule(source, from, targets);

  if (flags.json) {
    log(JSON.stringify(out, null, 2));
    return;
  }

  log("");
  log(pc.bold(`Translated from ${FORMAT_LABELS[from]}`) + pc.dim(" (deterministic field-map)"));
  for (const r of out.results) {
    log("");
    log(pc.cyan(pc.bold(`── ${r.label} ──`)));
    log(r.rule);
  }
  log("");
  for (const w of out.warnings) log(pc.yellow(`⚠ ${w}`));
  log("");
}
