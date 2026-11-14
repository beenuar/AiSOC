#!/usr/bin/env node
/**
 * `aisoc` — the wedge CLI.
 *
 * A tiny, dependency-light argument parser (only picocolors at runtime) keeps
 * `npx aisoc` cold-start fast and the supply-chain surface small — this is a
 * security tool, so every dependency is a liability.
 */

import pc from "picocolors";
import { runTriage, type TriageFlags } from "./commands/triage.js";
import { runTranslate, type TranslateFlags } from "./commands/translate.js";
import { runUp, type UpFlags } from "./commands/up.js";
import { VERSION } from "./version.js";

interface Parsed {
  command: string | undefined;
  positionals: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Parsed {
  const [command, ...rest] = argv;
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positionals.push(arg);
    }
  }
  return { command, positionals, flags };
}

function toBool(v: string | boolean | undefined): boolean | undefined {
  if (v === undefined) return undefined;
  if (typeof v === "boolean") return v;
  return v !== "false" && v !== "0";
}

function toNum(v: string | boolean | undefined): number | undefined {
  if (typeof v !== "string") return undefined;
  const n = Number(v);
  return Number.isNaN(n) ? undefined : n;
}

const HELP = `${pc.bold("aisoc")} — triage security alerts to verdicts in seconds. ${pc.dim(`v${VERSION}`)}

${pc.bold("USAGE")}
  npx aisoc <command> [options]

${pc.bold("COMMANDS")}
  triage            Score a batch of alerts to verdicts (TP / review / suppress)
  translate <rule>  Translate a detection rule across Sigma / SPL / KQL / ES|QL / YARA-L2 / UDM
  up                Boot the full local demo stack from a pinned compose bundle (needs Docker)
  help              Show this help

${pc.bold("TRIAGE OPTIONS")}
  --demo            Zero-credential, deterministic 200-alert demo (finishes in seconds)
  --file <path>     Triage a local JSONL / JSON alert export
  --source <name>   demo | jsonl | splunk | sentinel | elastic | crowdstrike
  --limit <n>       Cap the number of alerts triaged
  --max-rows <n>    Cap table rows printed (default 20; escalations shown first)
  --attention-only  Hide suppressed noise; show only escalate + review
  --llm             Use YOUR ANTHROPIC_API_KEY / OPENAI_API_KEY to refine the ambiguous middle (never proxied)
  --json            Emit machine-readable JSON
  --share [path]    Write a redacted, postable report card (Markdown + SVG)
  --telemetry       Opt IN to aggregate-only telemetry (default OFF; see TELEMETRY.md)
  --no-telemetry    Force telemetry off

${pc.bold("TRANSLATE OPTIONS")}
  --from <fmt>      Source format (default: sigma)
  --to <a,b,c>      Comma-separated target formats (default: all others)
  --file <path>     Read the rule from a file (else inline arg or stdin)
  --json            Emit machine-readable JSON

${pc.bold("EXAMPLES")}
  npx aisoc triage --demo
  npx aisoc triage --file alerts.jsonl --attention-only --share
  cat rule.yml | npx aisoc translate --from sigma --to spl,kql
  npx aisoc up

Open source · MIT · https://github.com/beenuar/AiSOC
`;

async function main(): Promise<number> {
  const { command, positionals, flags } = parseArgs(process.argv.slice(2));

  if (flags.version || flags.v || command === "version") {
    console.log(VERSION);
    return 0;
  }

  switch (command) {
    case undefined:
    case "help":
    case "--help":
      console.log(HELP);
      return 0;

    case "triage": {
      const tf: TriageFlags = {
        demo: toBool(flags.demo),
        file: typeof flags.file === "string" ? flags.file : undefined,
        source: typeof flags.source === "string" ? flags.source : undefined,
        limit: toNum(flags.limit),
        maxRows: toNum(flags["max-rows"]),
        attentionOnly: toBool(flags["attention-only"]),
        json: toBool(flags.json),
        share: flags.share === true ? true : typeof flags.share === "string" ? flags.share : undefined,
        llm: toBool(flags.llm),
        telemetry: toBool(flags.telemetry),
        noTelemetry: toBool(flags["no-telemetry"]),
      };
      await runTriage(tf);
      return 0;
    }

    case "up": {
      const uf: UpFlags = {
        ref: typeof flags.ref === "string" ? flags.ref : undefined,
        noOpen: toBool(flags["no-open"]),
        json: toBool(flags.json),
      };
      return runUp(uf);
    }

    case "translate": {
      const trf: TranslateFlags = {
        from: typeof flags.from === "string" ? flags.from : undefined,
        to: typeof flags.to === "string" ? flags.to : undefined,
        file: typeof flags.file === "string" ? flags.file : undefined,
        json: toBool(flags.json),
      };
      await runTranslate(positionals[0], trf);
      return 0;
    }

    default:
      console.error(pc.red(`Unknown command: ${command}`));
      console.error(pc.dim("Run `npx aisoc help` for usage."));
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(pc.red(`\naisoc: ${(err as Error).message}\n`));
    process.exit(1);
  });
