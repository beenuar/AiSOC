#!/usr/bin/env node
/**
 * Deterministic demo-alert fixture generator for `aisoc triage --demo`.
 *
 * Produces exactly 200 alerts with a realistic SOC noise distribution tuned so
 * the headline lands at "12 TP, 171 FP suppressed (95.5% noise), 17 need
 * review" — the numbers used in the README top fold and the launch materials.
 *
 * Determinism: a seeded mulberry32 PRNG. Re-running this script byte-for-byte
 * reproduces `src/fixtures/demo-alerts.json`. The `--demo` path must never
 * depend on wall-clock time or network, so every field is derived from the
 * seed.
 *
 * Run: `node scripts/gen-fixtures.mjs` (or `pnpm gen:fixtures`).
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "src", "fixtures", "demo-alerts.json");

function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = mulberry32(0x415_50c); // "AiSOC" flavored fixed seed
const pick = (arr) => arr[Math.floor(rng() * arr.length)];
const chance = (p) => rng() < p;
const ipOctet = () => Math.floor(rng() * 254) + 1;
const rndIp = () => `${ipOctet()}.${ipOctet()}.${ipOctet()}.${ipOctet()}`;
const hex = (n) => Array.from({ length: n }, () => "0123456789abcdef"[Math.floor(rng() * 16)]).join("");

const SOURCES = ["splunk", "sentinel", "elastic", "crowdstrike", "guardduty", "okta", "m365"];
const HOSTS = ["WIN-FIN-DB01", "web-prod-07", "jump-01", "hr-laptop-22", "k8s-node-14", "mail-gw-02", "dev-box-09"];
const USERS = ["j.doe", "svc_backup", "a.patel", "root", "admin", "s.kim", "contractor_31"];

// ── Benign noise templates (85.5% → 171 alerts): low risk, no keywords ───────
const BENIGN = [
  { t: "Scheduled backup job completed", raw: "veeam backup finished nominal, 0 errors" },
  { t: "DNS query to CDN endpoint", raw: "resolved cdn.jsdelivr.net for asset fetch" },
  { t: "Successful VPN login from known device", raw: "user connected from managed laptop, mfa satisfied" },
  { t: "Windows Defender signature update", raw: "definitions updated to latest, routine" },
  { t: "TLS certificate renewal", raw: "acme renewed cert for internal service" },
  { t: "Package manager fetched dependency", raw: "npm install pulled cached tarball" },
  { t: "Kubernetes liveness probe restart", raw: "pod restarted after failed healthcheck, self-healed" },
  { t: "Outbound SMTP to mail relay", raw: "newsletter batch sent via approved relay" },
  { t: "User password change (self-service)", raw: "password rotated via portal, policy compliant" },
  { t: "S3 bucket read from same account", raw: "internal analytics job read logs bucket" },
  { t: "Antivirus quarantine of EICAR test", raw: "eicar test file quarantined during av validation" },
  { t: "Firewall allowed established connection", raw: "return traffic on established session" },
];

// ── Review-band templates (8.5% → 17 alerts): medium risk, one weak signal ───
// No critical/high keywords (see scoring.py sets); the risk score alone plus at
// most one small IOC/host bump keeps these inside the needs_review band
// [0.40, 0.60). Titles/raws are deliberately keyword-free.
const REVIEW = [
  { t: "Unusual login hour for user", raw: "sign-in at 03:12 local, first time this quarter" },
  { t: "New device enrolled to identity provider", raw: "unrecognized device added to identity provider" },
  { t: "Elevated process spawned by office app", raw: "winword launched a child interpreter, no known template" },
  { t: "Outbound connection to newly-seen domain", raw: "first-seen destination contacted by workstation" },
  { t: "Several failed sign-ins then success", raw: "5 failures then a success, possible fat-finger" },
  { t: "Large file read from file share", raw: "user read 400 files from finance share in 2 minutes" },
];

// ── True-positive templates (6% → 12 alerts): critical keyword + risk + IOCs ─
const MALICIOUS = [
  {
    t: "Ransomware canary files encrypted on host",
    raw: "mass file rename to .lockbit extension, ransomware note dropped, shadow copies deleted",
    techniques: ["T1486", "T1490"],
    risk: 0.94,
  },
  {
    t: "Lateral movement via SMB with dumped credentials",
    raw: "credential dump observed, lateral movement to 3 hosts using mimikatz-harvested hashes",
    techniques: ["T1021.002", "T1003.001", "T1550.002"],
    risk: 0.9,
  },
  {
    t: "Cobalt Strike beacon C2 detected",
    raw: "cobalt strike beacon calling home to c2 over https jitter pattern",
    techniques: ["T1071.001", "T1573"],
    risk: 0.92,
  },
  {
    t: "Data exfiltration to external host",
    raw: "exfiltration of 12GB to unknown external ip over dns tunneling",
    techniques: ["T1048", "T1071.004"],
    risk: 0.88,
  },
  {
    t: "Suspected supply chain backdoor in build",
    raw: "supply chain: unexpected backdoor payload injected into ci artifact",
    techniques: ["T1195.002"],
    risk: 0.9,
  },
];

const alerts = [];
let n = 0;

function push(a) {
  n += 1;
  alerts.push({ id: `DEMO-${String(n).padStart(4, "0")}`, ...a });
}

// 171 benign
for (let i = 0; i < 171; i++) {
  const tpl = pick(BENIGN);
  push({
    title: tpl.t,
    source: pick(SOURCES),
    severity: chance(0.2) ? "low" : "info",
    riskScore: Number((rng() * 0.15).toFixed(2)),
    raw: tpl.raw,
    // Occasionally a benign alert carries a src IP; still below the review band.
    ...(chance(0.25) ? { iocs: { srcIp: rndIp() } } : {}),
  });
}

// 17 review — risk in [0.72, 0.78] → weight [0.432, 0.468]; at most +0.10 from
// one host + one IOC keeps the total inside [0.40, 0.60).
for (let i = 0; i < 17; i++) {
  const tpl = pick(REVIEW);
  push({
    title: tpl.t,
    source: pick(SOURCES),
    severity: "medium",
    riskScore: Number((0.72 + rng() * 0.06).toFixed(2)),
    hostname: chance(0.5) ? pick(HOSTS) : undefined,
    username: pick(USERS),
    raw: tpl.raw,
    ...(chance(0.5) ? { iocs: { srcIp: rndIp() } } : {}),
  });
}

// 12 true-positive
for (let i = 0; i < 12; i++) {
  const tpl = MALICIOUS[i % MALICIOUS.length];
  push({
    title: tpl.t,
    source: pick(SOURCES),
    severity: "critical",
    riskScore: Number((tpl.risk + rng() * 0.04).toFixed(2)),
    hostname: pick(HOSTS),
    username: pick(USERS),
    techniques: tpl.techniques,
    raw: tpl.raw,
    iocs: {
      srcIp: rndIp(),
      dstIp: rndIp(),
      fileHash: hex(64),
      domain: chance(0.6) ? `${hex(8)}.badexample.test` : undefined,
    },
  });
}

// Deterministic shuffle (Fisher–Yates over the same PRNG) so verdicts aren't
// pre-sorted by band in the raw fixture — the engine sorts at render time.
for (let i = alerts.length - 1; i > 0; i--) {
  const j = Math.floor(rng() * (i + 1));
  [alerts[i], alerts[j]] = [alerts[j], alerts[i]];
}

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(
  OUT,
  JSON.stringify(
    {
      _comment:
        "Deterministic demo fixture for `aisoc triage --demo`. Generated by scripts/gen-fixtures.mjs (seeded). Do not edit by hand; run `pnpm gen:fixtures`.",
      generatedBy: "scripts/gen-fixtures.mjs",
      count: alerts.length,
      alerts,
    },
    null,
    2,
  ) + "\n",
);

console.log(`Wrote ${alerts.length} demo alerts → ${OUT}`);
