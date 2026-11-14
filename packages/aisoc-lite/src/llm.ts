/**
 * Optional BYO-key LLM band.
 *
 * The deterministic engine (`src/verdict/`) is always the floor and always
 * runs. When the user supplies their OWN key (ANTHROPIC_API_KEY or
 * OPENAI_API_KEY) and opts in with `--llm`, this band re-ranks the alerts the
 * deterministic engine flagged as `needs_review` — the ambiguous middle — and
 * can nudge them toward escalate/suppress with a rationale.
 *
 * The key is read from the user's own environment and used to call the
 * provider directly. It is never proxied through any AiSOC server. Demo and CI
 * paths never touch this file.
 */

import type { Alert, Verdict } from "./verdict/types.js";

export interface LlmRefinement {
  alertId: string;
  verdict: Verdict;
  confidence: number;
  rationale: string;
}

export interface LlmProvider {
  name: "anthropic" | "openai";
  model: string;
}

export function detectProvider(): LlmProvider | null {
  if (process.env.ANTHROPIC_API_KEY) {
    return { name: "anthropic", model: process.env.AISOC_LLM_MODEL || "claude-3-5-haiku-latest" };
  }
  if (process.env.OPENAI_API_KEY) {
    return { name: "openai", model: process.env.AISOC_LLM_MODEL || "gpt-4o-mini" };
  }
  return null;
}

const SYSTEM = [
  "You are a senior SOC analyst. For each alert, decide a verdict from exactly:",
  "true_positive, likely_true_positive, needs_review, likely_benign.",
  "Return ONLY compact JSON: {\"verdicts\":[{\"id\":\"..\",\"verdict\":\"..\",\"confidence\":0.0,\"rationale\":\"..\"}]}.",
  "confidence is 0..1. Be conservative; prefer needs_review over guessing.",
].join(" ");

function buildUserPrompt(alerts: Alert[]): string {
  const compact = alerts.map((a) => ({
    id: a.id,
    title: a.title,
    severity: a.severity,
    risk: a.riskScore,
    techniques: a.techniques,
    iocs: a.iocs,
    raw: (a.raw ?? "").slice(0, 400),
  }));
  return `Triage these alerts and return JSON:\n${JSON.stringify(compact)}`;
}

async function callAnthropic(model: string, prompt: string): Promise<string> {
  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY as string,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 1500,
      system: SYSTEM,
      messages: [{ role: "user", content: prompt }],
    }),
  });
  if (!resp.ok) throw new Error(`anthropic ${resp.status}`);
  const data = (await resp.json()) as { content: { text?: string }[] };
  return data.content?.map((c) => c.text ?? "").join("") ?? "";
}

async function callOpenAI(model: string, prompt: string): Promise<string> {
  const base = process.env.OPENAI_BASE_URL || "https://api.openai.com/v1";
  const resp = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${process.env.OPENAI_API_KEY as string}`,
    },
    body: JSON.stringify({
      model,
      temperature: 0.1,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: SYSTEM },
        { role: "user", content: prompt },
      ],
    }),
  });
  if (!resp.ok) throw new Error(`openai ${resp.status}`);
  const data = (await resp.json()) as { choices: { message: { content: string } }[] };
  return data.choices?.[0]?.message?.content ?? "";
}

function parseRefinements(text: string): LlmRefinement[] {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end < 0) return [];
  try {
    const obj = JSON.parse(text.slice(start, end + 1)) as {
      verdicts?: { id: string; verdict: Verdict; confidence: number; rationale?: string }[];
    };
    return (obj.verdicts ?? []).map((v) => ({
      alertId: v.id,
      verdict: v.verdict,
      confidence: Math.max(0.05, Math.min(0.95, Number(v.confidence) || 0.5)),
      rationale: v.rationale ?? "",
    }));
  } catch {
    return [];
  }
}

/** Refine a set of alerts with the user's own LLM. Throws on provider error. */
export async function refineWithLlm(alerts: Alert[], provider: LlmProvider): Promise<LlmRefinement[]> {
  if (alerts.length === 0) return [];
  const prompt = buildUserPrompt(alerts);
  const text = provider.name === "anthropic" ? await callAnthropic(provider.model, prompt) : await callOpenAI(provider.model, prompt);
  return parseRefinements(text);
}
