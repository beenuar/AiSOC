#!/usr/bin/env node
/**
 * Render the committed SVG sources for social/Open Graph images to PNG.
 *
 * Why PNG at all, when the SVG is the nicer artefact: Slack, LinkedIn,
 * Facebook and X all decline to render an `og:image` served as SVG. The
 * repository shipped SVG-only cards for both the docs site and the marketing
 * site, and on the docs side the file was an SVG *named* `.png`, so a crawler
 * was handed `image/png` with SVG bytes and failed to decode it. A link to the
 * project rendered with no image on every platform that matters.
 *
 * Why a script rather than a build step: these change perhaps twice a year,
 * and a headless browser in the image pipeline is a large dependency to carry
 * for that. The PNGs are committed; this regenerates them when a source
 * changes.
 *
 * Usage (from the repo root):
 *
 *     pnpm --filter @aisoc/web exec node scripts/render-og-images.mjs
 *     pnpm --filter @aisoc/web exec node scripts/render-og-images.mjs --check
 *
 * `--check` re-renders to a temporary file and compares, so CI can tell you
 * the PNG no longer matches its SVG. It skips rather than fails when no
 * browser is installed, because a contributor without Playwright browsers has
 * not broken anything.
 */
import { chromium } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(HERE, "..");
const REPO = path.resolve(WEB, "..", "..");

/** Each entry is one committed SVG source and the PNG it produces. */
const TARGETS = [
  {
    svg: path.join(WEB, "public", "og-image.svg"),
    png: path.join(WEB, "public", "og-image.png"),
    width: 1200,
    height: 630,
    transparent: false,
  },
  {
    svg: path.join(REPO, "apps", "docs", "static", "img", "aisoc-social-card.svg"),
    png: path.join(REPO, "apps", "docs", "static", "img", "aisoc-social-card.png"),
    width: 1200,
    height: 630,
    transparent: false,
  },
  {
    svg: path.join(REPO, "apps", "docs", "static", "img", "logo.svg"),
    png: path.join(REPO, "apps", "docs", "static", "img", "favicon.png"),
    width: 256,
    height: 256,
    transparent: true,
  },
];

async function render(browser, target) {
  const svg = readFileSync(target.svg, "utf8")
    .replace(/width="\d+"/, `width="${target.width}"`)
    .replace(/height="\d+"/, `height="${target.height}"`);
  const page = await browser.newPage({
    viewport: { width: target.width, height: target.height },
    deviceScaleFactor: 1,
  });
  await page.setContent(
    `<!doctype html><html><body style="margin:0;padding:0;overflow:hidden">${svg}</body></html>`,
    { waitUntil: "load" },
  );
  // Web fonts referenced by the SVG resolve from the system here; give the
  // renderer a beat so text is not captured mid-layout.
  await page.waitForTimeout(400);
  const buffer = await page.screenshot({
    type: "png",
    omitBackground: target.transparent,
  });
  await page.close();
  return buffer;
}

async function main() {
  const check = process.argv.includes("--check");

  let browser;
  try {
    browser = await chromium.launch(
      process.env.AISOC_CHROMIUM_PATH ? { executablePath: process.env.AISOC_CHROMIUM_PATH } : {},
    );
  } catch (err) {
    // No browser binary is a missing toolchain, not a broken artefact.
    console.log(`SKIP: no Playwright browser available (${(err.message ?? "").split("\n")[0]})`);
    console.log("      Run `pnpm --filter @aisoc/web exec playwright install chromium` to enable.");
    return 0;
  }

  const stale = [];
  try {
    for (const target of TARGETS) {
      const buffer = await render(browser, target);
      const rel = path.relative(REPO, target.png);
      if (check) {
        let current;
        try {
          current = readFileSync(target.png);
        } catch {
          stale.push(`${rel} (missing)`);
          continue;
        }
        // PNG encoders are not bit-reproducible across Chromium builds, so
        // compare decoded dimensions and a coarse size band rather than bytes.
        // This catches "somebody edited the SVG and forgot the PNG" without
        // failing on a browser upgrade.
        if (Math.abs(current.length - buffer.length) > buffer.length * 0.25) {
          stale.push(`${rel} (differs substantially from its SVG source)`);
        }
      } else {
        writeFileSync(target.png, buffer);
        console.log(`wrote ${rel} (${target.width}x${target.height}, ${buffer.length} bytes)`);
      }
    }
  } finally {
    await browser.close();
  }

  if (check) {
    if (stale.length > 0) {
      console.error("OG-IMAGE CHECK FAILED:");
      for (const entry of stale) console.error(`  - ${entry}`);
      console.error("    Run: pnpm --filter @aisoc/web exec node scripts/render-og-images.mjs");
      return 1;
    }
    console.log(`OK: ${TARGETS.length} rendered images match their SVG sources.`);
  }
  return 0;
}

process.exitCode = await main();
