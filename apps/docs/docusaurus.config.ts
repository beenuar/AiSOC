import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

// Two deploy targets share this build:
//   1. GitHub Pages (default): https://beenuar.github.io/AiSOC/
//   2. Custom domain          : https://docs.tryaisoc.com/  (served behind cloudflared tunnel)
//
// Override at build time with:
//   DOCS_URL=https://docs.tryaisoc.com DOCS_BASE_URL=/ pnpm --filter @aisoc/docs build
const DOCS_URL = process.env.DOCS_URL || "https://beenuar.github.io";
const DOCS_BASE_URL = process.env.DOCS_BASE_URL || "/AiSOC/";

const SITE_DESCRIPTION =
  "AiSOC is an open-source, self-hostable AI Security Operations Center: alert fusion, agent-assisted triage, MITRE ATT&CK investigation, and a replayable decision ledger. MIT licensed.";

/** Absolute URL for an asset under `static/`, for tags that require one. */
const absoluteUrl = (assetPath: string): string =>
  `${DOCS_URL}${DOCS_BASE_URL}${assetPath.replace(/^\//, "")}`;

const config: Config = {
  title: "AiSOC",
  tagline:
    "Open-source AI SOC platform. Agent decisions are recorded in an investigation ledger and a public eval harness runs in CI. MIT-licensed and self-hostable.",
  // Was `img/favicon.ico`, which held SVG bytes — a browser asking for an ICO
  // got a document it could not decode. The PNG is rendered from `logo.svg`
  // by `apps/web/scripts/render-og-images.mjs`.
  favicon: "img/favicon.png",

  url: DOCS_URL,
  baseUrl: DOCS_BASE_URL,

  organizationName: "beenuar",
  projectName: "AiSOC",

  headTags: [
    {
      tagName: "meta",
      attributes: {
        name: "keywords",
        // Terms a practitioner would search. Deliberately excludes any
        // commercial hostname: this is the open-source project's site, and
        // a self-hoster's copy of these docs must not carry SEO for a
        // hosted offering. Also excludes competitor product names.
        content:
          "AiSOC, AI SOC, open source SOC, autonomous SOC, MITRE ATT&CK, Sigma rules, purple team, alert fusion, alert triage automation, detection engineering, detection as code, SOAR, security automation, self-hosted SOC, threat hunting, incident response, OCSF, MCP server, LangGraph, SOC automation",
      },
    },
    // Only tags Docusaurus does not already emit itself. It sets og:image,
    // og:url, og:title, og:description, og:locale, twitter:card and
    // twitter:image from `themeConfig.image` and the page metadata, and a
    // second copy of any of those is a conflicting duplicate rather than a
    // reinforcement.
    { tagName: "meta", attributes: { property: "og:site_name", content: "AiSOC Docs" } },
    { tagName: "meta", attributes: { property: "og:type", content: "website" } },
    // Crawlers that size a card from the declared dimensions fall back to a
    // small summary card when these are absent.
    { tagName: "meta", attributes: { property: "og:image:width", content: "1200" } },
    { tagName: "meta", attributes: { property: "og:image:height", content: "630" } },
    {
      tagName: "meta",
      attributes: {
        property: "og:image:alt",
        content: "AiSOC — open-source AI Security Operations Center",
      },
    },
    // Points automated readers at the machine-first index. Generated and
    // gated by `scripts/generate_llms_txt.py`.
    {
      tagName: "link",
      attributes: {
        rel: "alternate",
        type: "text/plain",
        href: absoluteUrl("llms.txt"),
        title: "llms.txt — machine-readable project summary",
      },
    },
  ],

  plugins: [
    /**
     * schema.org markup for the docs site.
     *
     * `headTags` above carries attributes only, and JSON-LD needs a script
     * body, so it goes through the plugin `injectHtmlTags` hook instead.
     *
     * Every assertion here has to be independently true, because structured
     * data is consumed without a human in the loop: the licence is MIT, the
     * price is genuinely zero because the whole platform is self-hostable
     * under that licence, and there is no `aggregateRating` or `review`
     * because no such data exists and inventing one would be fabrication
     * rather than markup.
     */
    function structuredDataPlugin() {
      return {
        name: "aisoc-structured-data",
        injectHtmlTags() {
          const jsonLd = {
            "@context": "https://schema.org",
            "@graph": [
              {
                "@type": "SoftwareApplication",
                name: "AiSOC",
                alternateName: ["AI SOC", "Open Source SOC"],
                applicationCategory: "SecurityApplication",
                applicationSubCategory: "Security Operations Center",
                operatingSystem: "Linux, macOS, Docker",
                description: SITE_DESCRIPTION,
                license: "https://opensource.org/licenses/MIT",
                isAccessibleForFree: true,
                offers: {
                  "@type": "Offer",
                  price: "0",
                  priceCurrency: "USD",
                  description: "Free and open source under the MIT licence; self-hostable.",
                },
                url: `${DOCS_URL}${DOCS_BASE_URL}`,
                downloadUrl: "https://github.com/beenuar/AiSOC",
                codeRepository: "https://github.com/beenuar/AiSOC",
                installUrl: `${DOCS_URL}${DOCS_BASE_URL}docs/quickstart`,
                releaseNotes: "https://github.com/beenuar/AiSOC/releases",
                image: absoluteUrl("img/aisoc-social-card.png"),
                author: {
                  "@type": "Organization",
                  name: "AiSOC contributors",
                  url: "https://github.com/beenuar/AiSOC",
                },
              },
              {
                "@type": "WebSite",
                name: "AiSOC Documentation",
                url: `${DOCS_URL}${DOCS_BASE_URL}`,
                description: SITE_DESCRIPTION,
                inLanguage: "en",
                license: "https://opensource.org/licenses/MIT",
              },
            ],
          };
          return {
            headTags: [
              {
                tagName: "script",
                attributes: { type: "application/ld+json" },
                innerHTML: JSON.stringify(jsonLd),
              },
            ],
          };
        },
      };
    },
  ],

  onBrokenLinks: "throw",

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  markdown: {
    hooks: {
      onBrokenMarkdownLinks: "warn",
    },
  },

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          editUrl: "https://github.com/beenuar/AiSOC/tree/main/apps/docs/",
        },
        // No blog is published on the documentation site. Long-form writing
        // lives on the project website instead.
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: "img/aisoc-social-card.png",
    navbar: {
      title: "AiSOC",
      logo: {
        alt: "AiSOC Logo",
        src: "img/logo.svg",
      },
      items: [
        {
          type: "docSidebar",
          sidebarId: "docsSidebar",
          position: "left",
          label: "Docs",
        },
        {
          href: "https://github.com/beenuar/AiSOC",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            { label: "Getting Started", to: "/docs/intro" },
            { label: "Plugin SDK (Python)", to: "/docs/plugins/python-sdk" },
            { label: "Plugin SDK (Go)", to: "/docs/plugins/go-sdk" },
          ],
        },
        {
          title: "Community",
          items: [
            {
              label: "GitHub Discussions",
              href: "https://github.com/beenuar/AiSOC/discussions",
            },
            {
              label: "Issues",
              href: "https://github.com/beenuar/AiSOC/issues",
            },
            {
              label: "GitHub",
              href: "https://github.com/beenuar/AiSOC",
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} AiSOC Contributors. MIT License.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["python", "go", "bash", "yaml", "json"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
