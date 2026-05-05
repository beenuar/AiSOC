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

const config: Config = {
  title: "AiSOC",
  tagline:
    "Open-source AI SOC platform. Agent decisions are recorded in an investigation ledger and a public eval harness runs in CI. MIT-licensed and self-hostable.",
  favicon: "img/favicon.ico",

  url: DOCS_URL,
  baseUrl: DOCS_BASE_URL,

  organizationName: "beenuar",
  projectName: "AiSOC",

  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          editUrl: "https://github.com/beenuar/AiSOC/tree/main/apps/docs/",
        },
        blog: {
          showReadingTime: true,
          editUrl: "https://github.com/beenuar/AiSOC/tree/main/apps/docs/",
        },
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
        { to: "/blog", label: "Blog", position: "left" },
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
          ],
        },
        {
          title: "More",
          items: [
            { label: "Blog", to: "/blog" },
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
