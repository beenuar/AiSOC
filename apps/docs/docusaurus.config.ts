import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

const config: Config = {
  title: "AiSOC",
  tagline:
    "The auditable AI SOC — every agent decision logged, replayable, and benchmarked publicly. MIT-licensed, self-hostable.",
  favicon: "img/favicon.ico",

  url: "https://beenuar.github.io",
  baseUrl: "/AiSOC/",

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
