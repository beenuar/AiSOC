import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: "category",
      label: "Getting Started",
      items: ["intro", "quickstart", "architecture"],
    },
    {
      type: "category",
      label: "Core Concepts",
      items: ["concepts/cases", "concepts/playbooks", "concepts/detections"],
    },
    {
      type: "category",
      label: "Plugin SDK",
      items: [
        "plugins/overview",
        "plugins/python-sdk",
        "plugins/go-sdk",
        "plugins/publishing",
      ],
    },
    {
      type: "category",
      label: "API Reference",
      items: ["api/rest", "api/graphql", "api/websocket"],
    },
    {
      type: "category",
      label: "Deployment",
      items: ["deployment/docker", "deployment/kubernetes", "deployment/env-vars"],
    },
    {
      type: "category",
      label: "Contributing",
      items: ["contributing/dev-setup", "contributing/guidelines"],
    },
  ],
};

export default sidebars;
