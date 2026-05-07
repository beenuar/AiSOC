import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: "category",
      label: "Getting Started",
      items: ["intro", "quickstart", "architecture", "benchmark"],
    },
    {
      type: "category",
      label: "Core Concepts",
      items: ["concepts/cases", "concepts/playbooks", "concepts/detections"],
    },
    {
      type: "category",
      label: "Connectors",
      items: [
        "connectors/index",
        "connectors/azure-entra",
        "connectors/azure-activity",
        "connectors/azure-defender",
        "connectors/gcp-cloud-audit",
        "connectors/gcp-scc",
        "connectors/m365-audit",
        "connectors/google-workspace",
        "connectors/cloudflare",
        "connectors/github",
        "connectors/tailscale",
      ],
    },
    {
      type: "category",
      label: "Operations",
      items: ["operations/credentials", "operations/airgap"],
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
      label: "Integrations",
      items: ["integrations/mcp"],
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
