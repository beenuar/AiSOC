import { AiChatCompliancePanel } from "@/components/ai-estate/AiChatCompliancePanel";
import AiEstateView from "@/components/ai-estate/AiEstateView";

export const metadata = {
  title: "AI estate",
  description: "Observed AI apps, coding agents, MCP servers, provider keys and OAuth grants",
};

export default function AiEstatePage() {
  return (
    <div className="space-y-6">
      <AiEstateView />
      <AiChatCompliancePanel />
    </div>
  );
}
