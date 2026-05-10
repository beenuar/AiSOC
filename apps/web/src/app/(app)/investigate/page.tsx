"use client";

/**
 * /investigate page  — tabbed view: Chat | Timeline
 *
 * Author: Beenu <beenu@cyble.com>
 */

import dynamic from "next/dynamic";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

const InvestigationChat = dynamic(
  () => import("@/components/copilot/InvestigationChat"),
  { ssr: false },
);

const InvestigationTimeline = dynamic(
  () => import("@/components/copilot/InvestigationTimeline"),
  { ssr: false },
);

type Tab = "chat" | "timeline";

function InvestigatePageInner() {
  const searchParams = useSearchParams();
  const runId = searchParams.get("runId") ?? undefined;
  const [activeTab, setActiveTab] = useState<Tab>("chat");

  return (
    <div className="flex h-full flex-col bg-slate-950 text-slate-100">
      {/* Tab bar */}
      <div className="flex border-b border-slate-800 bg-slate-900">
        {(["chat", "timeline"] as Tab[]).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-5 py-2.5 text-sm font-medium capitalize transition-colors
              ${activeTab === tab
                ? "border-b-2 border-indigo-500 text-indigo-300"
                : "text-slate-400 hover:text-slate-200"}`}
          >
            {tab === "chat" ? "💬 Chat" : "🕐 Timeline"}
          </button>
        ))}
        {runId && (
          <span className="ml-auto flex items-center pr-4 text-xs text-slate-500">
            run: {runId.slice(0, 8)}…
          </span>
        )}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "chat" && <InvestigationChat runId={runId} />}
        {activeTab === "timeline" && (
          <div className="h-full overflow-y-auto p-4">
            <InvestigationTimeline runId={runId} />
          </div>
        )}
      </div>
    </div>
  );
}

export default function InvestigatePage() {
  return (
    <Suspense
      fallback={
        <div className="flex h-full items-center justify-center text-slate-400">
          Loading…
        </div>
      }
    >
      <InvestigatePageInner />
    </Suspense>
  );
}
