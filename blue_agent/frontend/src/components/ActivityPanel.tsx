import type { ToolCall } from "@/types/blue.types";
import { ToolCard } from "./ToolCard";

interface ActivityPanelProps {
  toolCalls: ToolCall[];
  limit?: number;
  accent?: string;
}

export function ActivityPanel({
  toolCalls,
  limit = 10,
  accent = "#58a6ff",
}: ActivityPanelProps) {
  const recent = [...toolCalls].slice(-limit).reverse();

  return (
    <section
      style={{
        background: "#0d1117",
        borderRadius: 8,
        padding: 12,
        border: `1px solid ${accent}55`,
        minHeight: 0,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: 10,
          paddingBottom: 8,
          borderBottom: `1px solid ${accent}33`,
          flexShrink: 0,
        }}
      >
        <h3 style={{ margin: 0, color: accent, fontSize: 14, letterSpacing: 1 }}>
          CURRENT ACTIVITY
        </h3>
        <span style={{ color: "#8b949e", fontSize: 12 }}>
          {recent.length} tool calls
        </span>
      </header>
      <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
        {recent.length === 0 ? (
          <p style={{ color: "#8b949e", fontSize: 12 }}>No activity yet.</p>
        ) : (
          recent.map((call) => <ToolCard key={call.id} tool={call} accent={accent} />)
        )}
      </div>
    </section>
  );
}
