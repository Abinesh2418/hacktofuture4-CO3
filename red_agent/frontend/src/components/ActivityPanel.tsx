import { useState, type CSSProperties } from "react";
import type { ToolCall } from "@/types/red.types";
import { ToolCard } from "./ToolCard";

interface ActivityPanelProps {
  toolCalls: ToolCall[];
  onClear?: () => void;
}
type Filter = "all" | "RUNNING" | "DONE" | "FAILED";

export function ActivityPanel({ toolCalls, onClear }: ActivityPanelProps) {
  const [filter, setFilter] = useState<Filter>("all");
  const filtered = filter === "all" ? toolCalls : toolCalls.filter((t) => t.status === filter);
  const recent = [...filtered].reverse();

  return (
    <div style={container}>
      <div style={header}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ color: "var(--yellow)", fontSize: 13 }}>&#9881;</span>
          <span style={title}>TOOLS</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-ui)" }}>
            {toolCalls.length}
          </span>
          {toolCalls.length > 0 && onClear && (
            <button onClick={onClear} style={clearBtn}>CLEAR</button>
          )}
        </div>
      </div>

      <div style={filterRow}>
        {(["all", "RUNNING", "DONE", "FAILED"] as Filter[]).map((f) => (
          <button key={f} onClick={() => setFilter(f)} style={{
            ...filterBtn,
            color: filter === f ? "var(--accent)" : "var(--text-dim)",
            background: filter === f ? "var(--accent-dim)" : "transparent",
          }}>
            {f === "all" ? "ALL" : f}
          </button>
        ))}
      </div>

      <div style={list}>
        {recent.length === 0 ? (
          <div style={{ textAlign: "center", paddingTop: 30, fontSize: 10, color: "var(--text-dim)" }}>
            No tools {filter === "all" ? "executed yet" : `with status ${filter}`}
          </div>
        ) : (
          <div style={grid}>
            {recent.map((c) => <ToolCard key={c.id} tool={c} />)}
          </div>
        )}
      </div>
    </div>
  );
}

const container: CSSProperties = {
  display: "flex", flexDirection: "column", height: "100%",
  background: "var(--bg-primary)", borderRadius: "var(--radius)",
  border: "1px solid var(--accent-border)", overflow: "hidden",
};
const header: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "10px 12px", borderBottom: "1px solid var(--accent-border)",
  background: "var(--bg-secondary)",
};
const title: CSSProperties = {
  fontSize: 11, fontWeight: 700, letterSpacing: 2,
  fontFamily: "var(--font-display)", color: "var(--text-primary)",
};
const filterRow: CSSProperties = {
  display: "flex", gap: 2, padding: "6px 8px",
  borderBottom: "1px solid var(--accent-dim)",
};
const filterBtn: CSSProperties = {
  fontSize: 9, fontWeight: 700, fontFamily: "var(--font-display)",
  padding: "3px 8px", borderRadius: 3, border: "none",
  cursor: "pointer", letterSpacing: 0.5, transition: "all var(--transition)",
};
const clearBtn: CSSProperties = {
  fontSize: 8, fontWeight: 700, fontFamily: "var(--font-display)",
  padding: "2px 8px", borderRadius: 3, border: "1px solid var(--red)",
  background: "transparent", color: "var(--red)", cursor: "pointer",
  letterSpacing: 1,
};
const list: CSSProperties = {
  flex: 1, overflowY: "auto", padding: 8,
};
const grid: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
  gap: 6,
  alignItems: "start",
};
