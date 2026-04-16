import { useMemo, type CSSProperties } from "react";
import type { ToolCall } from "@/types/red.types";
import { ToolCard } from "./ToolCard";

const RECON_TOOLS = new Set([
  "nmap_scan",
  "httpx_probe",
  "gobuster_scan",
  "nuclei_scan",
  "katana_crawl",
  "dirsearch_scan",
  "sqlmap_detect",
]);

interface Props {
  toolCalls: ToolCall[];
  sqliDetected: boolean;
}

export function ReconAgentBox({ toolCalls, sqliDetected }: Props) {
  // Dedupe by tool name — keep the most recent call for each tool so the
  // box never grows beyond one card per tool, even if the agent re-runs.
  const dedupedRecon = useMemo(() => {
    const latest = new Map<string, ToolCall>();
    for (const c of toolCalls) {
      if (!RECON_TOOLS.has(c.name)) continue;
      const prev = latest.get(c.name);
      if (!prev || new Date(c.started_at) >= new Date(prev.started_at)) {
        latest.set(c.name, c);
      }
    }
    return Array.from(latest.values()).sort(
      (a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime(),
    );
  }, [toolCalls]);

  const running = dedupedRecon.some((c) => c.status === "RUNNING");
  const accent = sqliDetected ? "var(--red)" : "var(--accent)";

  return (
    <div style={containerOf(sqliDetected)}>
      <div style={headerOf(sqliDetected)}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{
            fontSize: 14,
            color: accent,
            textShadow: sqliDetected ? "0 0 12px var(--red)" : "0 0 8px var(--accent-glow)",
          }}>
            {sqliDetected ? "\u26A0" : "\u25C9"}
          </span>
          <span style={{ ...title, color: accent }}>RECON AGENT</span>
          {running && (
            <span className="anim-pulse" style={statusPill("var(--yellow)")}>
              SCANNING
            </span>
          )}
        </div>
        <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-ui)" }}>
          {dedupedRecon.length} tool{dedupedRecon.length === 1 ? "" : "s"}
        </span>
      </div>

      {sqliDetected && (
        <div className="anim-pulse" style={alertBanner}>
          <span style={{ fontSize: 14 }}>{"\uD83D\uDEA8"}</span>
          <span>SQL INJECTION CONFIRMED — handing off to Exploit Agent</span>
        </div>
      )}

      <div style={list}>
        {dedupedRecon.length === 0 ? (
          <div style={emptyState}>
            recon agent idle — launch a mission to begin<span className="anim-pulse">_</span>
          </div>
        ) : (
          <div style={grid}>
            {dedupedRecon.map((c) => (
              <ToolCard key={c.name} tool={c} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

const containerOf = (alert: boolean): CSSProperties => ({
  display: "flex",
  flexDirection: "column",
  height: "100%",
  background: "var(--bg-primary)",
  borderRadius: "var(--radius)",
  border: `1px solid ${alert ? "var(--red)" : "var(--accent-border)"}`,
  boxShadow: alert ? "0 0 18px rgba(255, 60, 60, 0.25)" : "none",
  overflow: "hidden",
  transition: "border-color var(--transition), box-shadow var(--transition)",
});

const headerOf = (alert: boolean): CSSProperties => ({
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  padding: "10px 12px",
  borderBottom: `1px solid ${alert ? "var(--red)" : "var(--accent-border)"}`,
  background: "var(--bg-secondary)",
});

const title: CSSProperties = {
  fontSize: 12,
  fontWeight: 800,
  letterSpacing: 3,
  fontFamily: "var(--font-display)",
};

const statusPill = (color: string): CSSProperties => ({
  fontSize: 9,
  fontWeight: 700,
  color,
  border: `1px solid ${color}`,
  borderRadius: 3,
  padding: "1px 6px",
  fontFamily: "var(--font-display)",
  letterSpacing: 1,
});

const alertBanner: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 8,
  padding: "6px 12px",
  background: "rgba(255, 60, 60, 0.1)",
  borderBottom: "1px solid var(--red)",
  color: "var(--red)",
  fontSize: 10,
  fontWeight: 700,
  letterSpacing: 1,
  fontFamily: "var(--font-display)",
};

const list: CSSProperties = {
  flex: 1,
  overflowY: "auto",
  padding: 8,
};

const grid: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
  gap: 6,
  alignItems: "start",
};

const emptyState: CSSProperties = {
  textAlign: "center",
  paddingTop: 30,
  fontSize: 10,
  color: "var(--text-dim)",
  fontFamily: "var(--font-mono)",
};
