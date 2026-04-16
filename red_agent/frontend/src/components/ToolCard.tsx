import { useState } from "react";
import type { ToolCall, ToolStatus } from "@/types/red.types";

interface ToolCardProps { tool: ToolCall; }

const STATUS: Record<ToolStatus, { color: string; bg: string; icon: string }> = {
  DONE:    { color: "var(--green)",  bg: "var(--green-dim)",  icon: "\u2713" },
  RUNNING: { color: "var(--yellow)", bg: "var(--yellow-dim)", icon: "\u25B6" },
  PENDING: { color: "var(--text-dim)", bg: "transparent",     icon: "\u25CB" },
  FAILED:  { color: "var(--red)",    bg: "var(--red-dim)",    icon: "\u2717" },
};

function elapsed(started: string, finished: string | null): string {
  const sec = Math.floor(((finished ? new Date(finished).getTime() : Date.now()) - new Date(started).getTime()) / 1000);
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m${sec % 60}s`;
}

export function ToolCard({ tool }: ToolCardProps) {
  const [open, setOpen] = useState(false);
  const s = STATUS[tool.status] ?? STATUS.PENDING;
  const isRunning = tool.status === "RUNNING";
  const result = tool.result as Record<string, unknown> | null;
  const findings = (result?.findings ?? []) as Record<string, unknown>[];

  return (
    <div
      className={isRunning ? "anim-border-glow" : "anim-slide-up"}
      onClick={() => setOpen(!open)}
      style={{
        background: "var(--bg-secondary)", borderRadius: "var(--radius)",
        padding: "8px 10px", border: "1px solid var(--accent-border)",
        borderLeft: `3px solid ${s.color}`, cursor: "pointer",
        transition: "all var(--transition)",
      }}
    >
      {/* Header row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span className={isRunning ? "anim-pulse" : ""} style={{ color: s.color, fontSize: 11 }}>{s.icon}</span>
          <div>
            <span style={{ fontSize: 11, fontWeight: 700, fontFamily: "var(--font-ui)", letterSpacing: 0.5 }}>
              {tool.name}
            </span>
            {typeof tool.params?.agent === "string" && (
              <span style={{ fontSize: 8, color: "var(--accent)", marginLeft: 6, fontFamily: "var(--font-ui)" }}>
                {tool.params.agent}
              </span>
            )}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 9, color: "var(--text-dim)" }}>{elapsed(tool.started_at, tool.finished_at)}</span>
          <span style={{
            fontSize: 8, fontWeight: 700, padding: "2px 6px", borderRadius: 3,
            background: s.bg, color: s.color, letterSpacing: 0.5,
            fontFamily: "var(--font-display)",
          }}>
            {tool.status}
          </span>
        </div>
      </div>

      {/* Running shimmer */}
      {isRunning && (
        <div style={{ marginTop: 6, height: 2, borderRadius: 1, overflow: "hidden" }}>
          <div className="shimmer-bar" style={{ height: "100%", borderRadius: 1 }} />
        </div>
      )}

      {/* Quick summary (always visible when done) */}
      {!isRunning && result && (
        <div style={{ marginTop: 6, fontSize: 10, color: "var(--text-secondary)" }}>
          {findings.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              {findings.slice(0, 3).map((f, i) => {
                const port = f.port as number | undefined;
                const service = f.service as string | undefined;
                const state = f.state as string | undefined;
                const host = f.host as string | undefined;
                const name = f.name as string | undefined;
                const severity = f.severity as string | undefined;
                const url = f.url as string | undefined;
                const path = f.path as string | undefined;

                if (port && service) {
                  return (
                    <span key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 9 }}>
                      <span style={{ color: state === "open" ? "var(--green)" : "var(--red)" }}>
                        {state === "open" ? "\u25CF" : "\u25CB"}
                      </span>
                      {" "}port {port}/{service}
                      {host ? ` (${host})` : ""}
                      {state ? ` [${state}]` : ""}
                    </span>
                  );
                }
                if (name || severity) {
                  return (
                    <span key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 9 }}>
                      <span style={{
                        color: severity === "critical" ? "var(--red)" :
                               severity === "high" ? "var(--orange)" :
                               severity === "medium" ? "var(--yellow)" : "var(--text-dim)"
                      }}>
                        [{severity || "info"}]
                      </span>
                      {" "}{name || JSON.stringify(f).slice(0, 60)}
                    </span>
                  );
                }
                if (url || path) {
                  return (
                    <span key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--cyan)" }}>
                      {url || path}
                    </span>
                  );
                }
                return (
                  <span key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 9 }}>
                    {JSON.stringify(f).slice(0, 80)}
                  </span>
                );
              })}
              {findings.length > 3 && (
                <span style={{ fontSize: 8, color: "var(--text-dim)" }}>
                  +{findings.length - 3} more — click to expand
                </span>
              )}
            </div>
          ) : (
            <span style={{ fontSize: 9, color: "var(--text-dim)" }}>
              {result.error ? `Error: ${String(result.error).slice(0, 80)}` :
               result.raw_output ? String(result.raw_output).slice(0, 80) :
               `${result.findings_count || 0} findings`}
            </span>
          )}
        </div>
      )}

      {/* Full result (expanded) */}
      {open && result && (
        <pre style={{
          fontSize: 9, color: "var(--green)", marginTop: 6, padding: "6px 8px",
          background: "var(--bg-void)", borderRadius: 4, whiteSpace: "pre-wrap",
          wordBreak: "break-word", maxHeight: 200, overflowY: "auto",
          border: "1px solid var(--green-dim)",
        }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  );
}
