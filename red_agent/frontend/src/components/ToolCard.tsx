import { useState, type CSSProperties } from "react";
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
          {/* sqlmap gets a cinematic renderer */}
          {tool.name.startsWith("sqlmap") ? (
            <SqlmapSummary findings={findings} toolName={tool.name} />
          ) : findings.length > 0 ? (
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


// ═════════════════════════════════════════════════════════════════════
// Creative sqlmap renderer — DBMS badge, injection banner, db/table
// tree, and a real data-grid for exfiltrated rows.
// ═════════════════════════════════════════════════════════════════════

function SqlmapSummary({ findings, toolName }: { findings: Record<string, unknown>[]; toolName: string }) {
  const dbms = findings.find((f) => f.type === "dbms")?.value as string | undefined;
  const injections = findings.filter((f) => f.type === "injection") as Array<{ param?: string; place?: string }>;
  const dbs = findings.filter((f) => f.type === "database") as Array<{ name?: string }>;
  const tables = findings.filter((f) => f.type === "table") as Array<{ db?: string; name?: string }>;
  const rows = findings.filter((f) => f.type === "row") as Array<{ db?: string; table?: string; cells?: string[] }>;

  // Group rows by table for the data-grid
  const grouped = new Map<string, string[][]>();
  for (const r of rows) {
    const key = `${r.db ?? ""}.${r.table ?? ""}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(r.cells ?? []);
  }

  return (
    <div
      onClick={(e) => e.stopPropagation()}
      style={{ display: "flex", flexDirection: "column", gap: 6, fontFamily: "var(--font-mono)", fontSize: 10 }}
    >
      {/* Top bar: DBMS + injection count */}
      {(dbms || injections.length > 0) && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
          {dbms && (
            <span className="anim-pulse" style={sqlBadge("var(--red)")}>
              {"\u26A0"} DBMS: {dbms}
            </span>
          )}
          {injections.map((inj, i) => (
            <span key={i} style={sqlBadge("var(--orange)")}>
              {"\u25B8"} INJECTED: {inj.param} ({inj.place})
            </span>
          ))}
        </div>
      )}

      {/* Databases discovered */}
      {dbs.length > 0 && (
        <div style={sqlBlock}>
          <div style={sqlBlockTitle}>DATABASES ({dbs.length})</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {dbs.map((d, i) => (
              <span key={i} style={sqlChip}>{"\uD83D\uDDC4"} {d.name}</span>
            ))}
          </div>
        </div>
      )}

      {/* Tables per db */}
      {tables.length > 0 && (
        <div style={sqlBlock}>
          <div style={sqlBlockTitle}>TABLES ({tables.length})</div>
          {Object.entries(groupByDb(tables)).map(([db, ts]) => (
            <div key={db} style={{ marginTop: 3 }}>
              <span style={{ color: "var(--cyan)", fontSize: 9 }}>{db}</span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 3, marginTop: 2 }}>
                {ts.map((t, i) => (
                  <span key={i} style={sqlChip}>{t.name}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Data grids — one per dumped table */}
      {grouped.size > 0 && (
        <div style={sqlBlock}>
          <div style={sqlBlockTitle}>
            EXFILTRATED DATA ({rows.length} row{rows.length === 1 ? "" : "s"})
          </div>
          {Array.from(grouped.entries()).map(([key, cells]) => (
            <DumpGrid key={key} title={key} cells={cells} />
          ))}
        </div>
      )}

      {/* Nothing substantive yet */}
      {!dbms && injections.length === 0 && dbs.length === 0 && tables.length === 0 && rows.length === 0 && (
        <span style={{ fontSize: 9, color: "var(--text-dim)" }}>
          {toolName} finished — no injectable points found
        </span>
      )}
    </div>
  );
}

function DumpGrid({ title, cells }: { title: string; cells: string[][] }) {
  const [hdr, ...rest] = cells;
  const widthCh = (c: string) => Math.min(24, Math.max(6, (c || "").length + 2));
  return (
    <div style={{ marginTop: 4, border: "1px solid var(--red-dim)", borderRadius: 3, overflow: "hidden" }}>
      <div style={{ background: "var(--red-dim)", color: "var(--red)", padding: "2px 6px", fontSize: 9, fontWeight: 700 }}>
        {"\uD83D\uDD13"} {title}
      </div>
      <div style={{ overflowX: "auto" }}>
        <table style={{ borderCollapse: "collapse", fontSize: 9, width: "100%" }}>
          {hdr && (
            <thead>
              <tr style={{ background: "rgba(255,60,60,0.08)" }}>
                {hdr.map((h, i) => (
                  <th key={i} style={{ ...gridCell, color: "var(--red)", fontWeight: 700, width: `${widthCh(h)}ch` }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
          )}
          <tbody>
            {rest.slice(0, 50).map((row, i) => (
              <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.02)" }}>
                {row.map((c, j) => (
                  <td key={j} style={gridCell}>{c}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {rest.length > 50 && (
          <div style={{ padding: "2px 6px", fontSize: 8, color: "var(--text-dim)" }}>
            +{rest.length - 50} more rows (click card header to expand full JSON)
          </div>
        )}
      </div>
    </div>
  );
}

function groupByDb<T extends { db?: string }>(items: T[]): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const it of items) {
    const k = it.db ?? "(unknown)";
    (out[k] ||= []).push(it);
  }
  return out;
}

const sqlBadge = (color: string): CSSProperties => ({
  fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 3,
  background: "rgba(255,60,60,0.12)", color, letterSpacing: 0.5,
  fontFamily: "var(--font-display)", border: `1px solid ${color}`,
});

const sqlBlock: CSSProperties = {
  padding: "4px 6px", background: "var(--bg-void)",
  border: "1px solid var(--accent-border)", borderRadius: 3,
};

const sqlBlockTitle: CSSProperties = {
  fontSize: 8, fontWeight: 700, color: "var(--accent)",
  letterSpacing: 1.5, marginBottom: 3, fontFamily: "var(--font-display)",
};

const sqlChip: CSSProperties = {
  fontSize: 9, padding: "1px 5px", borderRadius: 2,
  background: "rgba(0,255,180,0.06)", color: "var(--green)",
  border: "1px solid var(--green-dim)",
};

const gridCell: CSSProperties = {
  padding: "2px 6px", borderRight: "1px solid var(--accent-border)",
  borderBottom: "1px solid var(--accent-border)", whiteSpace: "nowrap",
  maxWidth: "24ch", overflow: "hidden", textOverflow: "ellipsis",
};
