import { useMemo, useState, type CSSProperties } from "react";
import type { AutoPwnStep, AutoPwnSection, AutoPwnKind, ToolStatus } from "@/types/red.types";

interface AutoPwnPanelProps {
  steps: AutoPwnStep[];
  armed?: boolean;
  onClear?: () => void;
}

const KIND_LABEL: Record<AutoPwnKind, string> = {
  CURL_PROBE: "CURL",
  SQLMAP_DBS: "DBS",
  SQLMAP_TABLES: "TABLES",
  SQLMAP_DUMP: "DUMP",
  SQLMAP_DUMP_ALL: "DUMP-ALL",
};

const STATUS_COLOR: Record<ToolStatus, string> = {
  PENDING: "var(--text-dim)",
  RUNNING: "var(--yellow)",
  DONE: "var(--green)",
  FAILED: "var(--red)",
};

function formatTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function AutoPwnPanel({ steps, armed = false, onClear }: AutoPwnPanelProps) {
  const ordered = [...steps].reverse();
  const running = steps.some((s) => s.status === "RUNNING");
  const showIntro = armed && steps.length === 0;

  return (
    <div style={container}>
      <div style={header}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className={armed ? "anim-pulse" : ""} style={{
            color: "var(--red)", fontSize: 14,
            textShadow: armed ? "0 0 12px var(--red)" : undefined,
          }}>
            &#9889;
          </span>
          <span style={title}>EXPLOIT AGENT</span>
          <span style={subTitle}>DETERMINISTIC LANE</span>
          {(running || armed) && (
            <span className="anim-pulse" style={{
              fontSize: 9, color: armed ? "var(--red)" : "var(--yellow)", marginLeft: 6,
              fontFamily: "var(--font-display)", letterSpacing: 1,
            }}>
              {running ? "ACTIVE" : "ARMED"}
            </span>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-ui)" }}>
            {steps.length} step{steps.length === 1 ? "" : "s"}
          </span>
          {steps.length > 0 && onClear && (
            <button onClick={onClear} style={clearBtn}>CLEAR</button>
          )}
        </div>
      </div>

      {steps.length > 0 && <ExploitStats steps={steps} />}

      <div style={list}>
        {showIntro ? (
          <ExploitIntro />
        ) : ordered.length === 0 ? (
          <div style={emptyState}>
            standing by — waiting for SQLi from recon<span className="anim-pulse">_</span>
          </div>
        ) : (
          ordered.map((s) => <StepCard key={s.id} step={s} />)
        )}
      </div>
    </div>
  );
}

// ── Stats showcase ──────────────────────────────────────────────────────

interface PwnStats {
  databases: number;
  tables: number;
  rows: number;
  credentials: number;
  emails: number;
  done: number;
  failed: number;
  total: number;
  dbms: string | null;
}

const _CRED_PATTERNS = [
  /^\$2[aby]\$/,                    // bcrypt
  /^\$1\$/, /^\$5\$/, /^\$6\$/,     // crypt MD5/SHA
  /^[a-f0-9]{32}$/i,                // raw md5
  /^[a-f0-9]{40}$/i,                // raw sha1
  /^[a-f0-9]{64}$/i,                // raw sha256
  /^pbkdf2[_-]/i,
  /^argon2/i,
  /^scrypt\$/i,
];
const _EMAIL = /^[\w.+-]+@[\w-]+\.[\w.-]+$/;

function looksLikeCred(cell: string): boolean {
  const s = (cell || "").trim();
  if (s.length < 8 || s.length > 200) return false;
  return _CRED_PATTERNS.some((re) => re.test(s));
}

function computeStats(steps: AutoPwnStep[]): PwnStats {
  const stats: PwnStats = {
    databases: 0, tables: 0, rows: 0, credentials: 0, emails: 0,
    done: 0, failed: 0, total: steps.length, dbms: null,
  };
  const dbSet = new Set<string>();

  for (const s of steps) {
    if (s.status === "DONE") stats.done++;
    else if (s.status === "FAILED") stats.failed++;

    if (s.kind === "SQLMAP_DBS") {
      for (const item of s.items || []) dbSet.add(item);
    }
    if (s.kind === "SQLMAP_TABLES") {
      stats.tables += (s.items || []).length;
    }
    if (s.kind === "SQLMAP_DUMP" || s.kind === "SQLMAP_DUMP_ALL") {
      for (const sec of s.sections || []) {
        stats.rows += sec.row_count || 0;
        if (sec.db) dbSet.add(sec.db);
        // Walk rows for credential-shaped + email-shaped cells.
        const [_hdr, ...data] = sec.rows || [];
        for (const row of data) {
          for (const cell of row) {
            if (looksLikeCred(cell)) stats.credentials++;
            else if (_EMAIL.test((cell || "").trim())) stats.emails++;
          }
        }
      }
    }
  }
  stats.databases = dbSet.size;
  return stats;
}

function ExploitStats({ steps }: { steps: AutoPwnStep[] }) {
  const stats = useMemo(() => computeStats(steps), [steps]);
  const tiles: Array<[string, number | string, string, string]> = [
    ["DBs", stats.databases, "var(--cyan)", "databases reached"],
    ["TABLES", stats.tables, "var(--accent)", "tables enumerated"],
    ["ROWS", stats.rows, "var(--green)", "records captured"],
    ["CREDS", stats.credentials, "var(--red)", "credential-shaped cells"],
    ["EMAILS", stats.emails, "var(--yellow)", "email-shaped cells"],
    ["STEPS", `${stats.done}/${stats.total}`, "var(--text-secondary)", "pipeline progress"],
  ];
  if (stats.failed > 0) {
    tiles.push(["FAIL", stats.failed, "var(--red)", "failed steps"]);
  }
  return (
    <div style={statsBar}>
      {tiles.map(([label, value, color, hint]) => (
        <div key={label} style={statTile} title={hint}>
          <span style={{ ...statValue, color }}>{value}</span>
          <span style={statLabel}>{label}</span>
        </div>
      ))}
    </div>
  );
}

const statsBar: CSSProperties = {
  display: "flex", gap: 6, padding: "8px 12px",
  borderBottom: "1px solid var(--red-dim)",
  background: "rgba(255, 60, 60, 0.04)",
  flexWrap: "wrap",
};
const statTile: CSSProperties = {
  display: "flex", flexDirection: "column", alignItems: "center",
  padding: "4px 10px", minWidth: 56,
  border: "1px solid var(--accent-border)", borderRadius: 4,
  background: "var(--bg-void)",
};
const statValue: CSSProperties = {
  fontSize: 16, fontWeight: 800, lineHeight: 1.1,
  fontFamily: "var(--font-display)",
};
const statLabel: CSSProperties = {
  fontSize: 8, color: "var(--text-dim)", letterSpacing: 1.5,
  fontFamily: "var(--font-display)", marginTop: 2,
};

function ExploitIntro() {
  return (
    <div style={introBox}>
      <div className="anim-pulse" style={introIcon}>&#9889;</div>
      <div style={introTitle}>I AM EXPLOITING THIS</div>
      <div style={introSub}>
        sqli confirmed by recon — running:
      </div>
      <div style={introSteps}>
        <div style={introStep}><span style={introBullet}>&rarr;</span>curl probe</div>
        <div style={introStep}><span style={introBullet}>&rarr;</span>sqlmap --dbs</div>
        <div style={introStep}><span style={introBullet}>&rarr;</span>sqlmap --tables</div>
        <div style={introStep}><span style={introBullet}>&rarr;</span>sqlmap --dump (every interesting table)</div>
      </div>
    </div>
  );
}

function StepCard({ step }: { step: AutoPwnStep }) {
  const [open, setOpen] = useState(false);
  const color = STATUS_COLOR[step.status];

  return (
    <div style={card}>
      <div
        style={{ ...cardHead, cursor: "pointer" }}
        onClick={() => setOpen((v) => !v)}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, flex: 1 }}>
          <span style={{
            ...kindBadge,
            color,
            borderColor: color,
          }}>
            {KIND_LABEL[step.kind]}
          </span>
          <span style={{
            fontSize: 11, color: "var(--text-primary)",
            fontFamily: "var(--font-mono)",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>
            {step.summary || step.target}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <span style={{ fontSize: 9, color: "var(--text-dim)" }}>
            {formatTime(step.started_at)}
          </span>
          <span style={{
            fontSize: 9, fontWeight: 700, color,
            fontFamily: "var(--font-display)", letterSpacing: 1,
          }} className={step.status === "RUNNING" ? "anim-pulse" : ""}>
            {step.status}
          </span>
        </div>
      </div>

      {open && (
        <div style={cardBody}>
          <div style={{ marginBottom: 6 }}>
            <span style={metaLabel}>TARGET</span>
            <span style={metaValue}>{step.target}</span>
          </div>
          <div style={{ marginBottom: 6 }}>
            <span style={metaLabel}>CMD</span>
            <code style={cmdBox}>{step.command || "—"}</code>
          </div>

          {step.items.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <span style={metaLabel}>
                {step.kind === "SQLMAP_DBS" ? "DATABASES" : "TABLES"}
              </span>
              <div style={chipRow}>
                {step.items.map((it) => (
                  <span key={it} style={chip}>{it}</span>
                ))}
              </div>
            </div>
          )}

          {step.sections && step.sections.length > 0 ? (
            <div style={{ marginBottom: 6 }}>
              <span style={metaLabel}>
                DUMPS ({step.sections.length} table{step.sections.length === 1 ? "" : "s"})
              </span>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {step.sections.map((sec, i) => (
                  <SectionRow key={`${sec.db}.${sec.table}.${i}`} section={sec} />
                ))}
              </div>
            </div>
          ) : step.rows.length > 0 ? (
            <div style={{ marginBottom: 6 }}>
              <span style={metaLabel}>ROWS ({step.rows.length})</span>
              <div style={rowsBox}>
                {step.rows.slice(0, 50).map((row, i) => (
                  <div key={i} style={rowLine}>
                    {row.map((cell, j) => (
                      <span key={j} style={cellBox}>{cell || "·"}</span>
                    ))}
                  </div>
                ))}
                {step.rows.length > 50 && (
                  <div style={{ ...rowLine, color: "var(--text-dim)" }}>
                    … {step.rows.length - 50} more rows in raw output
                  </div>
                )}
              </div>
            </div>
          ) : null}

          {step.error && (
            <div style={{ marginBottom: 6 }}>
              <span style={metaLabel}>ERROR</span>
              <code style={{ ...cmdBox, color: "var(--red)" }}>{step.error}</code>
            </div>
          )}

          {step.raw_tail && (
            <details style={{ marginTop: 4 }}>
              <summary style={{
                fontSize: 9, color: "var(--text-dim)", cursor: "pointer",
                letterSpacing: 1, fontFamily: "var(--font-display)",
              }}>
                RAW OUTPUT
              </summary>
              <pre style={rawBox}>{step.raw_tail}</pre>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

const introBox: CSSProperties = {
  display: "flex", flexDirection: "column", alignItems: "center",
  gap: 8, padding: "24px 16px", border: "1px dashed var(--red)",
  borderRadius: 6, background: "rgba(255, 60, 60, 0.05)",
};
const introIcon: CSSProperties = {
  fontSize: 32, color: "var(--red)",
  textShadow: "0 0 18px var(--red)",
};
const introTitle: CSSProperties = {
  fontSize: 14, fontWeight: 800, letterSpacing: 3,
  color: "var(--red)", fontFamily: "var(--font-display)",
};
const introSub: CSSProperties = {
  fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-ui)",
  letterSpacing: 0.5,
};
const introSteps: CSSProperties = {
  display: "flex", flexDirection: "column", gap: 4, marginTop: 6,
};
const introStep: CSSProperties = {
  display: "flex", alignItems: "center", gap: 6,
  fontSize: 11, color: "var(--text-secondary)", fontFamily: "var(--font-mono)",
};
const introBullet: CSSProperties = {
  color: "var(--red)", fontWeight: 800,
};

function SectionRow({ section }: { section: AutoPwnSection }) {
  const label = section.dump_all ? `${section.db}.*` : `${section.db}.${section.table}`;
  const empty = section.row_count === 0;
  const color = section.error ? "var(--red)" : empty ? "var(--text-dim)" : "var(--green)";
  // sqlmap dumps put column names as the first row.
  const [hdr, ...dataRows] = section.rows;
  const showHeader = !!hdr && hdr.length > 0;
  const ROW_CAP = 100;

  return (
    <div style={sectionBox}>
      <div style={sectionHead}>
        <span style={{
          fontSize: 11, fontFamily: "var(--font-mono)",
          color: section.error ? "var(--red)" : "var(--cyan)", fontWeight: 700,
        }}>
          {section.error ? "\u2717" : "\u26A1"} {label}
        </span>
        <span style={{
          fontSize: 9, fontWeight: 700, color, letterSpacing: 1,
          fontFamily: "var(--font-display)",
        }}>
          {section.error ? "ERR" : `${section.row_count} rows extracted`}
        </span>
      </div>

      {section.error && (
        <div style={{ padding: "4px 8px", fontSize: 9, color: "var(--red)", fontFamily: "var(--font-mono)" }}>
          {section.error}
        </div>
      )}

      {section.rows.length > 0 && (
        <div style={tableScroll}>
          <table style={dumpTable}>
            {showHeader && (
              <thead>
                <tr>
                  {hdr.map((h, i) => (
                    <th key={i} style={dumpTh}>{h || "—"}</th>
                  ))}
                </tr>
              </thead>
            )}
            <tbody>
              {dataRows.slice(0, ROW_CAP).map((row, i) => (
                <tr key={i} style={i % 2 === 0 ? dumpTr : dumpTrAlt}>
                  {row.map((cell, j) => (
                    <td key={j} style={dumpTd} title={cell}>{cell || "·"}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {dataRows.length > ROW_CAP && (
            <div style={{
              padding: "4px 8px", fontSize: 9, color: "var(--text-dim)",
              fontFamily: "var(--font-mono)", borderTop: "1px solid var(--accent-dim)",
            }}>
              + {dataRows.length - ROW_CAP} more rows (full set in raw output)
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const sectionBox: CSSProperties = {
  border: "1px solid var(--red-dim)", borderRadius: 4,
  background: "var(--bg-void)", overflow: "hidden",
};
const sectionHead: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "6px 10px", background: "var(--bg-secondary)",
  borderBottom: "1px solid var(--red-dim)",
};
const tableScroll: CSSProperties = {
  maxHeight: 320, overflow: "auto",
};
const dumpTable: CSSProperties = {
  width: "100%", borderCollapse: "collapse",
  fontFamily: "var(--font-mono)", fontSize: 10,
};
const dumpTh: CSSProperties = {
  padding: "4px 8px", textAlign: "left",
  background: "rgba(255,60,60,0.12)", color: "var(--red)",
  fontWeight: 700, letterSpacing: 0.5, position: "sticky", top: 0,
  borderBottom: "1px solid var(--red)", whiteSpace: "nowrap",
};
const dumpTr: CSSProperties = { background: "transparent" };
const dumpTrAlt: CSSProperties = { background: "rgba(255,255,255,0.025)" };
const dumpTd: CSSProperties = {
  padding: "3px 8px", color: "var(--green)",
  borderBottom: "1px solid var(--accent-dim)",
  borderRight: "1px solid var(--accent-dim)",
  maxWidth: "32ch", overflow: "hidden", textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

const container: CSSProperties = {
  display: "flex", flexDirection: "column", height: "100%",
  background: "var(--bg-primary)", borderRadius: "var(--radius)",
  border: "1px solid var(--red)",
  boxShadow: "0 0 12px rgba(255, 60, 60, 0.15)",
  overflow: "hidden",
};
const header: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "10px 12px", borderBottom: "1px solid var(--red)",
  background: "var(--bg-secondary)",
};
const title: CSSProperties = {
  fontSize: 11, fontWeight: 800, letterSpacing: 2.5,
  fontFamily: "var(--font-display)", color: "var(--red)",
};
const subTitle: CSSProperties = {
  fontSize: 9, letterSpacing: 1.5, color: "var(--text-dim)",
  fontFamily: "var(--font-ui)", marginLeft: 4,
};
const clearBtn: CSSProperties = {
  fontSize: 8, fontWeight: 700, fontFamily: "var(--font-display)",
  padding: "2px 8px", borderRadius: 3, border: "1px solid var(--red)",
  background: "transparent", color: "var(--red)", cursor: "pointer",
  letterSpacing: 1,
};
const list: CSSProperties = {
  flex: 1, overflowY: "auto", padding: 8,
  display: "flex", flexDirection: "column", gap: 6,
};
const emptyState: CSSProperties = {
  textAlign: "center", padding: 16, fontSize: 10,
  color: "var(--text-dim)", fontFamily: "var(--font-mono)",
};
const card: CSSProperties = {
  border: "1px solid var(--accent-border)", borderRadius: 4,
  background: "var(--bg-void)", overflow: "hidden",
};
const cardHead: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "6px 10px", gap: 8,
};
const kindBadge: CSSProperties = {
  fontSize: 9, fontWeight: 800, padding: "1px 6px",
  border: "1px solid", borderRadius: 3,
  fontFamily: "var(--font-display)", letterSpacing: 1, flexShrink: 0,
};
const cardBody: CSSProperties = {
  padding: "8px 10px 10px", borderTop: "1px solid var(--accent-dim)",
  background: "var(--bg-primary)",
};
const metaLabel: CSSProperties = {
  fontSize: 8, color: "var(--text-dim)", letterSpacing: 1.5,
  fontFamily: "var(--font-display)", marginRight: 6,
  display: "block", marginBottom: 3,
};
const metaValue: CSSProperties = {
  fontSize: 11, color: "var(--cyan)", fontFamily: "var(--font-mono)",
};
const cmdBox: CSSProperties = {
  display: "block", padding: "4px 6px", borderRadius: 3,
  background: "var(--bg-void)", fontSize: 10,
  color: "var(--green)", fontFamily: "var(--font-mono)",
  wordBreak: "break-all",
};
const chipRow: CSSProperties = {
  display: "flex", flexWrap: "wrap", gap: 4,
};
const chip: CSSProperties = {
  fontSize: 10, padding: "2px 6px", borderRadius: 3,
  background: "var(--accent-dim)", color: "var(--accent)",
  fontFamily: "var(--font-mono)", border: "1px solid var(--accent-border)",
};
const rowsBox: CSSProperties = {
  maxHeight: 200, overflowY: "auto", border: "1px solid var(--accent-dim)",
  borderRadius: 3, padding: 4, background: "var(--bg-void)",
};
const rowLine: CSSProperties = {
  display: "flex", flexWrap: "wrap", gap: 4, padding: "2px 0",
  borderBottom: "1px dashed var(--accent-dim)",
  fontSize: 10, fontFamily: "var(--font-mono)",
};
const cellBox: CSSProperties = {
  padding: "0 4px", color: "var(--text-secondary)",
  borderRight: "1px solid var(--accent-dim)",
};
const rawBox: CSSProperties = {
  margin: "4px 0 0", padding: 6, borderRadius: 3,
  background: "var(--bg-void)", color: "var(--text-secondary)",
  fontSize: 9, fontFamily: "var(--font-mono)",
  maxHeight: 200, overflow: "auto", whiteSpace: "pre-wrap",
};
