import type { SSHScanResult } from "@/types/blue.types";

interface FixPlanPanelProps {
  result: SSHScanResult;
  applying: boolean;
  onApply: () => void;
  accent?: string;
}

const SEV_COLORS: Record<string, string> = {
  critical: "#f85149",
  high: "#f0883e",
  medium: "#d29922",
  low: "#8b949e",
};

export function FixPlanPanel({ result, applying, onApply, accent = "#58a6ff" }: FixPlanPanelProps) {
  const vulnerable = result.services.filter((s) => s.cve_count > 0);
  const allFixed = vulnerable.length > 0 && vulnerable.every((s) => s.fixed);
  const totalCmds = vulnerable.reduce((sum, s) => sum + (s.proposed_fixes?.length ?? 0), 0);

  return (
    <section
      style={{
        background: "#0d1117",
        borderRadius: 8,
        padding: 12,
        border: `1px solid ${allFixed ? "#3fb95055" : "#f0883e55"}`,
        minHeight: 0,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 10,
          paddingBottom: 8,
          borderBottom: `1px solid ${accent}33`,
          flexShrink: 0,
        }}
      >
        <h3 style={{ margin: 0, color: allFixed ? "#3fb950" : "#f0883e", fontSize: 14, letterSpacing: 1 }}>
          {allFixed ? "FIXES APPLIED" : "FIX PLAN"}
        </h3>
        {!allFixed && vulnerable.length > 0 && (
          <button
            onClick={onApply}
            disabled={applying}
            style={{
              background: applying ? "#21262d" : "#f0883e",
              color: applying ? "#8b949e" : "#0d1117",
              border: "none",
              padding: "6px 16px",
              borderRadius: 5,
              fontWeight: 700,
              fontSize: 12,
              cursor: applying ? "wait" : "pointer",
              fontFamily: "inherit",
              letterSpacing: 0.5,
            }}
          >
            {applying ? "APPLYING..." : `APPLY ALL FIXES (${vulnerable.length} services)`}
          </button>
        )}
        {allFixed && (
          <span style={{ color: "#3fb950", fontSize: 12, fontWeight: 600 }}>ALL PATCHED</span>
        )}
      </header>

      {/* Fix list */}
      <div style={{ overflowY: "auto", flex: 1, minHeight: 0, fontSize: 11 }}>
        {vulnerable.length === 0 && (
          <div style={{ color: "#3fb950", textAlign: "center", marginTop: 30, fontSize: 13 }}>
            No vulnerabilities found — server is clean.
          </div>
        )}

        {vulnerable.map((svc, i) => (
          <div
            key={`fix-${svc.software}-${i}`}
            style={{
              background: "#161b22",
              border: `1px solid ${svc.fixed ? "#3fb95033" : "#f0883e33"}`,
              borderLeft: `3px solid ${svc.fixed ? "#3fb950" : "#f0883e"}`,
              borderRadius: 6,
              padding: "8px 10px",
              marginBottom: 8,
            }}
          >
            {/* Service header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <span style={{ fontWeight: 700, fontSize: 13, color: "#f0f6fc" }}>
                {svc.software} <span style={{ color: "#8b949e", fontWeight: 400 }}>{svc.version}</span>
                {svc.port && <span style={{ color: "#6e7681", fontWeight: 400 }}> :{svc.port}</span>}
              </span>
              {svc.fixed ? (
                <span style={{ background: "#3fb950", color: "#0d1117", padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700 }}>
                  PATCHED
                </span>
              ) : (
                <span style={{ background: "#f85149", color: "#fff", padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700 }}>
                  {svc.cve_count} CVE{svc.cve_count > 1 ? "s" : ""}
                </span>
              )}
            </div>

            {/* CVEs */}
            {svc.cves.map((cve) => (
              <div key={cve.cve_id} style={{ padding: "3px 0", fontSize: 10 }}>
                <span style={{ color: SEV_COLORS[cve.severity], fontWeight: 700 }}>{cve.cve_id}</span>
                <span style={{ color: "#8b949e" }}> CVSS {cve.cvss_score} ({cve.severity})</span>
                <span style={{ color: "#8b949e" }}> — {cve.description.slice(0, 80)}</span>
              </div>
            ))}

            {/* Proposed fix commands */}
            {!svc.fixed && svc.proposed_fixes && svc.proposed_fixes.length > 0 && (
              <div
                style={{
                  marginTop: 6,
                  padding: "6px 8px",
                  background: "#010409",
                  borderRadius: 4,
                  border: "1px solid #21262d",
                }}
              >
                <div style={{ color: "#d29922", fontSize: 10, fontWeight: 700, marginBottom: 4 }}>
                  COMMANDS TO EXECUTE:
                </div>
                {svc.proposed_fixes.map((line, j) => {
                  const isCmd = line.trimStart().startsWith("$");
                  const isHeader = !isCmd && !line.startsWith(" ");
                  return (
                    <div
                      key={j}
                      style={{
                        color: isCmd ? "#7ee787" : isHeader ? "#c9d1d9" : "#8b949e",
                        fontFamily: "ui-monospace, monospace",
                        fontSize: 10,
                        lineHeight: 1.6,
                        fontWeight: isHeader ? 600 : 400,
                      }}
                    >
                      {line}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Fix result */}
            {svc.fixed && (
              <div style={{ marginTop: 4, padding: "4px 8px", background: "#3fb95011", borderRadius: 4, color: "#3fb950", fontSize: 10 }}>
                Fix applied — upgrade + hardening executed on server
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
