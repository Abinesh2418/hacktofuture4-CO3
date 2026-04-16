import type { RemediationResult } from "@/types/blue.types";

interface Props {
  result: RemediationResult;
  accent: string;
}

const SEV_COLORS: Record<string, string> = {
  critical: "#f85149",
  high: "#f0883e",
  medium: "#d29922",
  low: "#7ee787",
  info: "#8b949e",
};

export function RemediationPanel({ result, accent }: Props) {
  return (
    <div
      style={{
        background: "#161b22",
        border: `1px solid ${accent}33`,
        borderRadius: 8,
        padding: 14,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        overflow: "hidden",
        minHeight: 0,
      }}
    >
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h3 style={{ color: accent, margin: 0, fontSize: 13, letterSpacing: 1 }}>
          REMEDIATION RESULTS
        </h3>
        <span
          style={{
            background: result.status === "complete" ? "#238636" : "#d29922",
            color: "#fff",
            padding: "2px 8px",
            borderRadius: 4,
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: 1,
          }}
        >
          {result.status.toUpperCase()}
        </span>
      </div>

      {/* Summary stats */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: 8,
          flexShrink: 0,
        }}
      >
        <StatBox label="FINDINGS" value={result.total_findings} color="#f85149" />
        <StatBox label="FIXES" value={result.fixes_applied} color="#3fb950" />
        <StatBox label="STEPS" value={result.total_steps} color={accent} />
      </div>

      {/* Risk score */}
      <div
        style={{
          background: "#0d1117",
          border: `1px solid ${result.risk_score >= 9 ? "#f85149" : result.risk_score >= 7 ? "#f0883e" : "#d29922"}55`,
          borderRadius: 6,
          padding: "8px 12px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <span style={{ color: "#8b949e", fontSize: 11 }}>RISK SCORE</span>
        <span
          style={{
            color: result.risk_score >= 9 ? "#f85149" : result.risk_score >= 7 ? "#f0883e" : "#d29922",
            fontSize: 18,
            fontWeight: 700,
          }}
        >
          {result.risk_score}/10
        </span>
      </div>

      {/* Severity breakdown */}
      {Object.keys(result.severity_counts).length > 0 && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {Object.entries(result.severity_counts)
            .filter(([, count]) => count > 0)
            .map(([sev, count]) => (
              <span
                key={sev}
                style={{
                  background: `${SEV_COLORS[sev] ?? "#8b949e"}22`,
                  color: SEV_COLORS[sev] ?? "#8b949e",
                  border: `1px solid ${SEV_COLORS[sev] ?? "#8b949e"}55`,
                  padding: "3px 8px",
                  borderRadius: 4,
                  fontSize: 10,
                  fontWeight: 700,
                }}
              >
                {sev.toUpperCase()}: {count}
              </span>
            ))}
        </div>
      )}

      {/* Applied fixes list */}
      <div style={{ display: "flex", flexDirection: "column", gap: 6, overflow: "auto", flex: 1, minHeight: 0 }}>
        <span style={{ color: "#8b949e", fontSize: 10, letterSpacing: 1 }}>APPLIED FIXES</span>
        {result.applied_fixes.map((fix) => (
          <div
            key={fix.fix_id}
            style={{
              background: "#0d1117",
              border: `1px solid ${SEV_COLORS[fix.severity] ?? "#30363d"}44`,
              borderLeft: `3px solid ${SEV_COLORS[fix.severity] ?? "#30363d"}`,
              borderRadius: 6,
              padding: "8px 10px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <span style={{ color: "#f0f6fc", fontSize: 12, fontWeight: 600 }}>
                {fix.fix_id.replace(/_/g, " ")}
              </span>
              <span
                style={{
                  background: fix.status === "FIXED" ? "#238636" : "#d29922",
                  color: "#fff",
                  padding: "1px 6px",
                  borderRadius: 3,
                  fontSize: 9,
                  fontWeight: 700,
                }}
              >
                {fix.status}
              </span>
            </div>
            <div style={{ color: "#8b949e", fontSize: 10, lineHeight: 1.4 }}>
              {fix.details}
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
              <span style={{ color: SEV_COLORS[fix.severity] ?? "#8b949e", fontSize: 9, fontWeight: 700 }}>
                {fix.severity.toUpperCase()}
              </span>
              <span style={{ color: "#8b949e", fontSize: 9 }}>
                {fix.steps_applied} steps
              </span>
              {fix.endpoint && (
                <span style={{ color: accent, fontSize: 9 }}>
                  {fix.endpoint as string}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatBox({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div
      style={{
        background: "#0d1117",
        border: `1px solid ${color}33`,
        borderRadius: 6,
        padding: "8px 10px",
        textAlign: "center",
      }}
    >
      <div style={{ color, fontSize: 20, fontWeight: 700 }}>{value}</div>
      <div style={{ color: "#8b949e", fontSize: 9, letterSpacing: 1 }}>{label}</div>
    </div>
  );
}
