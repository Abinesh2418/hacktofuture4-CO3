import type { SSHScanResult } from "@/types/blue.types";

interface SSHScanPanelProps {
  result: SSHScanResult | null;
  accent?: string;
}

const SEV_COLORS: Record<string, string> = {
  critical: "#f85149",
  high: "#f0883e",
  medium: "#d29922",
  low: "#8b949e",
};

export function SSHScanPanel({ result, accent = "#58a6ff" }: SSHScanPanelProps) {
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
        <h3 style={{ margin: 0, color: accent, fontSize: 14, letterSpacing: 1 }}>SCAN RESULTS</h3>
        <span style={{ color: "#8b949e", fontSize: 12 }}>
          {result?.success ? `${result.total_services} services · ${result.elapsed_seconds.toFixed(1)}s` : "waiting"}
        </span>
      </header>

      {!result && (
        <div style={{ color: "#8b949e", fontSize: 12, textAlign: "center", marginTop: 40 }}>
          Enter host &amp; SSH credentials above, then click <b>SCAN</b>.
        </div>
      )}

      {result && !result.success && (
        <div style={{ color: "#f85149", fontSize: 12 }}>{result.error}</div>
      )}

      {result?.success && (
        <div style={{ overflowY: "auto", flex: 1, minHeight: 0, fontSize: 11 }}>
          {/* OS */}
          {result.os_info && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ color: "#8b949e", fontSize: 10, marginBottom: 2 }}>SYSTEM</div>
              <div style={{ color: "#7ee787" }}>{result.os_info.split("\n").slice(0, 2).join(" | ").slice(0, 150)}</div>
            </div>
          )}

          {/* Ports */}
          {result.listening_ports.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ color: "#8b949e", fontSize: 10, marginBottom: 3 }}>OPEN PORTS ({result.listening_ports.length})</div>
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                {result.listening_ports.map((p) => (
                  <span key={p.port} style={{ background: "#21262d", color: "#c9d1d9", padding: "2px 6px", borderRadius: 3, fontSize: 10 }}>
                    :{p.port}{p.process ? ` ${p.process}` : ""}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* All discovered services */}
          <div style={{ color: "#8b949e", fontSize: 10, marginBottom: 4, marginTop: 4 }}>
            DISCOVERED SOFTWARE ({result.total_services})
          </div>
          {result.services.map((svc, i) => (
            <div
              key={`${svc.software}-${i}`}
              style={{
                background: "#161b22",
                borderLeft: `3px solid ${svc.cve_count > 0 ? (svc.fixed ? "#3fb950" : "#f85149") : "#3fb950"}`,
                borderRadius: 4,
                padding: "5px 8px",
                marginBottom: 3,
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span style={{ color: "#f0f6fc" }}>
                {svc.software} <span style={{ color: "#8b949e" }}>{svc.version}</span>
                {svc.port && <span style={{ color: "#6e7681" }}> :{svc.port}</span>}
              </span>
              <span>
                {svc.fixed && (
                  <span style={{ background: "#3fb950", color: "#0d1117", padding: "1px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700, marginRight: 4 }}>FIXED</span>
                )}
                {svc.cve_count > 0 && !svc.fixed && (
                  <span style={{ background: "#f85149", color: "#fff", padding: "1px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700 }}>
                    {svc.cve_count} CVE{svc.cve_count > 1 ? "s" : ""}
                  </span>
                )}
                {svc.cve_count === 0 && (
                  <span style={{ color: "#3fb950", fontSize: 10, fontWeight: 600 }}>CLEAN</span>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
