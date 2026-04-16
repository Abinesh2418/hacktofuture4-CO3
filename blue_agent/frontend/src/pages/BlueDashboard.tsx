import { useState } from "react";
import { ActivityPanel } from "@/components/ActivityPanel";
import { ChatButton } from "@/components/ChatButton";
import { FixPlanPanel } from "@/components/FixPlanPanel";
import { LogStream } from "@/components/LogStream";
import { RemediationPanel } from "@/components/RemediationPanel";
import { ReportInputPanel } from "@/components/ReportInputPanel";
import { SSHScanPanel } from "@/components/SSHScanPanel";
import { StatusBar } from "@/components/StatusBar";
import { useBlueWebSocket } from "@/hooks/useBlueWebSocket";
import { blueApi } from "@/api/blueApi";
import type { RemediationResult, SSHScanResult } from "@/types/blue.types";

const ACCENT = "#58a6ff";

export function BlueDashboard() {
  const { connected, toolCalls, logs, agentStatus } = useBlueWebSocket();

  const [host, setHost] = useState("");
  const [sshPort, setSshPort] = useState("22");
  const [username, setUsername] = useState("root");
  const [password, setPassword] = useState("");
  const [scanning, setScanning] = useState(false);
  const [applying, setApplying] = useState(false);
  const [scanResult, setScanResult] = useState<SSHScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Remediation state (Red report → Blue fix)
  const [remediating, setRemediating] = useState(false);
  const [remediationResult, setRemediationResult] = useState<RemediationResult | null>(null);
  const [remediationError, setRemediationError] = useState<string | null>(null);

  const hasVulnerabilities =
    scanResult?.success === true && scanResult.total_cves > 0;

  const handleScan = async () => {
    if (!host || !password) return;
    setScanning(true);
    setScanError(null);
    setScanResult(null);
    try {
      const res = await blueApi.sshScan({
        host,
        ssh_port: parseInt(sshPort, 10),
        username,
        password,
      });
      setScanResult(res);
      if (!res.success) setScanError(res.error || "Scan failed");
    } catch (err: any) {
      setScanError(err?.response?.data?.detail || err?.message || "Connection failed");
    } finally {
      setScanning(false);
    }
  };

  const handleApplyFixes = async () => {
    setApplying(true);
    try {
      const res = await blueApi.sshApplyFixes();
      if (res.services) {
        setScanResult((prev) =>
          prev ? { ...prev, services: res.services, fixes_applied: res.fixes_applied ?? 0 } : prev
        );
      }
    } catch (err: any) {
      setScanError(err?.response?.data?.detail || err?.message || "Fix failed");
    } finally {
      setApplying(false);
    }
  };

  const handleReportSubmit = async (raw: string) => {
    setRemediating(true);
    setRemediationError(null);
    setRemediationResult(null);
    try {
      const report = JSON.parse(raw);
      const res = await blueApi.ingestReport(report);
      setRemediationResult(res);
    } catch (err: any) {
      setRemediationError(err?.response?.data?.detail || err?.message || "Remediation failed");
    } finally {
      setRemediating(false);
    }
  };

  const handleRunSample = async () => {
    setRemediating(true);
    setRemediationError(null);
    setRemediationResult(null);
    try {
      const res = await blueApi.runSampleRemediation();
      setRemediationResult(res);
    } catch (err: any) {
      setRemediationError(err?.response?.data?.detail || err?.message || "Remediation failed");
    } finally {
      setRemediating(false);
    }
  };

  return (
    <div
      style={{
        height: "100vh",
        overflow: "hidden",
        background: "#0d1117",
        color: "#f0f6fc",
        padding: 20,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        display: "flex",
        flexDirection: "column",
        boxSizing: "border-box",
      }}
    >
      {/* Header */}
      <header style={{ paddingBottom: 10, marginBottom: 10, borderBottom: `1px solid ${ACCENT}55`, flexShrink: 0 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <div>
            <h1 style={{ color: ACCENT, margin: 0, letterSpacing: 2, fontSize: 18 }}>
              BLUE TEAM // AUTONOMOUS DEFENDER
            </h1>
            <p style={{ color: "#8b949e", margin: "2px 0 0", fontSize: 10 }}>
              Paste Red Team report &rarr; Auto-remediate &nbsp;|&nbsp; SSH scan &rarr; Fix plan &rarr; Apply
              &nbsp;&middot;&nbsp;ws:{" "}
              <span style={{ color: connected ? "#3fb950" : "#f85149" }}>
                {connected ? "connected" : "disconnected"}
              </span>
            </p>
          </div>
        </div>

        {/* SSH input bar */}
        <div
          style={{
            display: "flex",
            gap: 8,
            alignItems: "center",
            background: "#161b22",
            padding: "8px 12px",
            borderRadius: 8,
            border: `1px solid ${ACCENT}33`,
            flexWrap: "wrap",
          }}
        >
          <span style={{ color: ACCENT, fontSize: 11, fontWeight: 700, whiteSpace: "nowrap" }}>TARGET</span>
          <input placeholder="Host / IP" value={host} onChange={(e) => setHost(e.target.value)} style={inputStyle} />
          <span style={{ color: "#8b949e", fontSize: 11 }}>:</span>
          <input placeholder="Port" value={sshPort} onChange={(e) => setSshPort(e.target.value)} style={{ ...inputStyle, width: 55, flex: "none" }} />
          <input placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} style={{ ...inputStyle, width: 100, flex: "none" }} />
          <input placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} style={inputStyle} />
          <button
            onClick={handleScan}
            disabled={scanning || applying || !host || !password}
            style={{ ...btnBase, background: scanning ? "#21262d" : ACCENT, color: scanning ? "#8b949e" : "#0d1117" }}
          >
            {scanning ? "SCANNING..." : "SCAN"}
          </button>
          {scanError && <span style={{ color: "#f85149", fontSize: 11 }}>{scanError}</span>}
          {scanResult?.success && scanResult.total_cves === 0 && (
            <span style={{ color: "#3fb950", fontSize: 11 }}>All clean — no vulnerabilities</span>
          )}
        </div>
      </header>

      {/* Status bar */}
      <div style={{ flexShrink: 0 }}>
        <StatusBar status={agentStatus} accent={ACCENT} />
      </div>

      {/* Main content — fixed height, two rows */}
      <div style={{ marginTop: 10, flex: 1, minHeight: 0, display: "flex", flexDirection: "column", gap: 10 }}>

        {/* Row 1: Red Report Input + Remediation Results — fixed 45% */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: remediationResult ? "1fr 1fr" : "1fr",
            gap: 10,
            height: "45%",
            minHeight: 0,
          }}
        >
          <ReportInputPanel
            accent={ACCENT}
            onSubmit={handleReportSubmit}
            onRunSample={handleRunSample}
            submitting={remediating}
          />
          {remediationResult && (
            <RemediationPanel result={remediationResult} accent={ACCENT} />
          )}
        </div>

        {remediationError && (
          <span style={{ color: "#f85149", fontSize: 11, flexShrink: 0 }}>{remediationError}</span>
        )}

        {/* Row 2: SSH scan + Fix plan + Activity + Logs — fills remaining */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: hasVulnerabilities ? "1fr 1fr 1fr 1fr" : "1fr 1fr 1fr",
            gap: 10,
            flex: 1,
            minHeight: 0,
          }}
        >
          <SSHScanPanel result={scanResult} accent={ACCENT} />

          {hasVulnerabilities && (
            <FixPlanPanel
              result={scanResult!}
              applying={applying}
              onApply={handleApplyFixes}
              accent={ACCENT}
            />
          )}

          <ActivityPanel toolCalls={toolCalls} accent={ACCENT} limit={30} />
          <LogStream logs={logs} accent={ACCENT} />
        </div>
      </div>

      <ChatButton accent={ACCENT} />
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  background: "#0d1117",
  border: "1px solid #30363d",
  color: "#f0f6fc",
  padding: "7px 10px",
  borderRadius: 4,
  fontFamily: "inherit",
  fontSize: 12,
  flex: 1,
  minWidth: 0,
};

const btnBase: React.CSSProperties = {
  border: "none",
  padding: "8px 18px",
  borderRadius: 6,
  fontWeight: 700,
  fontSize: 12,
  cursor: "pointer",
  fontFamily: "inherit",
  letterSpacing: 1,
  whiteSpace: "nowrap",
};
