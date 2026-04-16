import { useState, useEffect, useRef } from "react";
import { useBlueWebSocket } from "@/hooks/useBlueWebSocket";
import { blueApi } from "@/api/blueApi";
import type { RemediationResult, SSHScanResult } from "@/types/blue.types";

/* ── Colors matching the reference UI ── */
const BG = "#0f0e17";
const SURFACE = "#1a1926";
const BORDER = "#2a2940";
const CYAN = "#00e5ff";
const GREEN = "#00e676";
const PURPLE = "#7c4dff";
const ORANGE = "#ffab40";
const RED = "#ff5252";
const MUTED = "#6e6b8a";
const TEXT = "#e0def4";

type ToolEntry = { id: string; name: string; status: "RUNNING" | "DONE" | "FAILED"; detail: string; ts: string };
type LogFilter = "ALL" | "INFO" | "WARN" | "ERROR";
type ToolFilter = "ALL" | "RUNNING" | "DONE" | "FAILED";

export function BlueDashboard() {
  const { connected, toolCalls, logs } = useBlueWebSocket();

  const [target, setTarget] = useState("http://172.25.8.172:5000");
  const [remediating, setRemediating] = useState(false);
  const [result, setResult] = useState<RemediationResult | null>(null);

  // Terminal messages
  const [messages, setMessages] = useState<{ role: "operator" | "agent"; text: string; ts: string }[]>([]);
  const [input, setInput] = useState("");
  const [thinking, setThinking] = useState(false);
  const termRef = useRef<HTMLDivElement>(null);

  // Filters
  const [logFilter, setLogFilter] = useState<LogFilter>("ALL");
  const [toolFilter, setToolFilter] = useState<ToolFilter>("ALL");

  // Scroll terminal to bottom
  useEffect(() => { termRef.current?.scrollTo(0, termRef.current.scrollHeight); }, [messages, thinking]);

  // Build tools from toolCalls
  const tools: ToolEntry[] = toolCalls.map(tc => ({
    id: tc.id,
    name: tc.name,
    status: tc.status === "PENDING" ? "RUNNING" : tc.status as any,
    detail: tc.result ? JSON.stringify(tc.result).slice(0, 60) : "",
    ts: tc.started_at,
  }));

  const filteredTools = toolFilter === "ALL" ? tools : tools.filter(t => t.status === toolFilter);
  const filteredLogs = logFilter === "ALL" ? logs : logs.filter(l => l.level === logFilter);

  const statusCounts = {
    active: tools.filter(t => t.status === "RUNNING").length,
    done: tools.filter(t => t.status === "DONE").length,
    fail: tools.filter(t => t.status === "FAILED").length,
  };

  const now = () => new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const fmtTime = (ts: string) => { try { const d = new Date(ts); return `${String(d.getHours()).padStart(2,"0")}:${String(d.getMinutes()).padStart(2,"0")}:${String(d.getSeconds()).padStart(2,"0")}`; } catch { return ts; } };

  const hasRun = useRef(false);

  const runRemediation = async () => {
    if (remediating) return;
    setRemediating(true);
    setThinking(true);
    setMessages(p => [...p, { role: "agent", text: "Ingesting Red Team report and starting remediation...", ts: now() }]);
    try {
      const res = await blueApi.runSampleRemediation();
      setResult(res);
      // Single summary message with all fixes listed
      const fixList = res.applied_fixes.map(f => `  [${f.severity.toUpperCase()}] ${f.fix_id.replace(/_/g, " ")} — ${f.status}`).join("\n");
      setMessages(p => [...p, {
        role: "agent",
        text: `Remediation complete.\n\nRisk: ${res.risk_score}/10 | Findings: ${res.total_findings} | Fixes: ${res.fixes_applied} | Steps: ${res.total_steps}\n\n${fixList}`,
        ts: now(),
      }]);
    } catch (e: any) {
      setMessages(p => [...p, { role: "agent", text: `Error: ${e?.message || "Remediation failed"}`, ts: now() }]);
    } finally {
      setRemediating(false);
      setThinking(false);
    }
  };

  const handleSend = () => {
    const txt = input.trim();
    if (!txt) return;
    setInput("");
    setMessages(p => [...p, { role: "operator", text: txt, ts: now() }]);

    // Auto-respond to commands
    if (txt.toLowerCase().includes("scan") || txt.toLowerCase().includes("remediate") || txt.toLowerCase().includes("fix") || txt.toLowerCase().includes("run")) {
      runRemediation();
    } else if (txt.toLowerCase().includes("status")) {
      setMessages(p => [...p, { role: "agent", text: result ? `Last run: ${result.fixes_applied} fixes, ${result.total_findings} findings, risk ${result.risk_score}/10` : "No remediation run yet. Type 'run' to start.", ts: now() }]);
    } else {
      setThinking(true);
      setTimeout(() => {
        setMessages(p => [...p, { role: "agent", text: "Blue Agent ready. Commands: 'run' (remediate), 'status' (check results). Paste a target URL or type 'scan' to begin.", ts: now() }]);
        setThinking(false);
      }, 800);
    }
  };

  // Auto-run once on mount (guard against StrictMode double-invoke)
  useEffect(() => {
    if (hasRun.current) return;
    hasRun.current = true;
    setMessages([{ role: "agent", text: "Blue Agent online. Auto-loading Red Team report...", ts: now() }]);
    runRemediation();
  }, []);

  return (
    <div style={{ height: "100vh", overflow: "hidden", background: BG, color: TEXT, fontFamily: "'JetBrains Mono','Fira Code',ui-monospace,monospace", display: "flex", flexDirection: "column" }}>

      {/* ═══ TOP BAR ═══ */}
      <header style={{ height: 52, padding: "0 20px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: `1px solid ${BORDER}`, flexShrink: 0, background: SURFACE }}>
        {/* Left: logo + title */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${PURPLE}, ${CYAN})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 900, color: "#fff" }}>B</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 800, color: CYAN, letterSpacing: 3, lineHeight: 1 }}>BLUE SHIELD</div>
            <div style={{ fontSize: 9, color: MUTED, letterSpacing: 2 }}>AUTONOMOUS DEFENSE AGENT</div>
          </div>
        </div>

        {/* Center: target input */}
        <div style={{ display: "flex", alignItems: "center", gap: 0, background: BG, borderRadius: 6, border: `1px solid ${BORDER}`, overflow: "hidden" }}>
          <span style={{ color: CYAN, fontSize: 10, fontWeight: 700, padding: "0 10px", letterSpacing: 1, background: `${CYAN}11` }}>TARGET</span>
          <input value={target} onChange={e => setTarget(e.target.value)} style={{ background: "transparent", border: "none", color: MUTED, padding: "8px 14px", fontSize: 12, fontFamily: "inherit", outline: "none", width: 260 }} />
        </div>

        {/* Right: status badges */}
        <div style={{ display: "flex", alignItems: "center", gap: 14, fontSize: 11 }}>
          <Badge icon="check" label="ACTIVE" value={statusCounts.active} color={CYAN} />
          <Badge icon="check" label="DONE" value={statusCounts.done} color={GREEN} />
          <Badge icon="x" label="FAIL" value={statusCounts.fail} color={RED} />
          <div style={{ display: "flex", alignItems: "center", gap: 5, marginLeft: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: connected ? GREEN : RED }} />
            <span style={{ color: connected ? GREEN : RED, fontWeight: 700, fontSize: 11, letterSpacing: 1 }}>LIVE</span>
          </div>
        </div>
      </header>

      {/* ═══ MAIN 3-COL ═══ */}
      <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "240px 1fr 280px" }}>

        {/* ── LEFT: TOOLS ── */}
        <div style={{ borderRight: `1px solid ${BORDER}`, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${BORDER}`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0 }}>
            <span style={{ fontSize: 12, fontWeight: 800, letterSpacing: 2, color: TEXT }}>&#x25CB; TOOLS</span>
            <span style={{ color: MUTED, fontSize: 11 }}>{tools.length}</span>
          </div>
          {/* Filter tabs */}
          <div style={{ display: "flex", gap: 0, borderBottom: `1px solid ${BORDER}`, flexShrink: 0 }}>
            {(["ALL", "RUNNING", "DONE", "FAILED"] as ToolFilter[]).map(f => (
              <button key={f} onClick={() => setToolFilter(f)} style={{
                flex: 1, background: toolFilter === f ? `${PURPLE}33` : "transparent",
                color: toolFilter === f ? CYAN : MUTED, border: "none", borderBottom: toolFilter === f ? `2px solid ${CYAN}` : "2px solid transparent",
                padding: "8px 0", fontSize: 9, fontWeight: 700, cursor: "pointer", fontFamily: "inherit", letterSpacing: 1,
              }}>{f}</button>
            ))}
          </div>
          {/* Tool list */}
          <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "8px 12px" }}>
            {filteredTools.length === 0 && <p style={{ color: MUTED, fontSize: 11 }}>No tools executed yet</p>}
            {filteredTools.map(t => (
              <div key={t.id} style={{ padding: "8px 10px", marginBottom: 4, background: `${PURPLE}11`, borderRadius: 6, borderLeft: `3px solid ${t.status === "DONE" ? GREEN : t.status === "RUNNING" ? ORANGE : RED}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: TEXT }}>{t.name}</span>
                  <span style={{ fontSize: 9, fontWeight: 700, color: t.status === "DONE" ? GREEN : t.status === "RUNNING" ? ORANGE : RED }}>{t.status}</span>
                </div>
                {t.detail && <div style={{ fontSize: 9, color: MUTED, marginTop: 3, wordBreak: "break-all" }}>{t.detail}</div>}
              </div>
            ))}
          </div>
        </div>

        {/* ── CENTER: OPERATOR TERMINAL ── */}
        <div style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {/* Terminal header */}
          <div style={{ padding: "12px 20px", borderBottom: `1px solid ${BORDER}`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ width: 10, height: 10, borderRadius: "50%", background: PURPLE }} />
              <span style={{ fontSize: 13, fontWeight: 800, letterSpacing: 2 }}>OPERATOR TERMINAL</span>
            </div>
            <span style={{ color: MUTED, fontSize: 11 }}>{messages.length} messages</span>
          </div>

          {/* Messages */}
          <div ref={termRef} style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "16px 24px" }}>
            {messages.map((m, i) => (
              <div key={i} style={{ marginBottom: 12, display: "flex", flexDirection: "column", alignItems: m.role === "operator" ? "flex-end" : "flex-start" }}>
                <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 3 }}>
                  <span style={{ color: m.role === "operator" ? ORANGE : CYAN, fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>
                    {m.role === "operator" ? "OPERATOR" : "BLUE AGENT"}
                  </span>
                  <span style={{ color: MUTED, fontSize: 9 }}>{m.ts}</span>
                </div>
                <div style={{
                  background: m.role === "operator" ? PURPLE : `${CYAN}11`,
                  color: m.role === "operator" ? "#fff" : TEXT,
                  padding: "10px 16px",
                  borderRadius: m.role === "operator" ? "14px 14px 4px 14px" : "14px 14px 14px 4px",
                  fontSize: 12,
                  maxWidth: "75%",
                  lineHeight: 1.5,
                  border: m.role === "operator" ? "none" : `1px solid ${BORDER}`,
                  whiteSpace: "pre-wrap",
                }}>
                  {m.text}
                </div>
              </div>
            ))}
            {thinking && (
              <div style={{ display: "flex", alignItems: "center", gap: 6, color: MUTED, fontSize: 12 }}>
                <span style={{ color: CYAN }}>&#x25CF;&#x25CF;&#x25CF;</span> analyzing...
              </div>
            )}
          </div>

          {/* Input bar */}
          <div style={{ padding: "12px 20px", borderTop: `1px solid ${BORDER}`, flexShrink: 0, display: "flex", gap: 8 }}>
            <div style={{ flex: 1, display: "flex", alignItems: "center", background: SURFACE, borderRadius: 8, border: `1px solid ${BORDER}`, padding: "0 14px" }}>
              <span style={{ color: PURPLE, marginRight: 8, fontSize: 13 }}>&#x276F;</span>
              <input
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleSend()}
                placeholder="waiting for response..."
                style={{ flex: 1, background: "transparent", border: "none", color: TEXT, padding: "10px 0", fontSize: 12, fontFamily: "inherit", outline: "none" }}
              />
            </div>
            <button onClick={handleSend} style={{ background: PURPLE, color: "#fff", border: "none", borderRadius: 8, padding: "0 16px", fontSize: 13, cursor: "pointer", fontFamily: "inherit" }}>
              &#x27A4;
            </button>
          </div>
        </div>

        {/* ── RIGHT: LIVE LOG ── */}
        <div style={{ borderLeft: `1px solid ${BORDER}`, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${BORDER}`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ color: CYAN, fontSize: 12 }}>&#x2261;</span>
              <span style={{ fontSize: 12, fontWeight: 800, letterSpacing: 2 }}>LIVE LOG</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: GREEN }} />
              <span style={{ color: GREEN, fontSize: 9, fontWeight: 700, letterSpacing: 1 }}>AUTO</span>
            </div>
          </div>
          {/* Log filter tabs */}
          <div style={{ display: "flex", gap: 0, borderBottom: `1px solid ${BORDER}`, flexShrink: 0 }}>
            {(["ALL", "INFO", "WARN", "ERROR"] as LogFilter[]).map(f => (
              <button key={f} onClick={() => setLogFilter(f)} style={{
                flex: 1, background: logFilter === f ? `${PURPLE}22` : "transparent",
                color: logFilter === f ? TEXT : MUTED, border: "none", borderBottom: logFilter === f ? `2px solid ${CYAN}` : "2px solid transparent",
                padding: "8px 0", fontSize: 9, fontWeight: 700, cursor: "pointer", fontFamily: "inherit", letterSpacing: 1,
              }}>{f}</button>
            ))}
          </div>
          {/* Log entries */}
          <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "8px 14px", fontSize: 10, lineHeight: 1.8 }}>
            {filteredLogs.length === 0 && <p style={{ color: MUTED }}>awaiting output</p>}
            {filteredLogs.map((l, i) => (
              <div key={i} style={{ display: "flex", gap: 6 }}>
                <span style={{ color: MUTED, flexShrink: 0 }}>{fmtTime(l.timestamp)}</span>
                <span style={{ color: l.level === "INFO" ? GREEN : l.level === "WARN" ? ORANGE : l.level === "ERROR" ? RED : MUTED, fontWeight: 700, flexShrink: 0, width: 34 }}>{l.level}</span>
                <span style={{ color: `${TEXT}cc` }}>{l.message}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Badge({ label, value, color }: { icon: string; label: string; value: number; color: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
      <span style={{ color, fontSize: 12 }}>&#x2713;</span>
      <span style={{ color: MUTED, fontSize: 10 }}>{label}</span>
      <span style={{ color, fontWeight: 700, fontSize: 11 }}>{value}</span>
    </div>
  );
}
