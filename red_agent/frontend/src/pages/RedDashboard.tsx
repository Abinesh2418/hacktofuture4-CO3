import { useState, useCallback, useRef, useEffect, useMemo, type CSSProperties } from "react";
import { MissionBanner } from "@/components/MissionBanner";
import { AutoPwnPanel } from "@/components/AutoPwnPanel";
import { ReconAgentBox } from "@/components/ReconAgentBox";
import { AgentFlowArrow } from "@/components/AgentFlowArrow";
import { LogModal } from "@/components/LogModal";
import { ChatModal } from "@/components/ChatModal";
import { MissionLauncher } from "@/components/MissionLauncher";
import { CveLookupModal } from "@/components/CveLookupModal";
import { useRedWebSocket } from "@/hooks/useRedWebSocket";
import { redApi } from "@/api/redApi";
import type { ChatMessage, ToolCall } from "@/types/red.types";

export function RedDashboard() {
  const {
    connected, toolCalls, logs, chatMessages, autoPwnSteps,
    missionPhase, sendMissionControl, clearToolCalls, clearLogs, clearAutoPwn,
  } = useRedWebSocket();
  const [target, setTarget] = useState("");
  const [logModalOpen, setLogModalOpen] = useState(false);
  const [chatModalOpen, setChatModalOpen] = useState(false);
  const [cveModalOpen, setCveModalOpen] = useState(false);
  const [reporting, setReporting] = useState(false);

  const handleDownloadReport = useCallback(async () => {
    if (reporting) return;
    setReporting(true);
    try {
      const { blob, filename } = await redApi.downloadReport(missionPhase?.mission_id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("[report] download failed", e);
      alert("Report download failed — see console.");
    } finally {
      setReporting(false);
    }
  // missionPhase is captured at click time via the latest closure
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reporting]);
  // Show the launcher on first load so the user gets a clear flow into a
  // scoped mission. Persist that they've seen it so reloads don't bug them.
  const [launcherOpen, setLauncherOpen] = useState<boolean>(() => {
    try { return localStorage.getItem("red_arsenal_seen_launcher") !== "1"; }
    catch { return true; }
  });

  // ── Single ordered chat list — persisted in localStorage ──
  const [chatList, setChatList] = useState<ChatMessage[]>(() => {
    try {
      const raw = localStorage.getItem("red_arsenal_chatlist");
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  });
  const seenIds = useRef(new Set<string>(
    (() => { try { const raw = localStorage.getItem("red_arsenal_chatlist"); return raw ? (JSON.parse(raw) as ChatMessage[]).map(m => m.id) : []; } catch { return []; } })()
  ));

  // Append new local messages
  const handleNewMessage = useCallback((msg: ChatMessage) => {
    if (seenIds.current.has(msg.id)) return;
    seenIds.current.add(msg.id);
    setChatList((prev) => [...prev, msg]);
  }, []);

  // Append new WebSocket messages in order
  useEffect(() => {
    for (const msg of chatMessages) {
      if (!seenIds.current.has(msg.id)) {
        seenIds.current.add(msg.id);
        setChatList((prev) => [...prev, msg]);
      }
    }
  }, [chatMessages]);

  // Persist chat list to localStorage
  useEffect(() => {
    try { localStorage.setItem("red_arsenal_chatlist", JSON.stringify(chatList)); } catch {}
  }, [chatList]);

  const clearChat = useCallback(() => {
    setChatList([]);
    seenIds.current.clear();
    localStorage.removeItem("red_arsenal_chatlist");
  }, []);

  const missionId = missionPhase?.mission_id;
  const running = toolCalls.filter((t) => t.status === "RUNNING").length;
  const done = toolCalls.filter((t) => t.status === "DONE").length;
  const failed = toolCalls.filter((t) => t.status === "FAILED").length;

  // ── SQLi detected? Watch sqlmap_detect tool calls for an "injection" finding.
  const sqliDetected = useMemo(() => detectSqli(toolCalls), [toolCalls]);

  return (
    <div className="has-scanline grid-bg" style={shell}>
      {/* ── Top Bar ── */}
      <header style={topBar}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={logoBadge} className="anim-glow">
            <span style={{ fontSize: 20 }}>&#9760;</span>
          </div>
          <div>
            <div style={brandName}>RED ARSENAL</div>
            <div style={brandSub}>AUTONOMOUS PENTEST AGENT</div>
          </div>
        </div>

        {/* Target */}
        <div style={targetBox}>
          <span style={{ color: "var(--accent)", fontSize: 11 }}>TARGET</span>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="http://target:port"
            style={targetInput}
          />
        </div>

        {/* Stats */}
        <div style={statsRow}>
          <Stat label="ACTIVE" value={running} color="var(--yellow)" pulse={running > 0} />
          <Stat label="DONE" value={done} color="var(--green)" />
          <Stat label="FAIL" value={failed} color="var(--red)" />
          <div style={divider} />
          <div style={{
            width: 10, height: 10, borderRadius: "50%",
            background: connected ? "var(--green)" : "var(--red)",
            boxShadow: `0 0 8px ${connected ? "var(--green-dim)" : "var(--accent-glow)"}`,
          }} className={connected ? "" : "anim-pulse"} />
          <span style={{ fontSize: 10, color: connected ? "var(--green)" : "var(--red)" }}>
            {connected ? "LIVE" : "OFF"}
          </span>
          <div style={divider} />
          <button
            onClick={handleDownloadReport}
            disabled={reporting}
            title="Download a markdown report of the current mission"
            style={{
              fontSize: 9, fontWeight: 800, fontFamily: "var(--font-display)",
              padding: "4px 12px", borderRadius: 4,
              border: "1px solid var(--green)",
              background: reporting ? "transparent" : "var(--green-dim)",
              color: "var(--green)", cursor: reporting ? "wait" : "pointer",
              letterSpacing: 1.5,
            }}
          >
            {reporting ? "PREPARING…" : "\u2913 REPORT"}
          </button>
          <button
            onClick={() => setCveModalOpen(true)}
            title="Look up a CVE in the NVD database"
            style={{
              fontSize: 9, fontWeight: 800, fontFamily: "var(--font-display)",
              padding: "4px 12px", borderRadius: 4,
              border: "1px solid var(--orange)",
              background: "transparent", color: "var(--orange)",
              cursor: "pointer", letterSpacing: 1.5,
            }}
          >+ NEW CVE</button>
          <button onClick={() => setLauncherOpen(true)} style={{
            fontSize: 9, fontWeight: 800, fontFamily: "var(--font-display)",
            padding: "4px 12px", borderRadius: 4, border: "1px solid var(--accent)",
            background: "var(--accent)", color: "#000", cursor: "pointer",
            letterSpacing: 1.5, boxShadow: "0 0 12px var(--accent-glow)",
          }}>+ NEW MISSION</button>
          <button onClick={() => { clearToolCalls(); clearLogs(); clearChat(); clearAutoPwn(); }} style={{
            fontSize: 9, fontWeight: 700, fontFamily: "var(--font-display)",
            padding: "4px 12px", borderRadius: 4, border: "1px solid var(--red)",
            background: "transparent", color: "var(--red)", cursor: "pointer",
            letterSpacing: 1,
          }}>CLEAR ALL</button>
        </div>
      </header>

      {/* ── Mission Banner ── */}
      <MissionBanner
        missionPhase={missionPhase}
        onPause={missionId ? () => sendMissionControl("pause", missionId) : undefined}
        onResume={missionId ? () => sendMissionControl("resume", missionId) : undefined}
        onAbort={missionId ? () => sendMissionControl("abort", missionId) : undefined}
      />

      {/* ── Main Layout ── */}
      <div style={mainArea}>
        {/* Top: Recon → Exploit, with arrow between */}
        <div style={agentRow}>
          <div style={agentCol}>
            <ReconAgentBox toolCalls={toolCalls} sqliDetected={sqliDetected} />
          </div>
          <AgentFlowArrow active={sqliDetected} />
          <div style={agentCol}>
            <AutoPwnPanel
              steps={autoPwnSteps}
              armed={sqliDetected}
              onClear={clearAutoPwn}
            />
          </div>
        </div>

        {/* Bottom: two collapsed launchers — Operator Terminal (chat) + Live Log */}
        <div style={launcherRow}>
          <button
            onClick={() => setChatModalOpen(true)}
            style={{ ...termLauncher, borderColor: "var(--accent-border)" }}
          >
            <span style={{
              width: 10, height: 10, borderRadius: "50%",
              background: "var(--accent)", boxShadow: "0 0 8px var(--accent-glow)",
            }} />
            <span style={{ ...termLauncherTitle, color: "var(--accent)" }}>OPERATOR TERMINAL</span>
            <span style={termLauncherSub}>
              {lastChatPreview(chatList)}
            </span>
            <span style={termLauncherCount}>
              {chatList.length} msg{chatList.length === 1 ? "" : "s"}
            </span>
            <span style={{ ...termLauncherCta, color: "var(--accent)", borderColor: "var(--accent)" }}>
              EXPAND &#8599;
            </span>
          </button>

          <button
            onClick={() => setLogModalOpen(true)}
            style={termLauncher}
          >
            <span style={{ fontSize: 18, color: "var(--green)" }}>&#9618;</span>
            <span style={termLauncherTitle}>LIVE LOG</span>
            <span style={termLauncherSub}>
              {lastLogPreview(logs)}
            </span>
            <span style={termLauncherCount}>
              {logs.length} entr{logs.length === 1 ? "y" : "ies"}
            </span>
            <span style={termLauncherCta}>EXPAND &#8599;</span>
          </button>
        </div>
      </div>

      <LogModal
        open={logModalOpen}
        logs={logs}
        onClose={() => setLogModalOpen(false)}
        onClear={clearLogs}
      />

      <ChatModal
        open={chatModalOpen}
        chatMessages={chatList}
        target={target}
        onNewMessage={handleNewMessage}
        onClose={() => setChatModalOpen(false)}
        onClear={clearChat}
      />

      <CveLookupModal
        open={cveModalOpen}
        onClose={() => setCveModalOpen(false)}
      />

      <MissionLauncher
        open={launcherOpen}
        initialTarget={target}
        onClose={() => {
          setLauncherOpen(false);
          try { localStorage.setItem("red_arsenal_seen_launcher", "1"); } catch {}
        }}
        onLaunched={(t) => {
          setTarget(t);
          try { localStorage.setItem("red_arsenal_seen_launcher", "1"); } catch {}
        }}
      />
    </div>
  );
}

function detectSqli(toolCalls: ToolCall[]): boolean {
  for (const c of toolCalls) {
    if (c.name !== "sqlmap_detect") continue;
    const result = c.result as Record<string, unknown> | null;
    const findings = (result?.findings ?? []) as Array<Record<string, unknown>>;
    if (findings.some((f) => f.type === "injection")) return true;
  }
  return false;
}

function lastLogPreview(logs: { message: string }[]): string {
  if (logs.length === 0) return "awaiting output…";
  const msg = logs[logs.length - 1].message;
  return msg.length > 90 ? msg.slice(0, 90) + "…" : msg;
}

function lastChatPreview(messages: ChatMessage[]): string {
  if (messages.length === 0) return "no messages yet — click to talk to the agent";
  const m = messages[messages.length - 1];
  const prefix = m.role === "user" ? "you: " : "agent: ";
  const flat = m.content.replace(/\s+/g, " ").trim();
  const body = flat.length > 80 ? flat.slice(0, 80) + "…" : flat;
  return prefix + body;
}

function Stat({ label, value, color, pulse }: { label: string; value: number; color: string; pulse?: boolean }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
      <span className={pulse ? "anim-pulse" : ""} style={{
        fontSize: 18, fontWeight: 800, color, fontFamily: "var(--font-display)",
      }}>
        {value}
      </span>
      <span style={{ fontSize: 8, color: "var(--text-dim)", letterSpacing: 1.5, fontFamily: "var(--font-ui)" }}>
        {label}
      </span>
    </div>
  );
}

/* ── Styles ── */
const shell: CSSProperties = {
  height: "100vh", display: "flex", flexDirection: "column",
  background: "var(--bg-void)", overflow: "hidden",
};

const topBar: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "8px 16px", background: "var(--bg-primary)",
  borderBottom: "1px solid var(--accent-border)", flexShrink: 0,
};

const logoBadge: CSSProperties = {
  width: 36, height: 36, borderRadius: 8,
  background: "var(--accent-dim)", border: "1px solid var(--accent-border)",
  display: "flex", alignItems: "center", justifyContent: "center",
  color: "var(--accent)",
};

const brandName: CSSProperties = {
  fontSize: 16, fontWeight: 900, letterSpacing: 5,
  color: "var(--accent)", fontFamily: "var(--font-display)",
  textShadow: "0 0 30px var(--accent-glow)",
};

const brandSub: CSSProperties = {
  fontSize: 9, letterSpacing: 3, color: "var(--text-dim)",
  fontFamily: "var(--font-ui)", fontWeight: 600,
};

const targetBox: CSSProperties = {
  display: "flex", alignItems: "center", gap: 10,
  background: "var(--bg-secondary)", borderRadius: 6,
  border: "1px solid var(--accent-border)", padding: "6px 14px",
  flex: 1, maxWidth: 380, margin: "0 20px",
};

const targetInput: CSSProperties = {
  flex: 1, background: "transparent", border: "none", outline: "none",
  color: "var(--cyan)", fontFamily: "var(--font-mono)", fontSize: 13,
  letterSpacing: 0.5,
};

const statsRow: CSSProperties = {
  display: "flex", alignItems: "center", gap: 14,
};

const divider: CSSProperties = {
  width: 1, height: 20, background: "var(--accent-border)",
};

const mainArea: CSSProperties = {
  flex: 1, minHeight: 0, display: "grid",
  // Top: Recon  →  Exploit  (the showcase, gets ALL remaining height)
  // Bottom: two collapsed-launcher buttons (Operator Terminal + Live Log)
  gridTemplateRows: "minmax(0, 1fr) 56px",
  gap: 6, padding: 6, overflow: "hidden",
};

const agentRow: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "1fr 56px 1fr",
  gap: 4, minHeight: 0, overflow: "hidden",
};

const agentCol: CSSProperties = { minHeight: 0, overflow: "hidden" };

const launcherRow: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr",
  gap: 6, minHeight: 0, overflow: "hidden",
};

const termLauncher: CSSProperties = {
  width: "100%", height: "100%",
  display: "flex", alignItems: "center", gap: 14,
  padding: "0 18px",
  background: "var(--bg-primary)",
  border: "1px solid var(--green-dim)", borderRadius: "var(--radius)",
  cursor: "pointer", transition: "all var(--transition)",
};
const termLauncherTitle: CSSProperties = {
  fontSize: 12, fontWeight: 800, letterSpacing: 3,
  fontFamily: "var(--font-display)", color: "var(--green)",
};
const termLauncherSub: CSSProperties = {
  flex: 1, textAlign: "left",
  fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)",
  letterSpacing: 0.5,
};
const termLauncherCount: CSSProperties = {
  fontSize: 9, color: "var(--text-dim)", fontFamily: "var(--font-ui)",
  letterSpacing: 1, padding: "2px 8px",
  border: "1px solid var(--accent-border)", borderRadius: 3,
};
const termLauncherCta: CSSProperties = {
  fontSize: 10, fontWeight: 800, letterSpacing: 1.5,
  color: "var(--green)", fontFamily: "var(--font-display)",
  padding: "4px 12px", border: "1px solid var(--green)", borderRadius: 4,
};
