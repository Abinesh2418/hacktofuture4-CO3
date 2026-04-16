import { useState, useCallback, useRef, useEffect, type CSSProperties } from "react";
import { ChatPanel } from "@/components/ChatPanel";
import { ActivityPanel } from "@/components/ActivityPanel";
import { LogStream } from "@/components/LogStream";
import { MissionBanner } from "@/components/MissionBanner";
import { useRedWebSocket } from "@/hooks/useRedWebSocket";
import type { ChatMessage } from "@/types/red.types";

export function RedDashboard() {
  const {
    connected, toolCalls, logs, chatMessages,
    missionPhase, sendMissionControl, clearToolCalls, clearLogs,
  } = useRedWebSocket();
  const [target, setTarget] = useState("");

  // ── Single ordered chat list (fixes ordering bug) ──
  const [chatList, setChatList] = useState<ChatMessage[]>([]);
  const seenIds = useRef(new Set<string>());

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

  const missionId = missionPhase?.mission_id;
  const running = toolCalls.filter((t) => t.status === "RUNNING").length;
  const done = toolCalls.filter((t) => t.status === "DONE").length;
  const failed = toolCalls.filter((t) => t.status === "FAILED").length;

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
      <div style={mainLayout}>
        {/* Left: Tool Activity */}
        <div style={leftCol}>
          <ActivityPanel toolCalls={toolCalls} onClear={clearToolCalls} />
        </div>

        {/* Center: Chat */}
        <div style={centerCol}>
          <ChatPanel
            chatMessages={chatList}
            target={target}
            onNewMessage={handleNewMessage}
          />
        </div>

        {/* Right: Live Terminal */}
        <div style={rightCol}>
          <LogStream logs={logs} onClear={clearLogs} />
        </div>
      </div>
    </div>
  );
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

const mainLayout: CSSProperties = {
  flex: 1, display: "grid",
  gridTemplateColumns: "280px 1fr 280px",
  gap: 6, padding: 6, overflow: "hidden",
};

const leftCol: CSSProperties = { minHeight: 0, overflow: "hidden" };
const centerCol: CSSProperties = { minHeight: 0, overflow: "hidden" };
const rightCol: CSSProperties = { minHeight: 0, overflow: "hidden" };
