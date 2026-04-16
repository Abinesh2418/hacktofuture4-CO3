import { useState, useEffect, useRef, type CSSProperties } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/App";
import { useRedWs } from "@/hooks/useRedWs";
import { useBlueWs } from "@/hooks/useBlueWs";
import { redApi } from "@/api/redApi";
import { blueApi } from "@/api/blueApi";
import { authApi } from "@/api/authApi";
import type { ToolCall, LogEntry, PendingFix, ScoreData } from "@/types";

export function ArenaDashboard() {
  const { username, logout } = useAuth();
  const nav = useNavigate();
  const red = useRedWs();
  const blue = useBlueWs();

  const [target, setTarget] = useState("http://172.25.8.172:5000");
  const [scores, setScores] = useState<ScoreData>({ red_score: 0, blue_score: 0, history: [] });
  const [pendingFixes, setPendingFixes] = useState<PendingFix[]>([]);
  const [tab, setTab] = useState<"battle" | "scores">("battle");

  // Red chat
  const [redInput, setRedInput] = useState("");
  const [redLoading, setRedLoading] = useState(false);
  const [redMessages, setRedMessages] = useState<{ role: string; text: string }[]>([]);
  const redTermRef = useRef<HTMLDivElement>(null);

  // Blue chat
  const [blueMessages, setBlueMessages] = useState<{ role: string; text: string }[]>([]);
  const blueTermRef = useRef<HTMLDivElement>(null);

  // Scroll terminals
  useEffect(() => { redTermRef.current?.scrollTo(0, redTermRef.current.scrollHeight); }, [redMessages]);
  useEffect(() => { blueTermRef.current?.scrollTo(0, blueTermRef.current.scrollHeight); }, [blueMessages]);

  // Poll scores
  useEffect(() => {
    const i = setInterval(async () => {
      try { setScores(await authApi.scores()); } catch { /* ignore */ }
    }, 5000);
    return () => clearInterval(i);
  }, []);

  // Poll pending fixes
  useEffect(() => {
    const i = setInterval(async () => {
      try { setPendingFixes(await blueApi.pendingFixes()); } catch { /* ignore */ }
    }, 3000);
    return () => clearInterval(i);
  }, []);

  // Red: send chat
  const sendRed = async () => {
    const txt = redInput.trim();
    if (!txt || redLoading) return;
    setRedInput("");
    setRedMessages(p => [...p, { role: "operator", text: txt }]);
    setRedLoading(true);
    try {
      const res = await redApi.chat(txt, target);
      setRedMessages(p => [...p, { role: "agent", text: res.content || res.reply || res.message || (typeof res === "string" ? res : JSON.stringify(res)) }]);
    } catch (e: any) {
      setRedMessages(p => [...p, { role: "agent", text: `Error: ${e?.message}` }]);
    } finally { setRedLoading(false); }
  };

  // Blue: approve fix
  const approveFix = async (fixId: string) => {
    try {
      const res = await blueApi.approveFix(fixId);
      setBlueMessages(p => [...p, { role: "agent", text: `Fix applied: ${res.fix_id} — ${res.status}` }]);
      setPendingFixes(p => p.filter(f => f.fix_id !== fixId));
    } catch (e: any) {
      setBlueMessages(p => [...p, { role: "agent", text: `Error: ${e?.message}` }]);
    }
  };

  const approveAll = async () => {
    try {
      const results = await blueApi.approveAll();
      setBlueMessages(p => [...p, { role: "agent", text: `All ${results.length} fixes applied.` }]);
      setPendingFixes([]);
    } catch (e: any) {
      setBlueMessages(p => [...p, { role: "agent", text: `Error: ${e?.message}` }]);
    }
  };

  // Send Red report to Blue
  const sendReportToBlue = async () => {
    setBlueMessages(p => [...p, { role: "system", text: "Receiving Red Team report..." }]);
    try {
      const res = await blueApi.runSample();
      setBlueMessages(p => [...p, { role: "agent", text: `Report processed: ${res.total_findings} findings. ${pendingFixes.length} fixes pending approval.` }]);
      // Refresh pending
      setPendingFixes(await blueApi.pendingFixes());
    } catch (e: any) {
      setBlueMessages(p => [...p, { role: "agent", text: `Error: ${e?.message}` }]);
    }
  };

  const redRunning = red.toolCalls.filter(t => t.status === "RUNNING").length;
  const redDone = red.toolCalls.filter(t => t.status === "DONE").length;
  const blueRunning = blue.toolCalls.filter(t => t.status === "RUNNING").length;
  const blueDone = blue.toolCalls.filter(t => t.status === "DONE").length;

  const fmtTime = (ts: string) => { try { const d = new Date(ts); return `${String(d.getHours()).padStart(2,"0")}:${String(d.getMinutes()).padStart(2,"0")}:${String(d.getSeconds()).padStart(2,"0")}`; } catch { return ""; } };
  const levCol: Record<string, string> = { INFO: "var(--green)", WARN: "var(--yellow)", ERROR: "var(--red)" };

  return (
    <div className="has-scanline grid-bg" style={{ height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden" }}>

      {/* ═══ TOP BAR ═══ */}
      <header style={topBar}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={logoBadge} className="anim-glow"><span style={{ fontSize: 18 }}>&#9876;</span></div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 900, color: "var(--accent)", fontFamily: "var(--font-display)", letterSpacing: 4 }}>HTF ARENA</div>
            <div style={{ fontSize: 8, color: "var(--text-dim)", letterSpacing: 3, fontFamily: "var(--font-ui)" }}>RED vs BLUE BATTLEGROUND</div>
          </div>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 0 }}>
          <TabBtn label="BATTLE" active={tab === "battle"} onClick={() => setTab("battle")} />
          <TabBtn label="SCOREBOARD" active={tab === "scores"} onClick={() => setTab("scores")} />
        </div>

        {/* Score ticker */}
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <ScoreBadge label="RED" score={scores.red_score} color="var(--red)" />
          <span style={{ color: "var(--text-dim)", fontFamily: "var(--font-display)", fontSize: 12 }}>VS</span>
          <ScoreBadge label="BLUE" score={scores.blue_score} color="var(--cyan)" />
        </div>

        {/* Status + user */}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <Dot on={red.connected} label="RED" />
          <Dot on={blue.connected} label="BLUE" />
          <span style={{ color: "var(--text-secondary)", fontSize: 10 }}>{username}</span>
          <button onClick={() => { logout(); nav("/login"); }} style={logoutBtn}>LOGOUT</button>
        </div>
      </header>

      {/* ═══ MAIN CONTENT ═══ */}
      {tab === "battle" ? (
        <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 1px 1fr", overflow: "hidden" }}>

          {/* ── RED HALF ── */}
          <div style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
            <div style={teamHeader}>
              <span style={{ color: "var(--red)", fontFamily: "var(--font-display)", fontSize: 12, fontWeight: 800, letterSpacing: 3 }}>&#9760; RED ARSENAL</span>
              <span style={{ color: "var(--text-dim)", fontSize: 10 }}>{redRunning} active / {redDone} done</span>
            </div>
            <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 1fr", overflow: "hidden", gap: 1 }}>
              {/* Red Terminal */}
              <div style={panel}>
                <div style={panelHeader}><span style={{ color: "var(--accent)" }}>&#9679;</span> TERMINAL</div>
                <div ref={redTermRef} style={termBody}>
                  {redMessages.map((m, i) => (
                    <div key={i} style={{ marginBottom: 8 }}>
                      <span style={{ color: m.role === "operator" ? "var(--orange)" : "var(--cyan)", fontSize: 9, fontWeight: 700 }}>{m.role === "operator" ? "YOU" : "RED AGENT"}</span>
                      <div style={{ ...msgBubble, background: m.role === "operator" ? "var(--accent-dim)" : "var(--bg-secondary)", whiteSpace: "pre-wrap" }}>{m.text}</div>
                    </div>
                  ))}
                  {redLoading && <div style={{ color: "var(--text-dim)", fontSize: 11 }}>&#9679;&#9679;&#9679; thinking...</div>}
                </div>
                <div style={inputBar}>
                  <span style={{ color: "var(--accent)" }}>&#10095;</span>
                  <input value={redInput} onChange={e => setRedInput(e.target.value)} onKeyDown={e => e.key === "Enter" && sendRed()} placeholder="attack command..." style={chatInput} />
                  <button onClick={sendRed} style={sendBtn}>&#10148;</button>
                </div>
              </div>
              {/* Red Logs */}
              <div style={panel}>
                <div style={panelHeader}>RED LOG <span style={{ color: "var(--text-dim)", fontSize: 10 }}>{red.logs.length}</span></div>
                <div style={logBody}>
                  {red.logs.map((l, i) => (
                    <div key={i} style={{ display: "flex", gap: 6, fontSize: 10 }}>
                      <span style={{ color: "var(--text-dim)", flexShrink: 0 }}>{fmtTime(l.timestamp)}</span>
                      <span style={{ color: levCol[l.level] || "var(--text-primary)", flexShrink: 0, width: 32, fontWeight: 700 }}>{l.level}</span>
                      <span style={{ color: "var(--text-secondary)" }}>{l.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Divider */}
          <div style={{ background: "var(--accent-border)", boxShadow: "0 0 12px var(--accent-glow)" }} />

          {/* ── BLUE HALF ── */}
          <div style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
            <div style={teamHeader}>
              <span style={{ color: "var(--cyan)", fontFamily: "var(--font-display)", fontSize: 12, fontWeight: 800, letterSpacing: 3 }}>&#9681; BLUE SHIELD</span>
              <div style={{ display: "flex", gap: 8 }}>
                {pendingFixes.length > 0 && (
                  <button onClick={approveAll} style={{ ...sendBtn, background: "var(--green)", color: "var(--bg-void)", padding: "4px 12px", fontSize: 9 }}>
                    APPROVE ALL ({pendingFixes.length})
                  </button>
                )}
                <button onClick={sendReportToBlue} style={{ ...sendBtn, padding: "4px 12px", fontSize: 9 }}>
                  SEND REPORT
                </button>
                <span style={{ color: "var(--text-dim)", fontSize: 10 }}>{blueRunning} active / {blueDone} done</span>
              </div>
            </div>
            <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 1fr", overflow: "hidden", gap: 1 }}>
              {/* Blue: Pending Fixes + Messages */}
              <div style={panel}>
                <div style={panelHeader}><span style={{ color: "var(--cyan)" }}>&#9679;</span> DEFENSE TERMINAL</div>
                <div ref={blueTermRef} style={termBody}>
                  {/* Pending fixes awaiting approval */}
                  {pendingFixes.map(f => (
                    <div key={f.fix_id} style={{ marginBottom: 6, padding: "8px 10px", background: "var(--bg-secondary)", borderRadius: 8, borderLeft: `3px solid ${f.severity === "critical" ? "var(--red)" : f.severity === "high" ? "var(--orange)" : "var(--yellow)"}` }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 11, fontWeight: 600 }}>{f.category.replace(/_/g, " ")}</span>
                        <div style={{ display: "flex", gap: 4 }}>
                          <button onClick={() => approveFix(f.fix_id)} style={{ background: "var(--green)", color: "var(--bg-void)", border: "none", borderRadius: 4, padding: "2px 8px", fontSize: 9, fontWeight: 800, cursor: "pointer", fontFamily: "var(--font-mono)" }}>APPLY</button>
                          <button onClick={() => blueApi.rejectFix(f.fix_id).then(() => setPendingFixes(p => p.filter(x => x.fix_id !== f.fix_id)))} style={{ background: "var(--red-dim)", color: "var(--red)", border: "none", borderRadius: 4, padding: "2px 8px", fontSize: 9, fontWeight: 800, cursor: "pointer", fontFamily: "var(--font-mono)" }}>SKIP</button>
                        </div>
                      </div>
                      <div style={{ fontSize: 9, color: "var(--text-dim)", marginTop: 3 }}>[{f.severity.toUpperCase()}] {f.description}</div>
                    </div>
                  ))}
                  {/* Blue messages */}
                  {blueMessages.map((m, i) => (
                    <div key={i} style={{ marginBottom: 6 }}>
                      <span style={{ color: m.role === "system" ? "var(--yellow)" : "var(--cyan)", fontSize: 9, fontWeight: 700 }}>{m.role === "system" ? "SYSTEM" : "BLUE AGENT"}</span>
                      <div style={{ ...msgBubble, background: "var(--cyan-dim)", whiteSpace: "pre-wrap" }}>{m.text}</div>
                    </div>
                  ))}
                  {pendingFixes.length === 0 && blueMessages.length === 0 && (
                    <div style={{ color: "var(--text-dim)", fontSize: 11, textAlign: "center", marginTop: 40 }}>
                      Click SEND REPORT to start defense analysis
                    </div>
                  )}
                </div>
              </div>
              {/* Blue Logs */}
              <div style={panel}>
                <div style={panelHeader}>BLUE LOG <span style={{ color: "var(--text-dim)", fontSize: 10 }}>{blue.logs.length}</span></div>
                <div style={logBody}>
                  {blue.logs.map((l, i) => (
                    <div key={i} style={{ display: "flex", gap: 6, fontSize: 10 }}>
                      <span style={{ color: "var(--text-dim)", flexShrink: 0 }}>{fmtTime(l.timestamp)}</span>
                      <span style={{ color: levCol[l.level] || "var(--text-primary)", flexShrink: 0, width: 32, fontWeight: 700 }}>{l.level}</span>
                      <span style={{ color: "var(--text-secondary)" }}>{l.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* ═══ SCOREBOARD TAB ═══ */
        <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", padding: 40, overflow: "auto" }}>
          <div style={{ fontFamily: "var(--font-display)", fontSize: 28, fontWeight: 900, color: "var(--accent)", letterSpacing: 6, marginBottom: 32 }}>LEADERBOARD</div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 100px 1fr", gap: 24, width: "100%", maxWidth: 700, marginBottom: 40 }}>
            {/* Red Score */}
            <div style={{ ...scoreCard, borderColor: "var(--red)" }}>
              <div style={{ fontSize: 48, fontWeight: 900, color: "var(--red)", fontFamily: "var(--font-display)" }}>{scores.red_score}</div>
              <div style={{ fontSize: 11, color: "var(--text-dim)", letterSpacing: 3, fontFamily: "var(--font-ui)" }}>RED TEAM</div>
            </div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
              <span style={{ fontSize: 24, fontFamily: "var(--font-display)", color: "var(--text-dim)" }}>VS</span>
            </div>
            {/* Blue Score */}
            <div style={{ ...scoreCard, borderColor: "var(--cyan)" }}>
              <div style={{ fontSize: 48, fontWeight: 900, color: "var(--cyan)", fontFamily: "var(--font-display)" }}>{scores.blue_score}</div>
              <div style={{ fontSize: 11, color: "var(--text-dim)", letterSpacing: 3, fontFamily: "var(--font-ui)" }}>BLUE TEAM</div>
            </div>
          </div>

          {/* Score history */}
          <div style={{ width: "100%", maxWidth: 700 }}>
            <div style={{ fontSize: 11, color: "var(--text-dim)", letterSpacing: 2, marginBottom: 12, fontFamily: "var(--font-ui)", fontWeight: 700 }}>SCORE HISTORY</div>
            {scores.history.length === 0 && <div style={{ color: "var(--text-dim)", fontSize: 11 }}>No points awarded yet</div>}
            {[...scores.history].reverse().slice(0, 20).map((h, i) => (
              <div key={i} style={{ display: "flex", gap: 12, padding: "6px 0", borderBottom: "1px solid var(--accent-border)" }}>
                <span style={{ color: h.team === "red" ? "var(--red)" : "var(--cyan)", fontWeight: 700, width: 50, fontFamily: "var(--font-display)", fontSize: 10 }}>{h.team.toUpperCase()}</span>
                <span style={{ color: "var(--green)", fontWeight: 700, width: 50, fontSize: 12 }}>+{h.points}</span>
                <span style={{ color: "var(--text-secondary)", fontSize: 11, flex: 1 }}>{h.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function TabBtn({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} style={{
      background: active ? "var(--accent-dim)" : "transparent",
      color: active ? "var(--accent)" : "var(--text-dim)",
      border: "1px solid var(--accent-border)",
      borderRadius: 0,
      padding: "6px 20px",
      fontSize: 10,
      fontWeight: 800,
      cursor: "pointer",
      fontFamily: "var(--font-display)",
      letterSpacing: 2,
    }}>{label}</button>
  );
}

function ScoreBadge({ label, score, color }: { label: string; score: number; color: string }) {
  return (
    <div style={{ textAlign: "center" }}>
      <div style={{ fontSize: 18, fontWeight: 900, color, fontFamily: "var(--font-display)" }}>{score}</div>
      <div style={{ fontSize: 7, color: "var(--text-dim)", letterSpacing: 2, fontFamily: "var(--font-ui)" }}>{label}</div>
    </div>
  );
}

function Dot({ on, label }: { on: boolean; label: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: on ? "var(--green)" : "var(--red)" }} />
      <span style={{ fontSize: 8, color: "var(--text-dim)", letterSpacing: 1, fontFamily: "var(--font-ui)" }}>{label}</span>
    </div>
  );
}

const topBar: CSSProperties = { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 16px", background: "var(--bg-primary)", borderBottom: "1px solid var(--accent-border)", flexShrink: 0 };
const logoBadge: CSSProperties = { width: 34, height: 34, borderRadius: 8, background: "var(--accent-dim)", border: "1px solid var(--accent-border)", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--accent)" };
const teamHeader: CSSProperties = { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 12px", background: "var(--bg-secondary)", borderBottom: "1px solid var(--accent-border)", flexShrink: 0 };
const panel: CSSProperties = { display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg-primary)", borderRight: "1px solid var(--accent-border)" };
const panelHeader: CSSProperties = { padding: "8px 12px", fontSize: 11, fontWeight: 800, letterSpacing: 2, color: "var(--text-primary)", borderBottom: "1px solid var(--accent-border)", flexShrink: 0, display: "flex", justifyContent: "space-between", alignItems: "center" };
const termBody: CSSProperties = { flex: 1, minHeight: 0, overflowY: "auto", padding: "10px 12px" };
const logBody: CSSProperties = { flex: 1, minHeight: 0, overflowY: "auto", padding: "6px 10px", lineHeight: 1.7 };
const msgBubble: CSSProperties = { padding: "8px 12px", borderRadius: 8, fontSize: 11, marginTop: 3, lineHeight: 1.5 };
const inputBar: CSSProperties = { display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderTop: "1px solid var(--accent-border)", flexShrink: 0 };
const chatInput: CSSProperties = { flex: 1, background: "var(--bg-input)", border: "1px solid var(--accent-border)", borderRadius: 6, padding: "8px 12px", color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: 12, outline: "none" };
const sendBtn: CSSProperties = { background: "var(--accent)", color: "var(--bg-void)", border: "none", borderRadius: 6, padding: "8px 14px", fontWeight: 800, cursor: "pointer", fontFamily: "var(--font-mono)" };
const logoutBtn: CSSProperties = { background: "var(--red-dim)", color: "var(--red)", border: "1px solid var(--red)", borderRadius: 4, padding: "4px 10px", fontSize: 9, fontWeight: 700, cursor: "pointer", fontFamily: "var(--font-ui)", letterSpacing: 1 };
const scoreCard: CSSProperties = { background: "var(--bg-card)", border: "2px solid", borderRadius: 16, padding: "24px 20px", textAlign: "center", boxShadow: "0 0 30px var(--accent-dim)" };
