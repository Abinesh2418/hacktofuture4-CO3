import type { CSSProperties } from "react";
import type { MissionPhaseUpdate, MissionPhaseValue } from "@/types/red.types";

interface Props {
  missionPhase: MissionPhaseUpdate | null;
  onPause?: () => void;
  onResume?: () => void;
  onAbort?: () => void;
}

const PHASES: MissionPhaseValue[] = ["RECON", "ANALYZE", "EXPLOIT", "REPORT"];
const CFG: Record<string, { c: string; i: string }> = {
  IDLE: { c: "var(--text-dim)", i: "\u25CB" }, RECON: { c: "var(--cyan)", i: "\u2316" },
  ANALYZE: { c: "var(--yellow)", i: "\u2699" }, PLAN: { c: "var(--orange)", i: "\u2694" },
  EXPLOIT: { c: "var(--red)", i: "\u26A1" }, REPORT: { c: "var(--green)", i: "\u2611" },
  DONE: { c: "var(--green)", i: "\u2713" }, FAILED: { c: "var(--red)", i: "\u2717" },
  PAUSED: { c: "var(--yellow)", i: "\u23F8" },
};

export function MissionBanner({ missionPhase, onPause, onResume, onAbort }: Props) {
  if (!missionPhase) return null;
  const { phase, mission_id } = missionPhase;
  const cfg = CFG[phase] ?? CFG.IDLE;
  const active = !["DONE", "FAILED", "IDLE"].includes(phase);
  const paused = phase === "PAUSED";

  return (
    <div style={bar}>
      <span style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: 1, fontFamily: "var(--font-ui)" }}>
        MISSION {mission_id.slice(0, 8)}
      </span>

      <div style={{ display: "flex", alignItems: "center", gap: 2 }}>
        {PHASES.map((p, i) => {
          const cur = p === phase;
          const done = PHASES.indexOf(phase) > i || phase === "DONE";
          const pc = CFG[p];
          return (
            <span key={p} style={{ display: "inline-flex", alignItems: "center", gap: 1 }}>
              {i > 0 && <span style={{ width: 10, height: 1, background: done ? pc.c : "var(--text-dim)", opacity: done ? 1 : 0.2 }} />}
              <span className={cur ? "anim-pulse" : ""} style={{
                fontSize: 8, fontWeight: cur ? 800 : 500, letterSpacing: 0.5,
                fontFamily: "var(--font-display)",
                color: cur ? pc.c : done ? pc.c : "var(--text-dim)",
                padding: "1px 5px", borderRadius: 2,
                background: cur ? `${pc.c}22` : "transparent",
              }}>
                {p}
              </span>
            </span>
          );
        })}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{
          fontSize: 8, fontWeight: 800, padding: "2px 8px", borderRadius: 3,
          color: cfg.c, background: `${cfg.c}22`, fontFamily: "var(--font-display)",
        }}>
          {cfg.i} {phase}
        </span>
        {active && !paused && onPause && <Btn onClick={onPause} color="var(--yellow)" label="PAUSE" />}
        {paused && onResume && <Btn onClick={onResume} color="var(--green)" label="RESUME" />}
        {active && onAbort && <Btn onClick={onAbort} color="var(--red)" label="ABORT" />}
      </div>
    </div>
  );
}

function Btn({ onClick, color, label }: { onClick: () => void; color: string; label: string }) {
  return (
    <button onClick={onClick} style={{
      fontSize: 7, fontWeight: 800, fontFamily: "var(--font-display)",
      padding: "2px 7px", borderRadius: 2, border: `1px solid ${color}`,
      background: "transparent", color, cursor: "pointer", letterSpacing: 1,
    }}>
      {label}
    </button>
  );
}

const bar: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "5px 16px", background: "var(--bg-secondary)",
  borderBottom: "1px solid var(--accent-border)", flexShrink: 0, gap: 12,
};
