import { useEffect, useState, type CSSProperties } from "react";
import { redApi } from "@/api/redApi";

export type AttackType = "sqli" | "cmdi" | "lfi" | "idor" | "xss" | "full";

interface Props {
  open: boolean;
  initialTarget?: string;
  onClose: () => void;
  onLaunched?: (target: string, attackType: AttackType, missionId: string) => void;
}

interface AttackOption {
  id: AttackType;
  label: string;
  short: string;
  glyph: string;
  blurb: string;
  accent: string;
}

const ATTACKS: AttackOption[] = [
  {
    id: "sqli",
    label: "SQL INJECTION",
    short: "SQLi",
    glyph: "\u26A1",
    blurb: "sqlmap detects → auto-pwn dumps every database",
    accent: "var(--red)",
  },
  {
    id: "cmdi",
    label: "COMMAND INJECTION",
    short: "CMDi",
    glyph: "\u232B",
    blurb: "find /exec /run /ping endpoints and shell-injectable params",
    accent: "var(--orange)",
  },
  {
    id: "lfi",
    label: "LOCAL FILE INCLUSION",
    short: "LFI",
    glyph: "\u2630",
    blurb: "hunt path/file/page parameters, traversal-friendly endpoints",
    accent: "#bb88ff",
  },
  {
    id: "idor",
    label: "INSECURE DIRECT OBJECT REF",
    short: "IDOR",
    glyph: "\u29C9",
    blurb: "enumerate /api /users/{id} /orders/{id} for predictable refs",
    accent: "var(--cyan)",
  },
  {
    id: "xss",
    label: "CROSS-SITE SCRIPTING",
    short: "XSS",
    glyph: "\u2388",
    blurb: "every form, search box, comment field, reflective query string",
    accent: "var(--yellow)",
  },
  {
    id: "full",
    label: "FULL SCOPE",
    short: "ALL",
    glyph: "\u2620",
    blurb: "default — recon every vector, exploit anything that lands",
    accent: "var(--accent)",
  },
];

export function MissionLauncher({ open, initialTarget = "", onClose, onLaunched }: Props) {
  const [target, setTarget] = useState(initialTarget);
  const [attack, setAttack] = useState<AttackType>("sqli");
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setTarget(initialTarget);
      setAttack("sqli");
      setError(null);
      setLaunching(false);
    }
  }, [open, initialTarget]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !launching) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, launching, onClose]);

  if (!open) return null;

  const valid = /^https?:\/\/.+/.test(target.trim()) || /^\d+\.\d+\.\d+\.\d+/.test(target.trim());

  const handleLaunch = async () => {
    if (!valid || launching) return;
    setLaunching(true);
    setError(null);
    try {
      const res = await redApi.launchMission(target.trim(), attack);
      onLaunched?.(res.target, res.attack_type as AttackType, res.mission_id);
      onClose();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      setLaunching(false);
    }
  };

  return (
    <div style={overlay} onClick={() => !launching && onClose()}>
      <div
        style={frame}
        onClick={(e) => e.stopPropagation()}
        className="anim-slide-up"
      >
        <div style={header}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 20, color: "var(--accent)" }}>&#9760;</span>
            <div>
              <div style={titleText}>NEW MISSION</div>
              <div style={subText}>pick a target and the attack vector you want to validate</div>
            </div>
          </div>
          <button onClick={() => !launching && onClose()} style={closeBtn}>
            &#10005;
          </button>
        </div>

        <div style={body}>
          {/* Target input */}
          <label style={fieldLabel}>TARGET</label>
          <div style={targetRow}>
            <span style={{ color: "var(--accent)", fontSize: 14 }}>&#8827;</span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="http://172.25.8.172:5000"
              style={targetInput}
              autoFocus
            />
            {!valid && target.length > 0 && (
              <span style={{ fontSize: 9, color: "var(--red)", letterSpacing: 1 }}>
                INVALID
              </span>
            )}
          </div>

          {/* Attack type selection */}
          <label style={{ ...fieldLabel, marginTop: 16 }}>ATTACK PROFILE</label>
          <div style={attackGrid}>
            {ATTACKS.map((a) => (
              <button
                key={a.id}
                onClick={() => setAttack(a.id)}
                style={attackCard(attack === a.id, a.accent)}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 18, color: a.accent }}>{a.glyph}</span>
                  <span style={attackLabel(a.accent)}>{a.label}</span>
                  {attack === a.id && (
                    <span style={pickedTag(a.accent)}>SELECTED</span>
                  )}
                </div>
                <div style={attackBlurb}>{a.blurb}</div>
                <div style={attackShort(a.accent)}>{a.short}</div>
              </button>
            ))}
          </div>

          {error && (
            <div style={errorBox}>
              {error}
            </div>
          )}
        </div>

        <div style={footer}>
          <span style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: 1, fontFamily: "var(--font-ui)" }}>
            ESC to cancel
          </span>
          <button
            onClick={handleLaunch}
            disabled={!valid || launching}
            style={launchBtn(valid && !launching)}
          >
            {launching ? "LAUNCHING…" : `LAUNCH ${ATTACKS.find((a) => a.id === attack)?.short ?? ""} MISSION  \u279E`}
          </button>
        </div>
      </div>
    </div>
  );
}

const overlay: CSSProperties = {
  position: "fixed", inset: 0, zIndex: 1000,
  background: "rgba(5, 5, 10, 0.85)", backdropFilter: "blur(4px)",
  display: "flex", alignItems: "center", justifyContent: "center", padding: 24,
};
const frame: CSSProperties = {
  width: "min(900px, 92vw)", maxHeight: "90vh",
  background: "var(--bg-primary)", border: "1px solid var(--accent)",
  borderRadius: 8, overflow: "hidden",
  boxShadow: "0 0 60px rgba(255, 60, 60, 0.15), 0 20px 80px rgba(0,0,0,0.6)",
  display: "flex", flexDirection: "column",
};
const header: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "14px 20px", borderBottom: "1px solid var(--accent-border)",
  background: "var(--bg-secondary)",
};
const titleText: CSSProperties = {
  fontSize: 16, fontWeight: 800, letterSpacing: 4,
  fontFamily: "var(--font-display)", color: "var(--accent)",
  textShadow: "0 0 20px var(--accent-glow)",
};
const subText: CSSProperties = {
  fontSize: 10, color: "var(--text-dim)", letterSpacing: 0.5,
  fontFamily: "var(--font-ui)", marginTop: 2,
};
const closeBtn: CSSProperties = {
  fontSize: 14, fontWeight: 700, padding: "4px 12px",
  border: "1px solid var(--accent-border)", borderRadius: 4,
  background: "transparent", color: "var(--text-dim)", cursor: "pointer",
};
const body: CSSProperties = {
  flex: 1, overflowY: "auto", padding: "18px 20px",
};
const fieldLabel: CSSProperties = {
  display: "block", fontSize: 9, fontWeight: 700, letterSpacing: 2,
  color: "var(--text-dim)", fontFamily: "var(--font-display)", marginBottom: 6,
};
const targetRow: CSSProperties = {
  display: "flex", alignItems: "center", gap: 10,
  background: "var(--bg-void)", border: "1px solid var(--accent-border)",
  borderRadius: 6, padding: "10px 14px",
};
const targetInput: CSSProperties = {
  flex: 1, background: "transparent", border: "none", outline: "none",
  color: "var(--cyan)", fontFamily: "var(--font-mono)", fontSize: 14,
  letterSpacing: 0.5,
};
const attackGrid: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))",
  gap: 8,
};
const attackCard = (selected: boolean, color: string): CSSProperties => ({
  textAlign: "left", cursor: "pointer",
  background: selected ? "rgba(255,255,255,0.04)" : "var(--bg-void)",
  border: `1.5px solid ${selected ? color : "var(--accent-border)"}`,
  borderRadius: 6, padding: "10px 12px",
  display: "flex", flexDirection: "column", gap: 6,
  transition: "all var(--transition)",
  boxShadow: selected ? `0 0 14px ${color}33` : "none",
});
const attackLabel = (color: string): CSSProperties => ({
  fontSize: 11, fontWeight: 800, letterSpacing: 1.5,
  fontFamily: "var(--font-display)", color, flex: 1,
});
const pickedTag = (color: string): CSSProperties => ({
  fontSize: 8, fontWeight: 800, letterSpacing: 1.5,
  padding: "1px 6px", border: `1px solid ${color}`, borderRadius: 3,
  color, fontFamily: "var(--font-display)",
});
const attackBlurb: CSSProperties = {
  fontSize: 10, color: "var(--text-secondary)", lineHeight: 1.5,
  fontFamily: "var(--font-mono)",
};
const attackShort = (color: string): CSSProperties => ({
  alignSelf: "flex-start",
  fontSize: 8, fontWeight: 700, letterSpacing: 1,
  padding: "1px 6px", borderRadius: 2,
  background: `${color}1a`, color,
  fontFamily: "var(--font-display)",
});
const footer: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "12px 20px", borderTop: "1px solid var(--accent-border)",
  background: "var(--bg-secondary)",
};
const launchBtn = (enabled: boolean): CSSProperties => ({
  fontSize: 11, fontWeight: 800, letterSpacing: 2,
  fontFamily: "var(--font-display)",
  padding: "10px 22px", borderRadius: 4,
  border: `1.5px solid ${enabled ? "var(--accent)" : "var(--accent-border)"}`,
  background: enabled ? "var(--accent)" : "transparent",
  color: enabled ? "#000" : "var(--text-dim)",
  cursor: enabled ? "pointer" : "not-allowed",
  textShadow: enabled ? "0 0 8px rgba(0,0,0,0.4)" : "none",
  boxShadow: enabled ? "0 0 18px var(--accent-glow)" : "none",
  transition: "all var(--transition)",
});
const errorBox: CSSProperties = {
  marginTop: 12, padding: "8px 12px", borderRadius: 4,
  border: "1px solid var(--red)", background: "rgba(255,60,60,0.08)",
  color: "var(--red)", fontSize: 11, fontFamily: "var(--font-mono)",
};
