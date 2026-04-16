import type { CSSProperties } from "react";

interface Props {
  active: boolean; // true once recon has confirmed SQLi → data flows to exploit
}

export function AgentFlowArrow({ active }: Props) {
  const color = active ? "var(--red)" : "var(--text-dim)";
  const glow = active ? "0 0 18px var(--red)" : "none";

  return (
    <div style={wrap}>
      <div style={{ ...rail, background: active ? "var(--red)" : "var(--accent-border)" }} />
      <div
        className={active ? "anim-pulse" : ""}
        style={{
          ...arrowBox,
          color,
          borderColor: color,
          boxShadow: glow,
          background: active ? "rgba(255, 60, 60, 0.12)" : "var(--bg-primary)",
        }}
      >
        <span style={{ fontSize: 22, lineHeight: 1 }}>&rarr;</span>
        <span style={{
          fontSize: 8, fontWeight: 800, letterSpacing: 1.5,
          fontFamily: "var(--font-display)", marginTop: 2,
        }}>
          {active ? "EXFIL" : "FLOW"}
        </span>
      </div>
      <div style={{ ...rail, background: active ? "var(--red)" : "var(--accent-border)" }} />
    </div>
  );
}

const wrap: CSSProperties = {
  display: "flex", flexDirection: "column", alignItems: "center",
  justifyContent: "center", height: "100%", gap: 4, minWidth: 56,
};
const rail: CSSProperties = {
  width: 2, flex: 1, transition: "background var(--transition)",
};
const arrowBox: CSSProperties = {
  display: "flex", flexDirection: "column", alignItems: "center",
  justifyContent: "center", padding: "10px 6px",
  border: "2px solid", borderRadius: 8,
  transition: "all var(--transition)",
};
