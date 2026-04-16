import { useEffect, useRef, useState, type CSSProperties } from "react";
import type { LogEntry } from "@/types/red.types";

interface LogStreamProps {
  logs: LogEntry[];
  onClear?: () => void;
  /** When rendered inside a modal that already has its own title bar. */
  hideHeader?: boolean;
}
type LogFilter = "ALL" | "INFO" | "WARN" | "ERROR";

function formatTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const COLORS: Record<string, string> = {
  INFO: "var(--green)", WARN: "var(--yellow)", ERROR: "var(--red)",
};

export function LogStream({ logs, onClear, hideHeader = false }: LogStreamProps) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const [filter, setFilter] = useState<LogFilter>("ALL");
  const [auto, setAuto] = useState(true);
  const filtered = filter === "ALL" ? logs : logs.filter((l) => l.level === filter);

  useEffect(() => {
    if (auto) bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [filtered, auto]);

  return (
    <div style={container}>
      {!hideHeader && (
        <div style={header}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ color: "var(--green)", fontSize: 12 }}>&#9618;</span>
            <span style={title}>LIVE LOG</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-ui)" }}>
              {filtered.length}
            </span>
            <button onClick={() => setAuto(!auto)} style={{
              ...autoBtn,
              color: auto ? "var(--green)" : "var(--text-dim)",
              borderColor: auto ? "var(--green-dim)" : "var(--text-dim)",
            }}>
              {auto ? "AUTO" : "SCROLL"}
            </button>
            {logs.length > 0 && onClear && (
              <button onClick={onClear} style={{
                fontSize: 8, fontWeight: 700, fontFamily: "var(--font-display)",
                padding: "2px 6px", borderRadius: 3, border: "1px solid var(--red)",
                background: "transparent", color: "var(--red)", cursor: "pointer", letterSpacing: 1,
              }}>CLEAR</button>
            )}
          </div>
        </div>
      )}

      <div style={filterRow}>
        {(["ALL", "INFO", "WARN", "ERROR"] as LogFilter[]).map((f) => (
          <button key={f} onClick={() => setFilter(f)} style={{
            ...filterBtn,
            color: filter === f ? (COLORS[f] ?? "var(--text-primary)") : "var(--text-dim)",
            background: filter === f ? "var(--bg-void)" : "transparent",
          }}>
            {f}
          </button>
        ))}
      </div>

      <div style={terminal}>
        {filtered.length === 0 && (
          <div style={{ color: "var(--text-dim)", fontSize: 10, padding: 12 }}>
            awaiting output<span className="anim-pulse">_</span>
          </div>
        )}
        {filtered.map((line, i) => (
          <div key={`${line.timestamp}-${i}`} style={logLine}>
            <span style={{ color: "var(--text-dim)", minWidth: 62 }}>{formatTime(line.timestamp)}</span>
            <span style={{
              color: COLORS[line.level] ?? "var(--text-secondary)",
              minWidth: 38, fontWeight: 600,
            }}>
              {line.level}
            </span>
            <span style={{
              color: line.level === "ERROR" ? "var(--red)" : "var(--text-secondary)",
              flex: 1, wordBreak: "break-word",
            }}>
              {line.message}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

const container: CSSProperties = {
  display: "flex", flexDirection: "column", height: "100%",
  background: "var(--bg-primary)", borderRadius: "var(--radius)",
  border: "1px solid var(--accent-border)", overflow: "hidden",
};
const header: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "10px 12px", borderBottom: "1px solid var(--accent-border)",
  background: "var(--bg-secondary)",
};
const title: CSSProperties = {
  fontSize: 11, fontWeight: 700, letterSpacing: 2,
  fontFamily: "var(--font-display)", color: "var(--text-primary)",
};
const filterRow: CSSProperties = {
  display: "flex", gap: 2, padding: "6px 8px",
  borderBottom: "1px solid var(--accent-dim)",
};
const filterBtn: CSSProperties = {
  fontSize: 9, fontWeight: 600, fontFamily: "var(--font-display)",
  padding: "3px 8px", border: "none", borderRadius: 3,
  cursor: "pointer", letterSpacing: 0.5,
};
const autoBtn: CSSProperties = {
  fontSize: 8, fontWeight: 700, fontFamily: "var(--font-display)",
  padding: "2px 6px", borderRadius: 3, border: "1px solid",
  background: "transparent", cursor: "pointer", letterSpacing: 0.5,
};
const terminal: CSSProperties = {
  flex: 1, overflowY: "auto", padding: "6px 0",
  background: "var(--bg-void)", fontFamily: "var(--font-mono)",
  fontSize: 10, lineHeight: 1.9,
};
const logLine: CSSProperties = {
  display: "flex", gap: 6, padding: "0 10px",
};
