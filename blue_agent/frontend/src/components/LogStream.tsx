import { useEffect, useRef } from "react";
import type { LogEntry } from "@/types/blue.types";

interface LogStreamProps {
  logs: LogEntry[];
  accent?: string;
}

function formatTime(ts: string): string {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

const LEVEL_COLORS: Record<string, string> = {
  INFO: "#7ee787",
  WARN: "#d29922",
  ERROR: "#f85149",
};

export function LogStream({ logs, accent = "#58a6ff" }: LogStreamProps) {
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <section
      style={{
        background: "#010409",
        border: `1px solid ${accent}55`,
        borderRadius: 8,
        padding: 12,
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
          marginBottom: 8,
          paddingBottom: 6,
          borderBottom: `1px solid ${accent}33`,
          flexShrink: 0,
        }}
      >
        <h3 style={{ margin: 0, color: accent, fontSize: 14, letterSpacing: 1 }}>
          LIVE LOGS
        </h3>
        <span style={{ color: "#8b949e", fontSize: 12 }}>{logs.length} lines</span>
      </header>
      <div
        style={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          fontSize: 12,
          lineHeight: 1.5,
        }}
      >
        {logs.map((line, i) => (
          <div key={`${line.timestamp}-${i}`} style={{ display: "flex", gap: 8 }}>
            <span style={{ color: "#6e7681" }}>[{formatTime(line.timestamp)}]</span>
            <span style={{ color: LEVEL_COLORS[line.level] ?? "#c9d1d9", width: 48 }}>
              {line.level}
            </span>
            <span style={{ color: "#c9d1d9", flex: 1 }}>{line.message}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </section>
  );
}
