import { useState, useEffect, useRef, useCallback } from "react";
import type { ToolCall, LogEntry } from "@/types";

const WS_URL = "ws://localhost:8002/ws/blue";

export function useBlueWs() {
  const [connected, setConnected] = useState(false);
  const [toolCalls, setToolCalls] = useState<ToolCall[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);

  const ws = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    const s = new WebSocket(WS_URL);
    ws.current = s;
    s.onopen = () => {
      setConnected(true);
      setToolCalls([]);
      setLogs([]);
    };
    s.onclose = () => { setConnected(false); setTimeout(connect, 2000); };
    s.onerror = () => s.close();
    s.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === "session_start") { setToolCalls([]); setLogs([]); }
        else if (msg.type === "tool_call") setToolCalls(p => [...p.slice(-99), msg.payload]);
        else if (msg.type === "log") setLogs(p => [...p.slice(-499), msg.payload]);
      } catch { /* ignore */ }
    };
  }, []);

  useEffect(() => { connect(); return () => ws.current?.close(); }, [connect]);

  const clearState = useCallback(() => {
    setToolCalls([]);
    setLogs([]);
  }, []);

  return { connected, toolCalls, logs, clearState };
}
