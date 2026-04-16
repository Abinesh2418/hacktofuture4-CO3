import { useState, useEffect, useRef, useCallback } from "react";
import type { ToolCall, LogEntry, ChatMessage, MissionPhase } from "@/types";

const WS_URL = "ws://localhost:8001/ws/red";

export function useRedWs() {
  const [connected, setConnected] = useState(false);
  const [toolCalls, setToolCalls] = useState<ToolCall[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [missionPhase, setMissionPhase] = useState<MissionPhase | null>(null);
  const ws = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    const s = new WebSocket(WS_URL);
    ws.current = s;
    s.onopen = () => setConnected(true);
    s.onclose = () => { setConnected(false); setTimeout(connect, 2000); };
    s.onerror = () => s.close();
    s.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === "tool_call") setToolCalls(p => [...p.slice(-99), msg.payload]);
        else if (msg.type === "log") setLogs(p => [...p.slice(-499), msg.payload]);
        else if (msg.type === "chat") setChatMessages(p => [...p.slice(-99), msg.payload]);
        else if (msg.type === "mission_phase") setMissionPhase(msg.payload);
      } catch { /* ignore */ }
    };
  }, []);

  useEffect(() => { connect(); return () => ws.current?.close(); }, [connect]);

  const sendMissionControl = useCallback((action: string, missionId: string) => {
    ws.current?.send(JSON.stringify({ type: "mission_control", action, mission_id: missionId }));
  }, []);

  return { connected, toolCalls, logs, chatMessages, missionPhase, sendMissionControl };
}
