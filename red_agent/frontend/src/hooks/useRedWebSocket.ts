import { useEffect, useRef, useState, useCallback } from "react";
import type {
  ChatMessage,
  LogEntry,
  MissionPhaseUpdate,
  ToolCall,
  WsEnvelope,
} from "@/types/red.types";

const RED_WS_URL =
  import.meta.env.VITE_RED_WS_URL ?? "ws://localhost:8001/ws/red";

export interface RedWsState {
  connected: boolean;
  toolCalls: ToolCall[];
  logs: LogEntry[];
  chatMessages: ChatMessage[];
  missionPhase: MissionPhaseUpdate | null;
  sendMissionControl: (action: string, missionId: string) => void;
  clearToolCalls: () => void;
  clearLogs: () => void;
}

const MAX_TOOL_CALLS = 50;
const MAX_LOGS = 300;
const MAX_CHAT = 200;

export function useRedWebSocket(): RedWsState {
  const [connected, setConnected] = useState(false);
  const [toolCalls, setToolCalls] = useState<ToolCall[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [missionPhase, setMissionPhase] = useState<MissionPhaseUpdate | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<number | null>(null);

  const sendMissionControl = useCallback((action: string, missionId: string) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: "mission_control",
        payload: { action, mission_id: missionId },
      }));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    const connect = () => {
      const ws = new WebSocket(RED_WS_URL);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!cancelled) {
          reconnectTimer.current = window.setTimeout(connect, 2_000);
        }
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (event) => {
        try {
          const env = JSON.parse(event.data) as WsEnvelope;
          if (env.type === "tool_call") {
            setToolCalls((prev) => {
              const next = prev.filter((t) => t.id !== env.payload.id);
              next.push(env.payload);
              return next.slice(-MAX_TOOL_CALLS);
            });
          } else if (env.type === "log") {
            setLogs((prev) => [...prev, env.payload].slice(-MAX_LOGS));
          } else if (env.type === "chat_response") {
            setChatMessages((prev) =>
              [...prev, env.payload].slice(-MAX_CHAT)
            );
          } else if (env.type === "mission_phase") {
            setMissionPhase(env.payload);
          }
        } catch (err) {
          console.error("[red ws] bad payload", err);
        }
      };
    };

    connect();
    return () => {
      cancelled = true;
      if (reconnectTimer.current) window.clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, []);

  const clearToolCalls = useCallback(() => setToolCalls([]), []);
  const clearLogs = useCallback(() => setLogs([]), []);

  return { connected, toolCalls, logs, chatMessages, missionPhase, sendMissionControl, clearToolCalls, clearLogs };
}
