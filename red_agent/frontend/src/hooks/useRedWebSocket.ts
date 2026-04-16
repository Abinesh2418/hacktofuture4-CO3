import { useEffect, useRef, useState, useCallback } from "react";
import type {
  AutoPwnStep,
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
  autoPwnSteps: AutoPwnStep[];
  sendMissionControl: (action: string, missionId: string) => void;
  clearToolCalls: () => void;
  clearLogs: () => void;
  clearAutoPwn: () => void;
}

const MAX_TOOL_CALLS = 50;
const MAX_LOGS = 300;
const MAX_CHAT = 200;
const MAX_AUTO_PWN = 100;

// ── localStorage helpers ──
const STORAGE_KEYS = {
  toolCalls: "red_arsenal_tools",
  logs: "red_arsenal_logs",
  chatMessages: "red_arsenal_chat",
  missionPhase: "red_arsenal_phase",
  autoPwnSteps: "red_arsenal_auto_pwn",
};

function loadFromStorage<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function saveToStorage<T>(key: string, data: T): void {
  try {
    localStorage.setItem(key, JSON.stringify(data));
  } catch {
    // localStorage full or unavailable — ignore
  }
}

export function useRedWebSocket(): RedWsState {
  const [connected, setConnected] = useState(false);
  const [toolCalls, setToolCalls] = useState<ToolCall[]>(() => loadFromStorage(STORAGE_KEYS.toolCalls, []));
  const [logs, setLogs] = useState<LogEntry[]>(() => loadFromStorage(STORAGE_KEYS.logs, []));
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>(() => loadFromStorage(STORAGE_KEYS.chatMessages, []));
  const [missionPhase, setMissionPhase] = useState<MissionPhaseUpdate | null>(() => loadFromStorage(STORAGE_KEYS.missionPhase, null));
  const [autoPwnSteps, setAutoPwnSteps] = useState<AutoPwnStep[]>(() => loadFromStorage(STORAGE_KEYS.autoPwnSteps, []));
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<number | null>(null);

  // Persist to localStorage on every state change
  useEffect(() => { saveToStorage(STORAGE_KEYS.toolCalls, toolCalls); }, [toolCalls]);
  useEffect(() => { saveToStorage(STORAGE_KEYS.logs, logs); }, [logs]);
  useEffect(() => { saveToStorage(STORAGE_KEYS.chatMessages, chatMessages); }, [chatMessages]);
  useEffect(() => { saveToStorage(STORAGE_KEYS.missionPhase, missionPhase); }, [missionPhase]);
  useEffect(() => { saveToStorage(STORAGE_KEYS.autoPwnSteps, autoPwnSteps); }, [autoPwnSteps]);

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
          } else if (env.type === "auto_pwn_step") {
            setAutoPwnSteps((prev) => {
              const next = prev.filter((s) => s.id !== env.payload.id);
              next.push(env.payload);
              return next.slice(-MAX_AUTO_PWN);
            });
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

  const clearToolCalls = useCallback(() => {
    setToolCalls([]);
    localStorage.removeItem(STORAGE_KEYS.toolCalls);
  }, []);

  const clearLogs = useCallback(() => {
    setLogs([]);
    localStorage.removeItem(STORAGE_KEYS.logs);
  }, []);

  const clearAutoPwn = useCallback(() => {
    setAutoPwnSteps([]);
    localStorage.removeItem(STORAGE_KEYS.autoPwnSteps);
  }, []);

  return { connected, toolCalls, logs, chatMessages, missionPhase, autoPwnSteps, sendMissionControl, clearToolCalls, clearLogs, clearAutoPwn };
}
