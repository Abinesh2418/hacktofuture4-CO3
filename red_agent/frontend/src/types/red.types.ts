export type ToolStatus = "PENDING" | "RUNNING" | "DONE" | "FAILED";

export interface ToolCall {
  id: string;
  name: string;
  category: "scan" | "exploit" | "strategy" | string;
  status: ToolStatus;
  params: Record<string, unknown>;
  result: Record<string, unknown> | null;
  started_at: string;
  finished_at: string | null;
}

export interface LogEntry {
  timestamp: string;
  level: "INFO" | "WARN" | "ERROR" | string;
  message: string;
  tool_id: string | null;
}

export type AutoPwnKind =
  | "CURL_PROBE"
  | "SQLMAP_DBS"
  | "SQLMAP_TABLES"
  | "SQLMAP_DUMP"
  | "SQLMAP_DUMP_ALL";

export interface AutoPwnSection {
  db: string;
  table: string;
  dump_all?: boolean;
  row_count: number;
  rows: string[][];
  error: string | null;
}

export interface AutoPwnStep {
  id: string;
  mission_id: string | null;
  target: string;
  kind: AutoPwnKind;
  status: ToolStatus;
  command: string;
  summary: string;
  db: string | null;
  table: string | null;
  items: string[];
  rows: string[][];
  sections: AutoPwnSection[];
  raw_tail: string;
  error: string | null;
  started_at: string;
  finished_at: string | null;
}

export type WsEnvelope =
  | { type: "tool_call"; payload: ToolCall }
  | { type: "log"; payload: LogEntry }
  | { type: "chat_response"; payload: ChatMessage }
  | { type: "mission_phase"; payload: MissionPhaseUpdate }
  | { type: "auto_pwn_step"; payload: AutoPwnStep }
  | { type: "heartbeat"; payload: Record<string, never> };

export interface ScanRequest {
  target: string;
  ports?: number[];
  options?: Record<string, unknown>;
}

/* ── Chat ── */
export interface ChatMessage {
  id: string;
  role: "user" | "agent" | "system";
  content: string;
  timestamp: string;
  tool_calls?: ToolCallRef[];
}

export interface ToolCallRef {
  tool_id: string;
  tool_name: string;
  status: ToolStatus;
}

export interface ChatRequest {
  message: string;
  target?: string;
}

/* ── Mission ── */
export type MissionPhaseValue =
  | "IDLE"
  | "RECON"
  | "ANALYZE"
  | "PLAN"
  | "EXPLOIT"
  | "REPORT"
  | "DONE"
  | "FAILED"
  | "PAUSED";

export interface MissionPhaseUpdate {
  mission_id: string;
  phase: MissionPhaseValue;
}
