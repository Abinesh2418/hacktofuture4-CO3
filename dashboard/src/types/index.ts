/* ── Shared types for HTF Arena ── */

export type ToolStatus = "PENDING" | "RUNNING" | "DONE" | "FAILED";

export interface ToolCall {
  id: string;
  name: string;
  category: string;
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

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "tool_start" | "tool_result" | "error" | "system";
  content: string;
  timestamp: string;
  tool_name?: string;
}

export interface MissionPhase {
  mission_id: string;
  phase: string;
  status: string;
  message: string;
}

export interface PendingFix {
  fix_id: string;
  category: string;
  severity: string;
  description: string;
  endpoint?: string;
  status: string;
  finding_details: Record<string, unknown>;
}

export interface ScoreData {
  red_score: number;
  blue_score: number;
  history: { team: string; points: number; reason: string; timestamp: string }[];
}

export interface RemediationResult {
  target: string;
  risk_score: number;
  total_findings: number;
  fixes_applied: number;
  total_steps: number;
  severity_counts: Record<string, number>;
  applied_fixes: { fix_id: string; category: string; severity: string; status: string; details: string; steps_applied: number; endpoint?: string }[];
  status: string;
}
