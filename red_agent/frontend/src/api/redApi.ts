import axios from "axios";
import type { ChatRequest, ChatMessage, ScanRequest, ToolCall } from "@/types/red.types";

export interface CveSummary {
  id: string;
  published: string;
  modified: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" | string;
  score: number | null;
  vector: string | null;
  cwes: string[];
  references: string[];
}
export interface CveLookupResponse {
  total: number;
  results: CveSummary[];
  api_key_in_use?: boolean;
}

const RED_BASE_URL =
  import.meta.env.VITE_RED_API_URL ?? "http://localhost:8001";

const client = axios.create({
  baseURL: RED_BASE_URL,
  timeout: 180_000,
});

function parseFilename(disposition?: string): string | null {
  if (!disposition) return null;
  const m = /filename="?([^";]+)"?/.exec(disposition);
  return m ? m[1] : null;
}

export const redApi = {
  health: () => client.get<{ status: string; agent: string }>("/health"),

  /* ── Chat ── */
  chat: (req: ChatRequest) =>
    client.post<ChatMessage>("/chat", req).then((r) => r.data),

  /* ── Mission launcher (no LLM in the loop) ── */
  launchMission: (target: string, attack_type: string) =>
    client
      .post<{ mission_id: string; target: string; attack_type: string }>(
        "/mission/launch",
        { target, attack_type },
      )
      .then((r) => r.data),

  /* ── NVD CVE lookup ── */
  lookupCveById: (cveId: string) =>
    client
      .get<CveLookupResponse>("/cve/lookup", { params: { cve_id: cveId } })
      .then((r) => r.data),
  searchCveByKeyword: (keyword: string, limit = 10) =>
    client
      .get<CveLookupResponse>("/cve/lookup", { params: { keyword, limit } })
      .then((r) => r.data),

  /* ── Report download (markdown) ── */
  downloadReport: (missionId?: string) => {
    const path = missionId ? `/report/mission/${missionId}` : "/report/mission/latest";
    return client.get(path, { responseType: "blob" }).then((r) => ({
      blob: r.data as Blob,
      filename: parseFilename(r.headers["content-disposition"] as string | undefined)
        ?? "red-arsenal-report.md",
    }));
  },

  /* ── Scans ── */
  scanNetwork: (req: ScanRequest) =>
    client.post("/scan/network", req).then((r) => r.data),
  scanWeb: (req: ScanRequest) =>
    client.post("/scan/web", req).then((r) => r.data),
  scanSystem: (req: ScanRequest) =>
    client.post("/scan/system", req).then((r) => r.data),
  scanCloud: (req: ScanRequest) =>
    client.post("/scan/cloud", req).then((r) => r.data),

  recentScans: (limit = 20) =>
    client
      .get<ToolCall[]>("/scan/recent", { params: { limit } })
      .then((r) => r.data),

  /* ── Recon ── */
  startRecon: (target: string) =>
    client.post("/scan/recon", { target }).then((r) => r.data),
  reconStatus: (sessionId: string) =>
    client.get(`/scan/recon/${sessionId}`).then((r) => r.data),

  /* ── Exploit ── */
  lookupCve: (service: string, version?: string) =>
    client.post("/exploit/lookup_cve", { service, version }).then((r) => r.data),
  runExploit: (target: string, cve_id?: string) =>
    client.post("/exploit/run", { target, cve_id }).then((r) => r.data),

  /* ── Strategy ── */
  planAttack: (target: string, intel: Record<string, unknown> = {}) =>
    client.post("/strategy/plan", { target, intel }).then((r) => r.data),
  currentStrategy: () =>
    client.get("/strategy/current").then((r) => r.data),
};
