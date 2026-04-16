import axios from "axios";
import type { ChatRequest, ChatMessage } from "@/types/red.types";

const RED_BASE_URL =
  import.meta.env.VITE_RED_API_URL ?? "http://localhost:8001";

const client = axios.create({
  baseURL: RED_BASE_URL,
  timeout: 180_000,
});

export const redApi = {
  health: () => client.get<{ status: string; agent: string }>("/health"),

  /* ── Chat ── */
  chat: (req: ChatRequest) =>
    client.post<ChatMessage>("/chat", req).then((r) => r.data),

  /* ── Mission ── */
  startMission: (target: string) =>
    client.post("/mission/start", { target }).then((r) => r.data),

  clearMission: () =>
    client.post("/mission/clear").then((r) => r.data),

  missionStatus: () =>
    client.get("/mission/status").then((r) => r.data),

  missionReport: () =>
    client.get("/mission/report").then((r) => r.data),
};
