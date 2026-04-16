import axios from "axios";

const client = axios.create({ baseURL: "http://localhost:8001", timeout: 120000 });

export const redApi = {
  health: () => client.get("/health").then(r => r.data),
  chat: (message: string, target: string) =>
    client.post("/chat", { message, target }).then(r => r.data),
  recon: (target: string, context?: string) =>
    client.post("/scan/recon", { target, context }).then(r => r.data),
  reconStatus: (sid: string) =>
    client.get(`/scan/recon/${sid}`).then(r => r.data),
  autoExploit: (target: string, recon_session_id: string) =>
    client.post("/exploit/auto", { target, recon_session_id }).then(r => r.data),
  exploitStatus: (eid: string) =>
    client.get(`/exploit/auto/${eid}`).then(r => r.data),
  downloadReport: (sid: string) =>
    client.get(`/report/download/${sid}`, { responseType: "blob" }).then(r => r.data),
  listReconSessions: () =>
    client.get("/scan/recon/sessions").then(r => r.data).catch(() => []),
};
