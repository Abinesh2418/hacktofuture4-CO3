import axios from "axios";

const client = axios.create({ baseURL: "http://localhost:8002", timeout: 120000 });

export const blueApi = {
  health: () => client.get("/health").then(r => r.data),
  ingestReport: (report: any) =>
    client.post("/remediate/ingest-report", report).then(r => r.data),
  runSample: () =>
    client.post("/remediate/run-sample").then(r => r.data),
  remediationStatus: () =>
    client.get("/remediate/status").then(r => r.data),
  pendingFixes: () =>
    client.get("/remediate/pending").then(r => r.data),
  approveFix: (fixId: string) =>
    client.post(`/remediate/approve/${fixId}`).then(r => r.data),
  approveAll: () =>
    client.post("/remediate/approve-all").then(r => r.data),
  rejectFix: (fixId: string) =>
    client.post(`/remediate/reject/${fixId}`).then(r => r.data),
  sshScan: (creds: { host: string; ssh_port: number; username: string; password: string }) =>
    client.post("/scan/ssh", creds).then(r => r.data),
  sshApplyFixes: () =>
    client.post("/scan/ssh/apply-fixes").then(r => r.data),
  // IDS
  idsStatus: () =>
    client.get("/ids/status").then(r => r.data),
  idsAlerts: (limit = 50) =>
    client.get(`/ids/alerts?limit=${limit}`).then(r => r.data),
  // SIEM
  siemReport: () =>
    client.get("/siem/report").then(r => r.data),
  siemStatus: () =>
    client.get("/siem/status").then(r => r.data),
};
