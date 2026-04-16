import axios from "axios";

const BASE = "http://localhost:8003";
const client = axios.create({ baseURL: BASE, timeout: 15000 });

export const authApi = {
  register: (username: string, email: string, password: string) =>
    client.post("/auth/register", { username, email, password }).then(r => r.data),

  verifyMfaSetup: (username: string, totp_code: string) =>
    client.post("/auth/verify-mfa-setup", { username, totp_code }).then(r => r.data),

  login: (username: string, password: string, totp_code: string) =>
    client.post("/auth/login", { username, password, totp_code }).then(r => r.data),

  scores: () => client.get("/scores").then(r => r.data),
  leaderboard: () => client.get("/scores/leaderboard").then(r => r.data),
  awardPoints: (team: "red" | "blue", points: number, reason: string) =>
    client.post("/scores/award", { team, points, reason }).then(r => r.data),
};
