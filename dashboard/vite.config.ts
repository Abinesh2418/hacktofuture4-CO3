import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": resolve(__dirname, "src") } },
  server: {
    port: 5173,
    proxy: {
      "/api/red": { target: "http://localhost:8001", rewrite: (p) => p.replace(/^\/api\/red/, "") },
      "/api/blue": { target: "http://localhost:8002", rewrite: (p) => p.replace(/^\/api\/blue/, "") },
      "/api/auth": { target: "http://localhost:8003", rewrite: (p) => p.replace(/^\/api\/auth/, "") },
      "/ws/red": { target: "ws://localhost:8001", ws: true },
      "/ws/blue": { target: "ws://localhost:8002", ws: true },
    },
  },
});
