import { useState, type CSSProperties } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "@/App";
import { authApi } from "@/api/authApi";

export function LoginPage() {
  const { login } = useAuth();
  const nav = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password || !totp) { setError("All fields required"); return; }
    setLoading(true); setError("");
    try {
      const res = await authApi.login(username, password, totp);
      login(res.access_token, res.username);
      nav("/arena");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Login failed");
    } finally { setLoading(false); }
  };

  return (
    <div className="has-scanline grid-bg" style={page}>
      <div style={card}>
        <div style={logoRow}>
          <div style={logoBadge}>&#9760;</div>
          <div>
            <div style={title}>HTF ARENA</div>
            <div style={subtitle}>CYBERSECURITY BATTLEGROUND</div>
          </div>
        </div>

        <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={fieldLabel}>USERNAME</div>
          <input value={username} onChange={e => setUsername(e.target.value)} placeholder="operator" style={input} autoFocus />

          <div style={fieldLabel}>PASSWORD</div>
          <input value={password} onChange={e => setPassword(e.target.value)} type="password" placeholder="********" style={input} />

          <div style={fieldLabel}>MFA CODE</div>
          <input value={totp} onChange={e => setTotp(e.target.value)} placeholder="6-digit code" maxLength={6} style={{ ...input, letterSpacing: 8, textAlign: "center", fontSize: 20 }} />

          {error && <div style={{ color: "var(--red)", fontSize: 11 }}>{error}</div>}

          <button type="submit" disabled={loading} style={btn}>
            {loading ? "AUTHENTICATING..." : "ACCESS ARENA"}
          </button>
        </form>

        <div style={{ textAlign: "center", marginTop: 16 }}>
          <Link to="/register" style={link}>NEW OPERATOR? REGISTER</Link>
        </div>
      </div>
    </div>
  );
}

const page: CSSProperties = { height: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-void)" };
const card: CSSProperties = { background: "var(--bg-card)", border: "1px solid var(--accent-border)", borderRadius: 12, padding: "32px 36px", width: 380, boxShadow: "0 0 60px var(--accent-dim)" };
const logoRow: CSSProperties = { display: "flex", alignItems: "center", gap: 12, marginBottom: 28 };
const logoBadge: CSSProperties = { width: 40, height: 40, borderRadius: 8, background: "var(--accent-dim)", border: "1px solid var(--accent-border)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, color: "var(--accent)" };
const title: CSSProperties = { fontSize: 20, fontWeight: 900, color: "var(--accent)", fontFamily: "var(--font-display)", letterSpacing: 4 };
const subtitle: CSSProperties = { fontSize: 8, color: "var(--text-dim)", letterSpacing: 3, fontFamily: "var(--font-ui)" };
const fieldLabel: CSSProperties = { fontSize: 9, fontWeight: 700, letterSpacing: 2, color: "var(--text-dim)", fontFamily: "var(--font-ui)" };
const input: CSSProperties = { background: "var(--bg-input)", border: "1px solid var(--accent-border)", borderRadius: 6, padding: "10px 14px", color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: 13, outline: "none" };
const btn: CSSProperties = { background: "var(--accent)", color: "var(--bg-void)", border: "none", borderRadius: 6, padding: "12px 0", fontWeight: 800, fontSize: 13, cursor: "pointer", fontFamily: "var(--font-display)", letterSpacing: 3, marginTop: 8 };
const link: CSSProperties = { color: "var(--accent-bright)", fontSize: 10, letterSpacing: 2, fontFamily: "var(--font-ui)", textDecoration: "none" };
