import { useState, type CSSProperties } from "react";
import { Link, useNavigate } from "react-router-dom";
import { authApi } from "@/api/authApi";

export function RegisterPage() {
  const nav = useNavigate();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !email || !password) { setError("All fields required"); return; }
    if (username.length < 3) { setError("Username must be 3+ characters"); return; }
    if (!email.includes("@")) { setError("Invalid email"); return; }
    if (password.length < 6) { setError("Password must be 6+ characters"); return; }
    if (password !== confirm) { setError("Passwords don't match"); return; }

    setLoading(true); setError("");
    try {
      const res = await authApi.register(username, email, password);
      // Store MFA setup data and redirect to MFA setup page
      sessionStorage.setItem("mfa_qr", res.qr_code);
      sessionStorage.setItem("mfa_secret", res.totp_secret);
      sessionStorage.setItem("mfa_user", username);
      nav("/mfa-setup");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Registration failed");
    } finally { setLoading(false); }
  };

  return (
    <div className="has-scanline grid-bg" style={page}>
      <div style={card}>
        <div style={logoRow}>
          <div style={logoBadge}>&#9760;</div>
          <div>
            <div style={title}>REGISTER</div>
            <div style={subtitle}>CREATE OPERATOR ACCOUNT</div>
          </div>
        </div>

        <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={fl}>USERNAME</div>
          <input value={username} onChange={e => setUsername(e.target.value)} placeholder="callsign" style={inp} autoFocus />

          <div style={fl}>EMAIL</div>
          <input value={email} onChange={e => setEmail(e.target.value)} placeholder="operator@htf.io" style={inp} />

          <div style={fl}>PASSWORD</div>
          <input value={password} onChange={e => setPassword(e.target.value)} type="password" placeholder="min 6 chars" style={inp} />

          <div style={fl}>CONFIRM PASSWORD</div>
          <input value={confirm} onChange={e => setConfirm(e.target.value)} type="password" placeholder="confirm" style={inp} />

          {error && <div style={{ color: "var(--red)", fontSize: 11 }}>{error}</div>}

          <button type="submit" disabled={loading} style={btn}>
            {loading ? "CREATING..." : "CREATE ACCOUNT"}
          </button>
        </form>

        <div style={{ textAlign: "center", marginTop: 14 }}>
          <Link to="/login" style={link}>ALREADY REGISTERED? LOGIN</Link>
        </div>
      </div>
    </div>
  );
}

const page: CSSProperties = { height: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-void)" };
const card: CSSProperties = { background: "var(--bg-card)", border: "1px solid var(--accent-border)", borderRadius: 12, padding: "28px 36px", width: 380, boxShadow: "0 0 60px var(--accent-dim)" };
const logoRow: CSSProperties = { display: "flex", alignItems: "center", gap: 12, marginBottom: 24 };
const logoBadge: CSSProperties = { width: 40, height: 40, borderRadius: 8, background: "var(--accent-dim)", border: "1px solid var(--accent-border)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, color: "var(--accent)" };
const title: CSSProperties = { fontSize: 18, fontWeight: 900, color: "var(--accent)", fontFamily: "var(--font-display)", letterSpacing: 4 };
const subtitle: CSSProperties = { fontSize: 8, color: "var(--text-dim)", letterSpacing: 3, fontFamily: "var(--font-ui)" };
const fl: CSSProperties = { fontSize: 9, fontWeight: 700, letterSpacing: 2, color: "var(--text-dim)", fontFamily: "var(--font-ui)" };
const inp: CSSProperties = { background: "var(--bg-input)", border: "1px solid var(--accent-border)", borderRadius: 6, padding: "10px 14px", color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: 13, outline: "none" };
const btn: CSSProperties = { background: "var(--accent)", color: "var(--bg-void)", border: "none", borderRadius: 6, padding: "12px 0", fontWeight: 800, fontSize: 13, cursor: "pointer", fontFamily: "var(--font-display)", letterSpacing: 3, marginTop: 4 };
const link: CSSProperties = { color: "var(--accent-bright)", fontSize: 10, letterSpacing: 2, fontFamily: "var(--font-ui)", textDecoration: "none" };
