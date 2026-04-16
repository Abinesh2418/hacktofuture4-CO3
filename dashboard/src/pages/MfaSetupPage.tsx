import { useState, type CSSProperties } from "react";
import { useNavigate } from "react-router-dom";
import { authApi } from "@/api/authApi";

export function MfaSetupPage() {
  const nav = useNavigate();
  const qr = sessionStorage.getItem("mfa_qr") || "";
  const secret = sessionStorage.getItem("mfa_secret") || "";
  const username = sessionStorage.getItem("mfa_user") || "";
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const verify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (code.length !== 6) { setError("Enter 6-digit code"); return; }
    setLoading(true); setError("");
    try {
      await authApi.verifyMfaSetup(username, code);
      sessionStorage.clear();
      nav("/login");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Invalid code");
    } finally { setLoading(false); }
  };

  return (
    <div className="has-scanline grid-bg" style={page}>
      <div style={card}>
        <div style={title}>MFA SETUP</div>
        <div style={subtitle}>Scan QR with Google Authenticator / Authy</div>

        {qr && (
          <div style={{ textAlign: "center", margin: "20px 0", background: "#fff", borderRadius: 12, padding: 16, display: "inline-block" }}>
            <img src={`data:image/png;base64,${qr}`} alt="MFA QR" style={{ width: 200, height: 200 }} />
          </div>
        )}

        <div style={{ fontSize: 9, color: "var(--text-dim)", marginBottom: 12, wordBreak: "break-all" }}>
          Manual key: <span style={{ color: "var(--cyan)", fontFamily: "var(--font-mono)" }}>{secret}</span>
        </div>

        <form onSubmit={verify} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={fl}>ENTER VERIFICATION CODE</div>
          <input value={code} onChange={e => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} placeholder="000000"
            style={{ ...inp, letterSpacing: 10, textAlign: "center", fontSize: 24 }} autoFocus />

          {error && <div style={{ color: "var(--red)", fontSize: 11 }}>{error}</div>}

          <button type="submit" disabled={loading} style={btn}>
            {loading ? "VERIFYING..." : "VERIFY & ACTIVATE"}
          </button>
        </form>
      </div>
    </div>
  );
}

const page: CSSProperties = { height: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-void)" };
const card: CSSProperties = { background: "var(--bg-card)", border: "1px solid var(--accent-border)", borderRadius: 12, padding: "32px 36px", width: 400, boxShadow: "0 0 60px var(--accent-dim)", textAlign: "center" };
const title: CSSProperties = { fontSize: 20, fontWeight: 900, color: "var(--accent)", fontFamily: "var(--font-display)", letterSpacing: 4, marginBottom: 4 };
const subtitle: CSSProperties = { fontSize: 10, color: "var(--text-secondary)", letterSpacing: 2, fontFamily: "var(--font-ui)", marginBottom: 8 };
const fl: CSSProperties = { fontSize: 9, fontWeight: 700, letterSpacing: 2, color: "var(--text-dim)", fontFamily: "var(--font-ui)", textAlign: "left" };
const inp: CSSProperties = { background: "var(--bg-input)", border: "1px solid var(--accent-border)", borderRadius: 6, padding: "12px 14px", color: "var(--text-primary)", fontFamily: "var(--font-mono)", outline: "none" };
const btn: CSSProperties = { background: "var(--accent)", color: "var(--bg-void)", border: "none", borderRadius: 6, padding: "12px 0", fontWeight: 800, fontSize: 13, cursor: "pointer", fontFamily: "var(--font-display)", letterSpacing: 3 };
