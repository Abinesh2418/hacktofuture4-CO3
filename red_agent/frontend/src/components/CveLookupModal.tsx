import { useEffect, useState, type CSSProperties } from "react";
import { redApi, type CveSummary } from "@/api/redApi";

interface Props {
  open: boolean;
  onClose: () => void;
}

type Mode = "id" | "keyword";

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "var(--red)",
  HIGH: "var(--orange)",
  MEDIUM: "var(--yellow)",
  LOW: "var(--green)",
  UNKNOWN: "var(--text-dim)",
};

export function CveLookupModal({ open, onClose }: Props) {
  const [mode, setMode] = useState<Mode>("id");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<CveSummary[]>([]);
  const [meta, setMeta] = useState<{ total: number; api_key: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setResults([]);
    setMeta(null);
    setError(null);
    setLoading(false);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !loading) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, loading, onClose]);

  if (!open) return null;

  const handleSearch = async () => {
    const q = query.trim();
    if (!q || loading) return;
    setLoading(true);
    setError(null);
    setResults([]);
    setMeta(null);
    try {
      const data =
        mode === "id"
          ? await redApi.lookupCveById(q)
          : await redApi.searchCveByKeyword(q, 15);
      setResults(data.results);
      setMeta({ total: data.total, api_key: !!data.api_key_in_use });
    } catch (e: unknown) {
      const msg =
        (e as { response?: { data?: { detail?: string } } }).response?.data?.detail ??
        (e instanceof Error ? e.message : String(e));
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={overlay} onClick={() => !loading && onClose()}>
      <div
        style={frame}
        onClick={(e) => e.stopPropagation()}
        className="anim-slide-up"
      >
        <div style={header}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ color: "var(--orange)", fontSize: 18 }}>&#9888;</span>
            <div>
              <div style={titleText}>NEW CVE LOOKUP</div>
              <div style={subText}>queries the NVD database in real time</div>
            </div>
          </div>
          <button onClick={() => !loading && onClose()} style={closeBtn}>
            &#10005;
          </button>
        </div>

        <div style={body}>
          <div style={tabRow}>
            {(["id", "keyword"] as Mode[]).map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                style={tabBtn(mode === m)}
              >
                {m === "id" ? "BY CVE ID" : "BY KEYWORD"}
              </button>
            ))}
          </div>

          <div style={inputRow}>
            <span style={{ color: "var(--orange)", fontSize: 14 }}>&#8827;</span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              placeholder={
                mode === "id"
                  ? "CVE-2024-1234"
                  : "apache log4j, openssl, sqli, …"
              }
              style={inputField}
              autoFocus
            />
            <button
              onClick={handleSearch}
              disabled={!query.trim() || loading}
              style={searchBtn(!!query.trim() && !loading)}
            >
              {loading ? "FETCHING…" : "FETCH"}
            </button>
          </div>

          {error && <div style={errorBox}>{error}</div>}

          {meta && (
            <div style={metaRow}>
              <span>{meta.total} result{meta.total === 1 ? "" : "s"}</span>
              {!meta.api_key && (
                <span style={{ color: "var(--yellow)" }}>
                  · running anonymous (5 req / 30s) — set <code>NVD_API_KEY</code> in .env for 50 req / 30s
                </span>
              )}
            </div>
          )}

          <div style={resultsList}>
            {results.map((cve) => <CveCard key={cve.id} cve={cve} />)}
            {!loading && !error && meta?.total === 0 && (
              <div style={emptyState}>
                no CVEs matched — try a different ID or keyword
              </div>
            )}
            {!loading && results.length === 0 && !error && !meta && (
              <div style={emptyState}>
                enter a CVE ID or keyword and hit FETCH
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function CveCard({ cve }: { cve: CveSummary }) {
  const sevColor = SEVERITY_COLOR[cve.severity] ?? "var(--text-dim)";
  const [open, setOpen] = useState(false);
  return (
    <div style={cveCard}>
      <div style={cveHead} onClick={() => setOpen((v) => !v)}>
        <span style={{
          fontSize: 12, fontWeight: 800, fontFamily: "var(--font-display)",
          color: "var(--cyan)", letterSpacing: 1,
        }}>
          {cve.id}
        </span>
        <span style={{ ...sevPill, color: sevColor, borderColor: sevColor }}>
          {cve.severity}{cve.score != null ? ` · ${cve.score}` : ""}
        </span>
        <span style={{ flex: 1, fontSize: 11, color: "var(--text-secondary)",
                       overflow: "hidden", textOverflow: "ellipsis",
                       whiteSpace: "nowrap", marginLeft: 8 }}>
          {cve.description}
        </span>
        <span style={{ fontSize: 9, color: "var(--text-dim)" }}>
          {open ? "\u25B2" : "\u25BC"}
        </span>
      </div>
      {open && (
        <div style={cveBody}>
          <div style={{ fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55, marginBottom: 8 }}>
            {cve.description}
          </div>
          {cve.cwes.length > 0 && (
            <div style={metaLine}>
              <span style={metaLbl}>CWE</span>
              {cve.cwes.map((c) => <span key={c} style={chip}>{c}</span>)}
            </div>
          )}
          {cve.vector && (
            <div style={metaLine}>
              <span style={metaLbl}>VECTOR</span>
              <code style={{ fontSize: 10, color: "var(--green)", fontFamily: "var(--font-mono)" }}>
                {cve.vector}
              </code>
            </div>
          )}
          {cve.published && (
            <div style={metaLine}>
              <span style={metaLbl}>PUBLISHED</span>
              <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{cve.published}</span>
            </div>
          )}
          {cve.references.length > 0 && (
            <div style={{ marginTop: 6 }}>
              <span style={metaLbl}>REFERENCES</span>
              <div style={{ marginTop: 3 }}>
                {cve.references.map((u) => (
                  <a key={u} href={u} target="_blank" rel="noreferrer noopener"
                     style={refLink}>{u}</a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const overlay: CSSProperties = {
  position: "fixed", inset: 0, zIndex: 1000,
  background: "rgba(5, 5, 10, 0.85)", backdropFilter: "blur(4px)",
  display: "flex", alignItems: "center", justifyContent: "center", padding: 24,
};
const frame: CSSProperties = {
  width: "min(900px, 92vw)", maxHeight: "90vh",
  background: "var(--bg-primary)", border: "1px solid var(--orange)",
  borderRadius: 8, overflow: "hidden",
  boxShadow: "0 0 60px rgba(255, 159, 28, 0.2), 0 20px 80px rgba(0,0,0,0.6)",
  display: "flex", flexDirection: "column",
};
const header: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "14px 20px", borderBottom: "1px solid var(--accent-border)",
  background: "var(--bg-secondary)",
};
const titleText: CSSProperties = {
  fontSize: 16, fontWeight: 800, letterSpacing: 4,
  fontFamily: "var(--font-display)", color: "var(--orange)",
};
const subText: CSSProperties = {
  fontSize: 10, color: "var(--text-dim)", letterSpacing: 0.5,
  fontFamily: "var(--font-ui)", marginTop: 2,
};
const closeBtn: CSSProperties = {
  fontSize: 14, fontWeight: 700, padding: "4px 12px",
  border: "1px solid var(--accent-border)", borderRadius: 4,
  background: "transparent", color: "var(--text-dim)", cursor: "pointer",
};
const body: CSSProperties = {
  flex: 1, overflowY: "auto", padding: "16px 20px",
  display: "flex", flexDirection: "column", gap: 12,
};
const tabRow: CSSProperties = { display: "flex", gap: 6 };
const tabBtn = (active: boolean): CSSProperties => ({
  fontSize: 10, fontWeight: 800, letterSpacing: 1.5,
  fontFamily: "var(--font-display)", padding: "5px 12px",
  border: `1px solid ${active ? "var(--orange)" : "var(--accent-border)"}`,
  borderRadius: 4,
  background: active ? "rgba(255,159,28,0.12)" : "transparent",
  color: active ? "var(--orange)" : "var(--text-dim)",
  cursor: "pointer",
});
const inputRow: CSSProperties = {
  display: "flex", alignItems: "center", gap: 10,
  background: "var(--bg-void)", border: "1px solid var(--accent-border)",
  borderRadius: 6, padding: "10px 14px",
};
const inputField: CSSProperties = {
  flex: 1, background: "transparent", border: "none", outline: "none",
  color: "var(--cyan)", fontFamily: "var(--font-mono)", fontSize: 14,
};
const searchBtn = (enabled: boolean): CSSProperties => ({
  fontSize: 10, fontWeight: 800, letterSpacing: 1.5,
  fontFamily: "var(--font-display)", padding: "6px 14px", borderRadius: 4,
  border: `1px solid ${enabled ? "var(--orange)" : "var(--accent-border)"}`,
  background: enabled ? "var(--orange)" : "transparent",
  color: enabled ? "#000" : "var(--text-dim)",
  cursor: enabled ? "pointer" : "not-allowed",
});
const errorBox: CSSProperties = {
  padding: "8px 12px", borderRadius: 4,
  border: "1px solid var(--red)", background: "rgba(255,60,60,0.08)",
  color: "var(--red)", fontSize: 11, fontFamily: "var(--font-mono)",
};
const metaRow: CSSProperties = {
  display: "flex", gap: 6, fontSize: 10, color: "var(--text-dim)",
  fontFamily: "var(--font-ui)", flexWrap: "wrap",
};
const resultsList: CSSProperties = {
  display: "flex", flexDirection: "column", gap: 6,
};
const emptyState: CSSProperties = {
  textAlign: "center", padding: 24, color: "var(--text-dim)",
  fontSize: 11, fontFamily: "var(--font-mono)",
};
const cveCard: CSSProperties = {
  border: "1px solid var(--accent-border)", borderRadius: 4,
  background: "var(--bg-void)", overflow: "hidden",
};
const cveHead: CSSProperties = {
  display: "flex", alignItems: "center", gap: 8, padding: "8px 10px",
  cursor: "pointer",
};
const sevPill: CSSProperties = {
  fontSize: 9, fontWeight: 800, letterSpacing: 1,
  padding: "1px 6px", borderRadius: 3, border: "1px solid",
  fontFamily: "var(--font-display)",
};
const cveBody: CSSProperties = {
  padding: "10px 14px", borderTop: "1px solid var(--accent-dim)",
  background: "var(--bg-primary)",
};
const metaLine: CSSProperties = {
  display: "flex", alignItems: "center", gap: 6, marginTop: 4, flexWrap: "wrap",
};
const metaLbl: CSSProperties = {
  fontSize: 8, fontWeight: 700, letterSpacing: 1.5,
  color: "var(--text-dim)", fontFamily: "var(--font-display)", minWidth: 70,
};
const chip: CSSProperties = {
  fontSize: 10, padding: "1px 6px", borderRadius: 2,
  background: "rgba(255,159,28,0.1)", color: "var(--orange)",
  border: "1px solid var(--orange)", fontFamily: "var(--font-mono)",
};
const refLink: CSSProperties = {
  display: "block", fontSize: 10, color: "var(--cyan)",
  fontFamily: "var(--font-mono)", textDecoration: "none",
  padding: "2px 0", wordBreak: "break-all",
};
