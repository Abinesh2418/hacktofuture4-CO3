import { useState } from "react";

interface Props {
  accent: string;
  onSubmit: (raw: string) => void;
  onRunSample: () => void;
  submitting: boolean;
}

const PLACEHOLDER = `Paste the Red Team report JSON here, for example:

{
  "target": "http://172.25.8.172:5000",
  "risk_score": 10.0,
  "recon": {
    "open_ports": [{"port": 5000, "service": "Flask"}],
    "tech_stack": {"language": "Python", "framework": "Flask", "database": "SQLite"},
    "vulnerabilities": [{
      "type": "sql_injection",
      "severity": "critical",
      "endpoint": "/login",
      "description": "SQL Injection on /login"
    }]
  },
  "exploit": {
    "database": {"type": "SQLite", "tables": ["users","products","secrets"]},
    "exfiltrated_data": [{
      "table": "users",
      "rows": [{"username":"admin","password":"sup3rs3cr3t","role":"admin"}],
      "has_plaintext_passwords": true
    }],
    "credentials_stolen": [{"username":"admin","role":"admin"}]
  },
  "recommendations": [
    {"severity":"critical","category":"sql_injection_fix","action":"parameterized_queries","description":"Use parameterized queries"},
    {"severity":"critical","category":"password_hashing","action":"hash_passwords","description":"Hash passwords with bcrypt"}
  ]
}`;

export function ReportInputPanel({ accent, onSubmit, onRunSample, submitting }: Props) {
  const [raw, setRaw] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);

  const handleSubmit = () => {
    setParseError(null);
    const text = raw.trim();
    if (!text) {
      setParseError("Paste a report first");
      return;
    }
    try {
      JSON.parse(text);
      onSubmit(text);
    } catch {
      setParseError("Invalid JSON — check the format and try again");
    }
  };

  return (
    <div
      style={{
        background: "#161b22",
        border: `1px solid ${accent}33`,
        borderRadius: 8,
        padding: 14,
        display: "flex",
        flexDirection: "column",
        gap: 10,
        overflow: "hidden",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0 }}>
        <h3 style={{ color: accent, margin: 0, fontSize: 13, letterSpacing: 1 }}>
          RED TEAM REPORT INPUT
        </h3>
        <span style={{ color: "#8b949e", fontSize: 10 }}>paste JSON or use sample</span>
      </div>

      <textarea
        value={raw}
        onChange={(e) => { setRaw(e.target.value); setParseError(null); }}
        placeholder={PLACEHOLDER}
        spellCheck={false}
        style={{
          flex: 1,
          minHeight: 0,
          background: "#0d1117",
          color: "#f0f6fc",
          border: `1px solid ${parseError ? "#f85149" : "#30363d"}`,
          borderRadius: 6,
          padding: 12,
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          fontSize: 11,
          lineHeight: 1.5,
          resize: "none",
          outline: "none",
          overflow: "auto",
        }}
      />

      {parseError && (
        <span style={{ color: "#f85149", fontSize: 11 }}>{parseError}</span>
      )}

      <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
        <button
          onClick={handleSubmit}
          disabled={submitting || !raw.trim()}
          style={{
            flex: 1,
            border: "none",
            padding: "9px 0",
            borderRadius: 6,
            fontWeight: 700,
            fontSize: 12,
            cursor: submitting ? "default" : "pointer",
            fontFamily: "inherit",
            letterSpacing: 1,
            background: submitting ? "#21262d" : accent,
            color: submitting ? "#8b949e" : "#0d1117",
          }}
        >
          {submitting ? "REMEDIATING..." : "SUBMIT REPORT & REMEDIATE"}
        </button>

        <button
          onClick={onRunSample}
          disabled={submitting}
          style={{
            border: `1px solid ${accent}55`,
            padding: "9px 14px",
            borderRadius: 6,
            fontWeight: 700,
            fontSize: 11,
            cursor: submitting ? "default" : "pointer",
            fontFamily: "inherit",
            letterSpacing: 1,
            background: "transparent",
            color: accent,
            whiteSpace: "nowrap",
          }}
        >
          RUN SAMPLE
        </button>
      </div>
    </div>
  );
}
