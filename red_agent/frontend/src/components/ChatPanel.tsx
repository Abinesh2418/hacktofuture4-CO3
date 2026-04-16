import { useState, useRef, useEffect, type CSSProperties, type KeyboardEvent } from "react";
import type { ChatMessage } from "@/types/red.types";
import { redApi } from "@/api/redApi";

interface ChatPanelProps {
  chatMessages: ChatMessage[];
  target: string;
  onNewMessage: (msg: ChatMessage) => void;
  onClear?: () => void;
  /** When rendered inside a modal that already has its own title bar. */
  hideHeader?: boolean;
}

function formatTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function ChatPanel({ chatMessages, target, onNewMessage, onClear, hideHeader = false }: ChatPanelProps) {
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const waitingForWs = useRef(false);
  const prevChatCount = useRef(chatMessages.length);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages]);

  // Unlock input when agent WS message arrives
  useEffect(() => {
    if (waitingForWs.current && chatMessages.length > prevChatCount.current) {
      const latest = chatMessages[chatMessages.length - 1];
      if (latest && latest.role === "agent") {
        waitingForWs.current = false;
        setSending(false);
      }
    }
    prevChatCount.current = chatMessages.length;
  }, [chatMessages]);

  const handleSend = async () => {
    const text = input.trim();
    if (!text || sending) return;

    onNewMessage({
      id: crypto.randomUUID(),
      role: "user",
      content: text,
      timestamp: new Date().toISOString(),
    });
    setInput("");
    setSending(true);

    try {
      const response = await redApi.chat({ message: text, target });
      if (response.content) {
        onNewMessage(response);
        setSending(false);
        waitingForWs.current = false;
      } else {
        waitingForWs.current = true;
        setTimeout(() => {
          if (waitingForWs.current) { waitingForWs.current = false; setSending(false); }
        }, 30000);
      }
    } catch {
      setSending(false);
      waitingForWs.current = false;
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); }
  };

  return (
    <div style={container}>
      {/* Header */}
      {!hideHeader && (
        <div style={header}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={headerDot} />
            <span style={headerTitle}>OPERATOR TERMINAL</span>
          </div>
          <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-ui)" }}>
            {chatMessages.length} messages
            {chatMessages.length > 0 && onClear && (
              <button onClick={onClear} style={{
                fontSize: 8, fontWeight: 700, fontFamily: "var(--font-display)",
                padding: "2px 8px", borderRadius: 3, border: "1px solid var(--red)",
                background: "transparent", color: "var(--red)", cursor: "pointer",
                letterSpacing: 1, marginLeft: 6,
              }}>CLEAR</button>
            )}
          </span>
        </div>
      )}

      {/* Messages */}
      <div style={messageArea}>
        {chatMessages.length === 0 && (
          <div style={emptyState}>
            <div style={{ fontSize: 40, marginBottom: 16, opacity: 0.3 }}>&#9760;</div>
            <div style={{ fontSize: 14, color: "var(--accent)", fontFamily: "var(--font-display)", letterSpacing: 2, marginBottom: 8 }}>
              AWAITING ORDERS
            </div>
            <div style={{ fontSize: 11, color: "var(--text-dim)", lineHeight: 1.8 }}>
              Type "attack &lt;target&gt;" to start a mission<br />
              or ask about capabilities
            </div>
          </div>
        )}

        {chatMessages.map((msg) => {
          const isUser = msg.role === "user";
          return (
            <div
              key={msg.id}
              className={isUser ? "anim-slide-left" : "anim-slide-right"}
              style={{ display: "flex", flexDirection: "column", alignItems: isUser ? "flex-end" : "flex-start" }}
            >
              {/* Label */}
              <div style={{
                fontSize: 9, fontWeight: 700, letterSpacing: 1.5, marginBottom: 4,
                fontFamily: "var(--font-ui)",
                color: isUser ? "var(--cyan)" : "var(--red)",
              }}>
                {isUser ? "OPERATOR" : "RED ARSENAL"}
                <span style={{ color: "var(--text-dim)", fontWeight: 400, marginLeft: 8 }}>
                  {formatTime(msg.timestamp)}
                </span>
              </div>
              {/* Bubble */}
              <div style={{
                ...bubble,
                background: isUser ? "var(--cyan-dim)" : "var(--bg-card)",
                borderColor: isUser ? "rgba(0,229,255,0.2)" : "var(--accent-border)",
                borderLeftWidth: isUser ? 1 : 3,
                borderRightWidth: isUser ? 3 : 1,
                borderLeftColor: isUser ? "rgba(0,229,255,0.2)" : "var(--accent)",
                borderRightColor: isUser ? "var(--cyan)" : "var(--accent-border)",
              }}>
                {msg.content}
              </div>
            </div>
          );
        })}

        {sending && (
          <div className="anim-slide-right" style={thinkingBox}>
            <div style={thinkingDots}>
              <span className="anim-pulse" style={{ ...dot, animationDelay: "0s" }} />
              <span className="anim-pulse" style={{ ...dot, animationDelay: "0.2s" }} />
              <span className="anim-pulse" style={{ ...dot, animationDelay: "0.4s" }} />
            </div>
            <span style={{ fontSize: 10, color: "var(--text-dim)" }}>analyzing...</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div style={inputArea}>
        <div style={{
          ...inputBox,
          borderColor: sending ? "var(--yellow-dim)" : "var(--accent-border)",
        }}>
          <span style={{ color: "var(--accent)", fontSize: 14 }}>&#8827;</span>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={sending ? "waiting for response..." : "enter command..."}
            rows={1}
            disabled={sending}
            style={{ ...inputField, opacity: sending ? 0.4 : 1 }}
          />
          <button
            onClick={handleSend}
            disabled={sending || !input.trim()}
            style={{
              ...sendBtn,
              opacity: sending || !input.trim() ? 0.3 : 1,
              cursor: sending || !input.trim() ? "default" : "pointer",
            }}
          >
            {sending ? "..." : "EXEC"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── Styles ── */
const container: CSSProperties = {
  display: "flex", flexDirection: "column", height: "100%",
  background: "var(--bg-primary)", borderRadius: "var(--radius)",
  border: "1px solid var(--accent-border)", overflow: "hidden",
};
const header: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "10px 14px", borderBottom: "1px solid var(--accent-border)",
  background: "var(--bg-secondary)",
};
const headerDot: CSSProperties = {
  width: 8, height: 8, borderRadius: "50%", background: "var(--accent)",
  boxShadow: "0 0 8px var(--accent-glow)",
};
const headerTitle: CSSProperties = {
  fontSize: 12, fontWeight: 700, letterSpacing: 2,
  fontFamily: "var(--font-display)", color: "var(--text-primary)",
};
const messageArea: CSSProperties = {
  flex: 1, overflowY: "auto", padding: 14,
  display: "flex", flexDirection: "column", gap: 12,
};
const emptyState: CSSProperties = {
  textAlign: "center", marginTop: 80,
};
const bubble: CSSProperties = {
  padding: "10px 14px", borderRadius: 6, maxWidth: "88%",
  fontSize: 13, lineHeight: 1.7, whiteSpace: "pre-wrap", wordBreak: "break-word",
  fontFamily: "var(--font-mono)", border: "1px solid",
  color: "var(--text-primary)",
};
const thinkingBox: CSSProperties = {
  display: "flex", alignItems: "center", gap: 10, padding: "8px 14px",
};
const thinkingDots: CSSProperties = {
  display: "flex", gap: 4,
};
const dot: CSSProperties = {
  width: 5, height: 5, borderRadius: "50%", background: "var(--accent)",
};
const inputArea: CSSProperties = {
  padding: "10px 14px", borderTop: "1px solid var(--accent-border)",
  background: "var(--bg-secondary)",
};
const inputBox: CSSProperties = {
  display: "flex", alignItems: "center", gap: 10,
  background: "var(--bg-void)", borderRadius: 6,
  border: "1px solid", padding: "8px 12px",
  transition: "border-color var(--transition)",
};
const inputField: CSSProperties = {
  flex: 1, background: "transparent", border: "none", outline: "none",
  color: "var(--text-primary)", fontFamily: "var(--font-mono)",
  fontSize: 13, resize: "none", lineHeight: 1.5,
};
const sendBtn: CSSProperties = {
  background: "var(--accent)", color: "#fff", border: "none", borderRadius: 4,
  padding: "5px 14px", fontSize: 10, fontWeight: 800, letterSpacing: 2,
  fontFamily: "var(--font-display)", transition: "opacity var(--transition)",
};
