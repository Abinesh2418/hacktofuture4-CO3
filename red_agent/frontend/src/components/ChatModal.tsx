import { useEffect, type CSSProperties } from "react";
import type { ChatMessage } from "@/types/red.types";
import { ChatPanel } from "./ChatPanel";

interface Props {
  open: boolean;
  chatMessages: ChatMessage[];
  target: string;
  onNewMessage: (msg: ChatMessage) => void;
  onClose: () => void;
  onClear?: () => void;
}

export function ChatModal({ open, chatMessages, target, onNewMessage, onClose, onClear }: Props) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div style={overlay} onClick={onClose}>
      <div
        style={frame}
        onClick={(e) => e.stopPropagation()}
        className="anim-slide-up"
      >
        <div style={frameHeader}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={headerDot} />
            <span style={titleText}>OPERATOR TERMINAL</span>
            <span style={subText}>EXPANDED · {chatMessages.length} messages</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {onClear && chatMessages.length > 0 && (
              <button onClick={onClear} style={clearBtn}>CLEAR</button>
            )}
            <button onClick={onClose} style={closeBtn} aria-label="Collapse terminal">
              &#10005; COLLAPSE
            </button>
          </div>
        </div>
        <div style={frameBody}>
          <ChatPanel
            chatMessages={chatMessages}
            target={target}
            onNewMessage={onNewMessage}
            onClear={onClear}
            hideHeader
          />
        </div>
      </div>
    </div>
  );
}

const overlay: CSSProperties = {
  position: "fixed", inset: 0, zIndex: 1000,
  background: "rgba(5, 5, 10, 0.85)", backdropFilter: "blur(4px)",
  display: "flex", alignItems: "center", justifyContent: "center", padding: 24,
};
const frame: CSSProperties = {
  width: "min(1100px, 90vw)", height: "min(820px, 90vh)",
  background: "var(--bg-primary)", border: "1px solid var(--accent)",
  borderRadius: 8, overflow: "hidden",
  boxShadow: "0 0 60px var(--accent-glow), 0 20px 80px rgba(0,0,0,0.6)",
  display: "flex", flexDirection: "column",
};
const frameHeader: CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "12px 18px", borderBottom: "1px solid var(--accent-border)",
  background: "var(--bg-secondary)",
};
const headerDot: CSSProperties = {
  width: 10, height: 10, borderRadius: "50%",
  background: "var(--accent)", boxShadow: "0 0 10px var(--accent-glow)",
};
const titleText: CSSProperties = {
  fontSize: 14, fontWeight: 800, letterSpacing: 3,
  fontFamily: "var(--font-display)", color: "var(--accent)",
};
const subText: CSSProperties = {
  fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-ui)",
  letterSpacing: 1,
};
const closeBtn: CSSProperties = {
  fontSize: 10, fontWeight: 800, fontFamily: "var(--font-display)",
  padding: "6px 14px", borderRadius: 4,
  border: "1px solid var(--red)", background: "transparent",
  color: "var(--red)", cursor: "pointer", letterSpacing: 1.5,
};
const clearBtn: CSSProperties = {
  fontSize: 9, fontWeight: 700, fontFamily: "var(--font-display)",
  padding: "5px 10px", borderRadius: 3,
  border: "1px solid var(--accent-border)", background: "transparent",
  color: "var(--text-dim)", cursor: "pointer", letterSpacing: 1,
};
const frameBody: CSSProperties = {
  flex: 1, minHeight: 0, padding: 6,
};
