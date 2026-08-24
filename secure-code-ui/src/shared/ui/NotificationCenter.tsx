import React, { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useNotifications } from "../hooks/useNotifications";
import { Icon } from "./Icon";
import { EmptyState } from "./AsyncState";

function relativeTime(ts: number): string {
  const diff = Date.now() - ts;
  if (diff < 60_000) return "just now";
  const m = Math.floor(diff / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const TYPE_COLOR: Record<string, string> = {
  success: "var(--success)",
  error: "var(--critical)",
  warning: "var(--medium)",
  info: "var(--primary)",
};

export const NotificationCenter: React.FC = () => {
  const { notifications, unreadCount, markAllRead, clearAll, markRead } =
    useNotifications();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("click", handler);
    return () => document.removeEventListener("click", handler);
  }, []);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  const handleOpen = () => {
    setOpen((o) => !o);
  };

  const handleClick = (id: string, href?: string) => {
    markRead(id);
    if (href) {
      setOpen(false);
      navigate(href);
    }
  };

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        className="sccap-btn sccap-btn-icon sccap-btn-ghost"
        onClick={handleOpen}
        title="Notifications"
        aria-label={unreadCount > 0 ? `Notifications, ${unreadCount} unread` : "Notifications"}
        aria-haspopup="dialog"
        aria-expanded={open}
        style={{ position: "relative" }}
      >
        <Icon.Bell size={16} />
        {unreadCount > 0 && (
          <span
            aria-hidden="true"
            style={{
              position: "absolute",
              top: 2,
              right: 2,
              minWidth: 14,
              height: 14,
              borderRadius: 999,
              background: "var(--critical)",
              color: "#fff",
              fontSize: 9,
              fontWeight: 700,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              lineHeight: 1,
              padding: "0 3px",
              pointerEvents: "none",
            }}
          >
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div
          className="surface fade-in"
          role="dialog"
          aria-label="Notifications"
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            right: 0,
            width: 320,
            maxHeight: 420,
            overflowY: "auto",
            padding: 0,
            boxShadow: "var(--shadow-md)",
            zIndex: 30,
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "10px 14px 8px",
              borderBottom: "1px solid var(--border)",
            }}
          >
            <span style={{ fontSize: 13, fontWeight: 600, color: "var(--fg)" }}>
              Notifications
            </span>
            <div style={{ display: "flex", gap: 4 }}>
              {unreadCount > 0 && (
                <button
                  className="sccap-btn sccap-btn-ghost"
                  onClick={markAllRead}
                  style={{ fontSize: 11, padding: "2px 8px" }}
                >
                  Mark all read
                </button>
              )}
              {notifications.length > 0 && (
                <button
                  className="sccap-btn sccap-btn-ghost"
                  onClick={clearAll}
                  style={{ fontSize: 11, padding: "2px 8px" }}
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          {notifications.length === 0 ? (
            <EmptyState
              title="No notifications yet"
              detail="Scan and budget activity will appear here."
              compact
            />
          ) : (
            <div>
              {notifications.map((n) => (
                <button
                  key={n.id}
                  onClick={() => handleClick(n.id, n.href)}
                  className="notification-row"
                  style={{
                    display: "flex",
                    width: "100%",
                    textAlign: "left",
                    gap: 10,
                    padding: "10px 14px",
                    border: "none",
                    borderBottom: "1px solid var(--border)",
                    borderRadius: 0,
                    cursor: n.href ? "pointer" : "default",
                    background: n.read ? "transparent" : "var(--primary-weak)",
                    transition: "background .1s",
                  }}
                  onMouseEnter={(e) => {
                    if (n.href)
                      e.currentTarget.style.background = "var(--bg-soft)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = n.read
                      ? "transparent"
                      : "var(--primary-weak)";
                  }}
                >
                  <div
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: "50%",
                      background: TYPE_COLOR[n.type] ?? "var(--fg-muted)",
                      marginTop: 5,
                      flexShrink: 0,
                    }}
                  />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: 12.5,
                        fontWeight: n.read ? 400 : 600,
                        color: "var(--fg)",
                        marginBottom: 2,
                      }}
                    >
                      {n.title}
                    </div>
                    {n.body && (
                      <div
                        style={{
                          fontSize: 11.5,
                          color: "var(--fg-muted)",
                          marginBottom: 2,
                        }}
                      >
                        {n.body}
                      </div>
                    )}
                    <div style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                      {relativeTime(n.timestamp)}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
