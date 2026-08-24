// secure-code-ui/src/shared/ui/Modal.tsx
//
// Modal primitive used by SCCAP admin/settings pages. It owns initial focus,
// traps Tab within the active dialog, closes on Escape, and restores focus to
// the invoker so every consumer gets the same keyboard contract.

import React, { useEffect, useId, useRef } from "react";
import { Icon } from "./Icon";

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  width?: number | string;
}

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  children,
  footer,
  width = 520,
}) => {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement | null>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    returnFocusRef.current = document.activeElement as HTMLElement | null;
    const panel = panelRef.current;
    const focusable = () =>
      Array.from(
        panel?.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ) ?? [],
      ).filter((element) => !element.hasAttribute("hidden"));
    window.requestAnimationFrame(() => (focusable()[0] ?? panel)?.focus());
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key !== "Tab") return;
      const elements = focusable();
      if (elements.length === 0) {
        e.preventDefault();
        panel?.focus();
        return;
      }
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      returnFocusRef.current?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby={title !== undefined ? titleId : undefined}
      aria-label={title === undefined ? "Dialog" : undefined}
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0, 0, 0, 0.45)",
        display: "grid",
        placeItems: "center",
        zIndex: 1000,
        padding: 20,
        animation: "sccap-fade-in .15s var(--ease)",
      }}
    >
      <div
        ref={panelRef}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        className="surface"
        style={{
          width,
          maxWidth: "100%",
          maxHeight: "90vh",
          overflow: "auto",
          boxShadow: "var(--shadow-lg, 0 20px 40px rgba(0,0,0,.25))",
        }}
      >
        {title !== undefined && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              padding: "16px 20px",
              borderBottom: "1px solid var(--border)",
            }}
          >
            <div id={titleId} style={{ fontWeight: 600, color: "var(--fg)", fontSize: 15 }}>
              {title}
            </div>
            <button
              aria-label="Close"
              className="sccap-btn sccap-btn-ghost sccap-btn-icon"
              onClick={onClose}
            >
              <Icon.X size={14} />
            </button>
          </div>
        )}
        <div style={{ padding: 20 }}>{children}</div>
        {footer && (
          <div
            style={{
              borderTop: "1px solid var(--border)",
              padding: "12px 20px",
              display: "flex",
              justifyContent: "flex-end",
              gap: 8,
            }}
          >
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};

export default Modal;
