// Small copy-to-clipboard button — copies `value` and briefly flips to
// a checkmark. Icon-only by default; pass `label` for a labelled
// variant. Used for scan IDs, code blocks, and diff blocks.

import React, { useState } from "react";

import { Icon } from "./Icon";

interface CopyButtonProps {
  /** The text written to the clipboard. */
  value: string;
  /** Tooltip / aria-label. */
  title?: string;
  /** When set, a text label sits next to the icon. */
  label?: string;
  size?: number;
}

export const CopyButton: React.FC<CopyButtonProps> = ({
  value,
  title = "Copy",
  label,
  size = 12,
}) => {
  const [copied, setCopied] = useState(false);

  const copy = async (e: React.MouseEvent) => {
    // Stop the click bubbling — these buttons sit inside clickable
    // rows / cards.
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Fallback for non-secure contexts where the Clipboard API is
      // unavailable.
      const ta = document.createElement("textarea");
      ta.value = value;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
      } catch {
        /* ignore */
      }
      document.body.removeChild(ta);
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      type="button"
      className="sccap-btn sccap-btn-sm sccap-btn-ghost"
      onClick={copy}
      title={title}
      aria-label={title}
      style={{ gap: 5 }}
    >
      {copied ? <Icon.Check size={size} /> : <Icon.Copy size={size} />}
      {label ? <span>{copied ? "Copied" : label}</span> : null}
    </button>
  );
};

export default CopyButton;
