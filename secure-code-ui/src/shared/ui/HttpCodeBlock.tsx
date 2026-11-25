// secure-code-ui/src/shared/ui/HttpCodeBlock.tsx
//
// An HTTP exchange, rendered so it can be read and copied.
//
// The headers are aligned, the body is separated by a rule, and the copy button copies the whole
// exchange in the form a bug report expects. A plain <pre> is readable; this is also checkable,
// which is the point of keeping a receipt.

import { useState } from "react";
import { Icon } from "./Icon";

export interface HttpExchange {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string | null;
  status?: number | null;
  truncated?: boolean;
}

function renderHead(line: string, headers?: Record<string, string>): string {
  const rows = Object.entries(headers ?? {});
  const width = rows.reduce((max, [key]) => Math.max(max, key.length), 0);
  return [line, ...rows.map(([key, value]) => `${key.padEnd(width)}: ${value}`)].join("\n");
}

export function HttpCodeBlock({
  title,
  exchange,
  maxHeight = 260,
}: {
  title?: string;
  exchange: HttpExchange;
  maxHeight?: number;
}) {
  const [copied, setCopied] = useState(false);
  const text =
    renderHead(
      [exchange.method, exchange.url].filter(Boolean).join(" ") ||
        (exchange.status ? `HTTP ${exchange.status}` : ""),
      exchange.headers,
    ) + (exchange.body ? `\n\n${exchange.body}` : "");

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard unavailable; the text is still selectable */
    }
  };

  return (
    <div className="http-block">
      <div className="http-block-bar">
        {title && <span className="http-block-title">{title}</span>}
        {exchange.status != null && (
          <span className={`coverage-outcome is-${exchange.status < 400 ? "reported" : "needs_follow_up"}`}>
            {exchange.status}
          </span>
        )}
        {exchange.truncated && <span className="asset-muted">truncated</span>}
        <button className="console-tool" onClick={() => void copy()} title="Copy this exchange">
          {copied ? "copied" : <Icon.Copy size={12} />}
        </button>
      </div>
      <pre style={{ maxHeight }}>{text}</pre>
    </div>
  );
}

export default HttpCodeBlock;
