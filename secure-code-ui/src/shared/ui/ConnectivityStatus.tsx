import React, { useEffect, useRef, useState } from "react";

type ConnectionState = "online" | "offline" | "reconnected";

function readConnectionState(): ConnectionState {
  return typeof navigator !== "undefined" && !navigator.onLine
    ? "offline"
    : "online";
}

/**
 * A single shell-level network status announcer. It deliberately does not
 * reload the page: active SSE consumers own their cursor-based reconnect and
 * keep their diagnostic history intact.
 */
export const ConnectivityStatus: React.FC = () => {
  const [state, setState] = useState<ConnectionState>(readConnectionState);
  const wasOffline = useRef(state === "offline");

  useEffect(() => {
    let clearReconnected: number | undefined;
    const offline = () => {
      wasOffline.current = true;
      setState("offline");
    };
    const online = () => {
      if (!wasOffline.current) return;
      wasOffline.current = false;
      setState("reconnected");
      clearReconnected = window.setTimeout(() => setState("online"), 4_000);
    };
    window.addEventListener("offline", offline);
    window.addEventListener("online", online);
    return () => {
      window.removeEventListener("offline", offline);
      window.removeEventListener("online", online);
      if (clearReconnected !== undefined) window.clearTimeout(clearReconnected);
    };
  }, []);

  if (state === "online") return null;

  return (
    <div
      className={`connectivity-banner connectivity-banner-${state}`}
      role={state === "offline" ? "alert" : "status"}
      aria-live={state === "offline" ? "assertive" : "polite"}
    >
      <strong>{state === "offline" ? "You’re offline." : "Connection restored."}</strong>{" "}
      {state === "offline"
        ? "Live updates will reconnect automatically; completed work remains available."
        : "Live updates are reconnecting from the last received event."}
    </div>
  );
};
