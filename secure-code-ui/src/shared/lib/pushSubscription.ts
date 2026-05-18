// Web Push subscription lifecycle (#90 / PRD #83).
//
// Registers the push service worker, subscribes the browser to Web
// Push using the server's VAPID public key, and persists the
// subscription server-side so the worker can deliver scan-completion
// notifications when the SCCAP tab is closed.
//
// All functions are best-effort and idempotent — a browser without
// service-worker / Push support, or a server with Web Push disabled,
// degrades silently to the in-app + tab-open desktop notifications.

import apiClient from "../api/apiClient";

const SW_URL = "/push-sw.js";

function urlBase64ToUint8Array(base64: string): Uint8Array {
  // The VAPID public key is base64url; the Push API wants a Uint8Array.
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  const normalized = (base64 + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(normalized);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function isSupported(): boolean {
  return (
    typeof navigator !== "undefined" &&
    "serviceWorker" in navigator &&
    typeof window !== "undefined" &&
    "PushManager" in window &&
    typeof Notification !== "undefined"
  );
}

/**
 * Ensure this browser is registered for scan-completion Web Push.
 *
 * No-op when: the browser lacks support, notification permission is
 * not granted, or the server has Web Push disabled (no VAPID key).
 * Safe to call repeatedly — an existing subscription is re-used and
 * just re-synced server-side.
 */
export async function ensureWebPushSubscription(): Promise<void> {
  try {
    if (!isSupported() || Notification.permission !== "granted") return;

    const res = await apiClient.get<{ public_key: string | null }>(
      "/push/vapid-public-key",
    );
    const vapidKey = res.data?.public_key;
    if (!vapidKey) return; // Web Push disabled server-side.

    const registration = await navigator.serviceWorker.register(SW_URL);
    let subscription = await registration.pushManager.getSubscription();
    if (!subscription) {
      subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(vapidKey),
      });
    }

    const json = subscription.toJSON();
    if (!json.endpoint || !json.keys) return;
    await apiClient.post("/push/subscriptions", {
      endpoint: json.endpoint,
      keys: { p256dh: json.keys.p256dh, auth: json.keys.auth },
    });
  } catch {
    // Best-effort — the in-app + tab-open notifications still work.
  }
}
