/* SCCAP Web Push service worker (#90 / PRD #83).
 *
 * Receives scan-completion pushes and shows a desktop notification —
 * even when the SCCAP tab is closed. The per-scan `tag` collapses this
 * against the in-page notification (#89) so a focused user sees one
 * popup. Clicking the notification focuses an existing SCCAP tab (or
 * opens one) at the scan's results URL.
 */

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = {};
  }
  const title = data.title || "SCCAP — Scan finished";
  event.waitUntil(
    self.registration.showNotification(title, {
      body: data.body || "A scan has finished.",
      tag: data.tag || "sccap-scan",
      data: { url: data.url || "/" },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url =
    (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clientList) => {
        for (const client of clientList) {
          if ("focus" in client) {
            client.focus();
            if ("navigate" in client) client.navigate(url);
            return undefined;
          }
        }
        return self.clients.openWindow(url);
      }),
  );
});
