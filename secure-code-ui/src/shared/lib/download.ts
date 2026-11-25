// secure-code-ui/src/shared/lib/download.ts
//
// File downloads that carry the session.
//
// A plain `<a href="/api/...">` download sends no Authorization header, so every one of these
// links returned 401 and the browser's download manager reported "unknown server error" — which
// reads like a broken server rather than a missing credential. The file is fetched through the
// same axios client as every other request, then handed to the browser as a blob.
//
// The filename comes from Content-Disposition when the server sets one, so the client does not
// have to guess (or duplicate) the naming rules.

import apiClient from "../api/apiClient";

export interface DownloadOptions {
  /** Path relative to the API base, e.g. `/pentest/runs/<id>/export?format=zip`. */
  path: string;
  /** Used when the server does not set Content-Disposition. */
  fallbackName: string;
}

function filenameFrom(disposition: string | undefined, fallback: string): string {
  if (!disposition) return fallback;
  // Handles both `filename="x.zip"` and RFC 5987 `filename*=UTF-8''x.zip`.
  const encoded = /filename\*=UTF-8''([^;]+)/i.exec(disposition);
  if (encoded) {
    try {
      return decodeURIComponent(encoded[1].trim());
    } catch {
      return fallback;
    }
  }
  const plain = /filename="?([^";]+)"?/i.exec(disposition);
  return plain ? plain[1].trim() : fallback;
}

function filenameFromPath(path: string, fallback: string): string {
  const match = /filename="?([^";]+)"?/i.exec(path);
  return match ? match[1] : fallback;
}

export async function downloadFile({ path, fallbackName }: DownloadOptions): Promise<void> {
  const response = await apiClient.get(path, { responseType: "blob" });
  const disposition = String(response.headers["content-disposition"] ?? "");
  const name = filenameFrom(disposition, filenameFromPath(path, fallbackName));

  const url = URL.createObjectURL(response.data as Blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Revoking immediately can cancel the download in Safari; a tick is enough.
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Read a failed download's blob body, so the error can name the server's reason. */
export async function downloadErrorMessage(error: unknown): Promise<string> {
  const candidate = error as { response?: { data?: unknown; status?: number } };
  const status = candidate.response?.status;
  const data = candidate.response?.data;
  if (data instanceof Blob) {
    try {
      const text = await data.text();
      try {
        const parsed = JSON.parse(text) as { detail?: string };
        if (parsed.detail) return parsed.detail;
      } catch {
        if (text.trim()) return text.slice(0, 200);
      }
    } catch {
      /* fall through to the status */
    }
  }
  return status ? `the server returned ${status}` : "the request failed";
}
