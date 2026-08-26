import { afterEach, describe, expect, it, vi } from "vitest";

import apiClient, {
  getAuthBoundaryAction,
  markTenantEntryEstablished,
  setBrowserSessionEstablished,
  shouldRetryApiQuery,
  TENANT_ENTRY_REQUIRED_EVENT,
} from "./apiClient";

afterEach(() => {
  setBrowserSessionEstablished(false);
  vi.unstubAllGlobals();
});

describe("API authentication boundary", () => {
  it("treats 401 as an expired browser session", () => {
    expect(
      getAuthBoundaryAction({ response: { status: 401, data: {} } }),
    ).toBe("session-expired");
  });

  it("distinguishes tenant entry from authentication expiry", () => {
    expect(
      getAuthBoundaryAction({
        response: {
          status: 403,
          data: { detail: "Tenant entry required." },
        },
      }),
    ).toBe("tenant-entry-required");
    expect(
      getAuthBoundaryAction({
        response: {
          status: 403,
          data: { detail: "Tenant entry denied." },
        },
      }),
    ).toBe("tenant-entry-required");
  });

  it("does not turn permission or CSRF denials into logout", () => {
    expect(
      getAuthBoundaryAction({
        response: { status: 403, data: { detail: "Permission denied." } },
      }),
    ).toBeNull();
    expect(
      getAuthBoundaryAction({
        response: {
          status: 403,
          data: { detail: "CSRF validation failed." },
        },
      }),
    ).toBeNull();
  });

  it("does not retry deterministic client errors", () => {
    expect(shouldRetryApiQuery(0, { response: { status: 401 } })).toBe(false);
    expect(shouldRetryApiQuery(0, { response: { status: 403 } })).toBe(false);
    expect(shouldRetryApiQuery(0, { response: { status: 422 } })).toBe(false);
    expect(shouldRetryApiQuery(0, { response: { status: 503 } })).toBe(true);
    expect(shouldRetryApiQuery(3, { response: { status: 503 } })).toBe(false);
  });

  it("does not let a stale tenant denial clear a newer entry grant", async () => {
    const dispatchEvent = vi.fn();
    vi.stubGlobal("window", { dispatchEvent });
    setBrowserSessionEstablished(true);

    const staleControl: { reject: (() => void) | null } = { reject: null };
    let markAdapterReady!: () => void;
    const adapterReady = new Promise<void>((resolve) => {
      markAdapterReady = resolve;
    });
    const staleRequest = apiClient.get("/tenant-scoped-resource", {
      adapter: (config) =>
        new Promise((_resolve, reject) => {
          staleControl.reject = () =>
            reject({
              config,
              response: {
                status: 403,
                data: { detail: "Tenant entry required." },
              },
            });
          markAdapterReady();
        }),
    });

    await adapterReady;
    markTenantEntryEstablished();
    staleControl.reject?.();
    await expect(staleRequest).rejects.toMatchObject({
      response: { status: 403 },
    });

    expect(dispatchEvent).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: TENANT_ENTRY_REQUIRED_EVENT }),
    );
  });
});
