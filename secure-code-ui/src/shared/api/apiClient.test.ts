import { afterEach, describe, expect, it, vi } from "vitest";

import {
  getAuthBoundaryAction,
  setBrowserSessionEstablished,
  shouldRetryApiQuery,
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

  it("does not turn legacy tenant-entry denials into authentication expiry", () => {
    expect(
      getAuthBoundaryAction({
        response: {
          status: 403,
          data: { detail: "Tenant entry required." },
        },
      }),
    ).toBeNull();
    expect(
      getAuthBoundaryAction({
        response: {
          status: 403,
          data: { detail: "Tenant entry denied." },
        },
      }),
    ).toBeNull();
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
});
