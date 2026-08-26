import { describe, expect, it } from "vitest";

import {
  getAuthBoundaryAction,
  shouldRetryApiQuery,
} from "./apiClient";

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
});
