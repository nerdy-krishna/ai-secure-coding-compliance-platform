import { describe, expect, it } from "vitest";

import {
  accountingLabel,
  budgetStateAt,
  usageCostLabel,
} from "./usagePresentation";

describe("usage center presentation contracts", () => {
  it("never displays an unknown price as zero", () => {
    expect(usageCostLabel(null)).toBe("Unknown");
    expect(accountingLabel("unknown")).toBe("Unknown price");
  });

  it("keeps reconciled usage visually distinct", () => {
    expect(accountingLabel("reconciled")).toBe("Reconciled");
    expect(accountingLabel("reconciled")).not.toBe(accountingLabel("exact"));
  });

  it("surfaces both near-limit threshold bands and exhaustion", () => {
    expect(budgetStateAt("79.99")).toBe("normal");
    expect(budgetStateAt("80.00")).toBe("warning");
    expect(budgetStateAt("95.00")).toBe("critical");
    expect(budgetStateAt("100.00")).toBe("exhausted");
  });
});
