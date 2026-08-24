import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { FindingGovernancePanel } from "./FindingGovernancePanel";

describe("FindingGovernancePanel", () => {
  it("shows evidence, attempt, predecessor, dataflow, and waiver controls", () => {
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <FindingGovernancePanel scanId="scan-1" findingId={12} initial={{
          id: "lineage-1", attempt_id: "attempt-1", finding_id: 12,
          predecessor_finding_id: 8, fingerprint: "a".repeat(64), baseline_state: "reintroduced",
          exact_ranges: [{ file_path: "src/app.py", start_line: 7, end_line: 8 }],
          dataflow: { cross_file_status: "confirmed" }, source_provenance: {}, producer_provenance: {},
          coverage_entry_ids: ["coverage-1"], evidence_object_ids: ["evidence-1"], remediation_state: {},
        }} />
      </QueryClientProvider>,
    );
    expect(html).toContain("attempt-1");
    expect(html).toContain("lineage-1");
    expect(html).toContain("evidence-1");
    expect(html).toContain("coverage-1");
    expect(html).toContain("Grant waiver");
    expect(html).toContain("src/app.py:7–8");
  });
});
