import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Permission } from "../../shared/lib/permissions";
import { ToastProvider } from "../../shared/ui/Toast";
import { RuleFoundryPanel } from "./RuleFoundryPanel";

describe("RuleFoundryPanel", () => {
  it("labels governance truth and permission-gates candidate creation", () => {
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <ToastProvider>
          <RuleFoundryPanel permissions={[Permission.ruleCandidateCreate]} />
        </ToastProvider>
      </QueryClientProvider>,
    );
    expect(html).toContain("Governed AI rule foundry");
    expect(html).toContain("server-measured quality");
    expect(html).toContain("KMS-signed rollout");
    expect(html).toContain("New candidate");
  });

  it("hides creator controls without the stable permission", () => {
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <ToastProvider><RuleFoundryPanel permissions={[]} /></ToastProvider>
      </QueryClientProvider>,
    );
    expect(html).not.toContain("New candidate");
  });
});
