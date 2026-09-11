import { beforeEach, expect, it, vi } from "vitest";
import apiClient from "./apiClient";
import { llmConfigService } from "./llmConfigService";

vi.mock("./apiClient", () => ({
  default: { post: vi.fn(), patch: vi.fn() },
}));

beforeEach(() => {
  vi.mocked(apiClient.post).mockResolvedValue({ data: {} });
  vi.mocked(apiClient.patch).mockResolvedValue({ data: {} });
});

it("persists the custom endpoint and tokenizer on creation and editing", async () => {
  const config = {
    name: "OpenRouter",
    provider: "custom_openai" as const,
    model_name: "fixture/model",
    base_url: "https://openrouter.ai/api/v1",
    tokenizer: "cl100k_base",
    api_key: "synthetic-test-key",
  };
  await llmConfigService.createLlmConfig(config);
  expect(apiClient.post).toHaveBeenCalledWith(
    "/admin/llm-configs/", expect.objectContaining(config),
  );
  const update = { base_url: config.base_url, tokenizer: config.tokenizer };
  await llmConfigService.updateLlmConfig("c1f6940e-6209-4a22-b997-f572f6e182c8", update);
  expect(apiClient.patch).toHaveBeenCalledWith(
    "/admin/llm-configs/c1f6940e-6209-4a22-b997-f572f6e182c8", update,
  );
});
