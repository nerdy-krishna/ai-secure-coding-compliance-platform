// secure-code-ui/src/shared/api/llmConfigService.ts
import {
  type LLMConfiguration,
  type LLMConfigurationCreate,
  type LLMInteractionResponse,
} from "../types/api";
import apiClient from "./apiClient";

// Use Partial to make all fields optional for the update payload
export type LLMConfigurationUpdate = Partial<Omit<LLMConfigurationCreate, 'api_key'>> & { api_key?: string };

// V02.2.1: UUID format guard — rejects any configId that is not a canonical UUID v4.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function assertUuid(id: string): void {
  if (!UUID_RE.test(id)) {
    throw new Error('Invalid LLM config');
  }
}

// V02.2.1: Runtime validation for LLMConfigurationCreate fields.
function validateCreatePayload(data: LLMConfigurationCreate): void {
  if (typeof data.name !== 'string' || data.name.length === 0 || data.name.length > 100) {
    throw new Error('Invalid LLM config');
  }
  if (typeof data.provider !== 'string' || data.provider.length === 0 || data.provider.length > 100) {
    throw new Error('Invalid LLM config');
  }
  if (typeof data.model_name !== 'string' || data.model_name.length === 0 || data.model_name.length > 100) {
    throw new Error('Invalid LLM config');
  }
  if (data.api_key !== undefined && (typeof data.api_key !== 'string' || data.api_key.length > 4096)) {
    throw new Error('Invalid LLM config');
  }
  if (data.input_cost_per_million !== undefined && (!Number.isFinite(data.input_cost_per_million) || data.input_cost_per_million < 0)) {
    throw new Error('Invalid LLM config');
  }
  if (data.output_cost_per_million !== undefined && (!Number.isFinite(data.output_cost_per_million) || data.output_cost_per_million < 0)) {
    throw new Error('Invalid LLM config');
  }
  for (const value of [data.requests_per_minute, data.tokens_per_minute, data.max_prompt_tokens]) {
    if (value !== undefined && value !== null && (!Number.isInteger(value) || value <= 0)) {
      throw new Error('Invalid LLM config');
    }
  }
}

// V02.2.1: Runtime validation for LLMConfigurationUpdate fields.
function validateUpdatePayload(data: LLMConfigurationUpdate): void {
  if (data.name !== undefined && (typeof data.name !== 'string' || data.name.length === 0 || data.name.length > 100)) {
    throw new Error('Invalid LLM config');
  }
  if (data.provider !== undefined && (typeof data.provider !== 'string' || data.provider.length === 0 || data.provider.length > 100)) {
    throw new Error('Invalid LLM config');
  }
  if (data.model_name !== undefined && (typeof data.model_name !== 'string' || data.model_name.length === 0 || data.model_name.length > 100)) {
    throw new Error('Invalid LLM config');
  }
  if (data.api_key !== undefined && (typeof data.api_key !== 'string' || data.api_key.length > 4096)) {
    throw new Error('Invalid LLM config');
  }
  if (data.input_cost_per_million !== undefined && (!Number.isFinite(data.input_cost_per_million) || data.input_cost_per_million < 0)) {
    throw new Error('Invalid LLM config');
  }
  if (data.output_cost_per_million !== undefined && (!Number.isFinite(data.output_cost_per_million) || data.output_cost_per_million < 0)) {
    throw new Error('Invalid LLM config');
  }
  for (const value of [data.requests_per_minute, data.tokens_per_minute, data.max_prompt_tokens]) {
    if (value !== undefined && value !== null && (!Number.isInteger(value) || value <= 0)) {
      throw new Error('Invalid LLM config');
    }
  }
}

export const llmConfigService = {
  /**
   * Fetches all available LLM configurations.
   */
  getLlmConfigs: async (): Promise<LLMConfiguration[]> => {
    const response = await apiClient.get<LLMConfiguration[]>(
      "/admin/llm-configs/",
    );
    return response.data;
  },

  /**
   * Creates a new LLM provider configuration.
   */
  createLlmConfig: async (
    configData: LLMConfigurationCreate,
  ): Promise<LLMConfiguration> => {
    // V02.2.1: Validate all fields before submitting.
    validateCreatePayload(configData);

    // V15.3.3: Explicitly construct payload (defense-in-depth alongside backend mass-assignment guards).
    const payload: LLMConfigurationCreate = {
      name: configData.name,
      provider: configData.provider,
      model_name: configData.model_name,
      api_key: configData.api_key,
      input_cost_per_million: configData.input_cost_per_million,
      output_cost_per_million: configData.output_cost_per_million,
      requests_per_minute: configData.requests_per_minute,
      tokens_per_minute: configData.tokens_per_minute,
      max_prompt_tokens: configData.max_prompt_tokens,
    };

    const response = await apiClient.post<LLMConfiguration>(
      "/admin/llm-configs/",
      payload,
    );
    return response.data;
  },

  /**
   * (NEW) Updates an existing LLM configuration.
   * @param configId The ID of the configuration to update.
   * @param configData The data to update. API key is optional.
   */
  updateLlmConfig: async (
    configId: string,
    configData: LLMConfigurationUpdate,
  ): Promise<LLMConfiguration> => {
    // V02.2.1: Reject non-UUID config IDs before any network call.
    assertUuid(configId);

    // V02.2.1: Validate all provided fields before submitting.
    validateUpdatePayload(configData);

    // V15.3.3: Explicitly construct payload (defense-in-depth alongside backend mass-assignment guards).
    const payload: LLMConfigurationUpdate = {};
    if (configData.name !== undefined) payload.name = configData.name;
    if (configData.provider !== undefined) payload.provider = configData.provider;
    if (configData.model_name !== undefined) payload.model_name = configData.model_name;
    if (configData.api_key !== undefined) payload.api_key = configData.api_key;
    if (configData.input_cost_per_million !== undefined) payload.input_cost_per_million = configData.input_cost_per_million;
    if (configData.output_cost_per_million !== undefined) payload.output_cost_per_million = configData.output_cost_per_million;
    if (configData.requests_per_minute !== undefined) payload.requests_per_minute = configData.requests_per_minute;
    if (configData.tokens_per_minute !== undefined) payload.tokens_per_minute = configData.tokens_per_minute;
    if (configData.max_prompt_tokens !== undefined) payload.max_prompt_tokens = configData.max_prompt_tokens;

    // V01.2.2: encodeURIComponent prevents URL path manipulation via configId metacharacters.
    const response = await apiClient.patch<LLMConfiguration>(
      `/admin/llm-configs/${encodeURIComponent(configId)}`,
      payload,
    );
    return response.data;
  },

  /**
   * Deletes an LLM configuration by its ID.
   */
  deleteLlmConfig: async (configId: string): Promise<void> => {
    // V02.2.1: Reject non-UUID config IDs before any network call.
    assertUuid(configId);

    // V01.2.2: encodeURIComponent prevents URL path manipulation via configId metacharacters.
    await apiClient.delete(`/admin/llm-configs/${encodeURIComponent(configId)}`);
  },

  getLlmInteractions: async (): Promise<LLMInteractionResponse[]> => {
    const response = await apiClient.get<LLMInteractionResponse[]>("/llm-interactions/");
    return response.data;
  },
};
