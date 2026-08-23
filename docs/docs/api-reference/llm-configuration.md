---
sidebar_position: 2
title: LLM Configuration
---

# LLM Configuration API

These endpoints manage the LLM provider configurations used for scans
and chat. Provider API keys are **Fernet-encrypted at rest** using the
installation's `ENCRYPTION_KEY`.

**Base URL:** `/api/v1/admin/llm-configs`

!!! danger "Permissions"

    All endpoints on this router require **Superuser** authentication.

## Pricing: estimates, catalog actuals, and versioned overrides

Pre-call token counting and estimates use LiteLLM's local model map.
Post-call actuals use provider-reported Pydantic AI usage and the
immutable request-aware usage ledger. The legacy
`input_cost_per_million` / `output_cost_per_million` fields remain a
text-only fallback when no versioned price override exists:

- **Leave them zero** (default) and SCCAP calls
  `litellm.cost_per_token(model=model_name, ...)` against the
  community-maintained model price map. Offline-pinnable with
  `LITELLM_LOCAL_MODEL_COST_MAP=True`.
- **Set both to non-zero** only for a simple text-token contract. Calls
  containing cache categories are marked unknown because two flat rates
  cannot represent those prices safely.
- **For negotiated or private pricing**, append a complete effective-dated
  version through `POST /{config_id}/price-overrides`. It must include all
  text, cache read/write, reasoning, audio, image, and provider-request
  categories. Zero is valid for a category explicitly priced at zero;
  omitted categories are rejected.

## Supported providers

| Provider | Type | Notes |
|---|---|---|
| `openai` | Native | GPT-4o, GPT-4o-mini, O-series |
| `anthropic` | Native | Claude Sonnet 4.5, Claude Opus 4 |
| `google` | Native | Gemini 1.5 / 2.0 Pro, Flash |
| `deepseek` | OpenAI-compatible | DeepSeek V4 Pro, Reasoner |
| `xai` | OpenAI-compatible | Grok-2, Grok-3 |
| `custom_openai` | OpenAI-compatible | **Any endpoint speaking OpenAI Chat Completions** |

The `custom_openai` provider accepts a `base_url` field and works with:

- **Self-hosted models**: vLLM, Ollama, LM Studio, TGI, LocalAI
- **Enterprise clouds**: Azure OpenAI, AWS Bedrock (via LiteLLM proxy), Google Vertex AI proxy
- **API gateways**: Groq, Together AI, OpenRouter, Fireworks, Anyscale

Example custom_openai payload:

```json
{
  "name": "vLLM Llama-3-70B",
  "provider": "custom_openai",
  "model_name": "meta-llama/Llama-3-70b",
  "base_url": "http://10.0.1.50:8000/v1",
  "api_key": "not-used-for-local"
}
```

See [Architecture → LLM Integration](../architecture/llm-integration.md)
for the full data flow.

## Create LLM Configuration

Creates a new LLM provider configuration. The provided API key will be encrypted at rest.

-   **Endpoint:** `POST /`
-   **Permissions:** Superuser
-   **Request Body:**

    ```json
    {
      "name": "OpenAI GPT-4o",
      "provider": "openai",
      "model_name": "gpt-4o",
      "api_key": "sk-..."
    }
    ```

-   **Response (`201 Created`):**

    ```json
    {
      "name": "OpenAI GPT-4o",
      "provider": "openai",
      "model_name": "gpt-4o",
      "id": "e4a2c9c0-a1b2-c3d4-e5f6-1234567890ab"
    }
    ```

## List LLM Configurations

Retrieves a list of all available LLM configurations. API keys are not included in the response.

-   **Endpoint:** `GET /`
-   **Permissions:** Superuser
-   **Response (`200 OK`):**

    ```json
    [
      {
        "name": "OpenAI GPT-4o",
        "provider": "openai",
        "model_name": "gpt-4o",
        "id": "e4a2c9c0-a1b2-c3d4-e5f6-1234567890ab"
      },
      {
        "name": "Google Gemini 1.5",
        "provider": "google",
        "model_name": "gemini-1.5-pro-latest",
        "id": "f8b7e6d5-c4b3-a2a1-b0c9-0987654321fe"
      }
    ]
    ```

## Append a Price Override Version

Closes the current active version and appends a complete immutable price set.
Existing usage events retain their original snapshot.

- **Endpoint:** `POST /{config_id}/price-overrides`
- **Permissions:** Superuser
- **Request body:** `rates` must contain exactly these categories:
  `uncached_input`, `cache_read_input`, `cache_write_input`, `input_audio`,
  `cache_audio_read`, `image_input`, `non_reasoning_output`,
  `reasoning_output`, `output_audio`, `image_output`, and `provider_request`.
  Token categories use `million_tokens`; `provider_request` uses
  `thousand_requests`. Each rate contains decimal `amount` and optional
  `modifier`.

## List Price Override History

- **Endpoint:** `GET /{config_id}/price-overrides`
- **Permissions:** Superuser
- **Response:** newest-first versions with `effective_from`, `effective_to`,
  source, currency, creator, and the complete rate set.

## Delete LLM Configuration

Deletes an LLM configuration by its unique ID.

-   **Endpoint:** `DELETE /{config_id}`
-   **Permissions:** Superuser
-   **URL Parameters:**
    -   `config_id` (string, UUID): The ID of the configuration to delete.
-   **Response:**
    -   `204 No Content`: If the deletion was successful.
    -   `404 Not Found`: If no configuration with the given ID exists.
