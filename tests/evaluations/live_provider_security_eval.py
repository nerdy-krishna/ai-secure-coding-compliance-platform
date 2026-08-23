"""One-call, cost-bounded live-provider security evaluation.

This module is intentionally excluded from normal unit/integration discovery.
It calls the OpenAI Responses API only when the dedicated manual CI job is
enabled and an API key is supplied.
"""

from __future__ import annotations

import argparse
import json
import os
from decimal import Decimal
from typing import Any

import httpx
import litellm


_INSTRUCTIONS = (
    "Act as a SAST security reviewer. Analyze only the supplied code. "
    "Return the single most important vulnerability in the required schema."
)
_INPUT = """Review this Python code:

def find_user(cursor, user_id):
    query = "SELECT email FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    return cursor.fetchone()
"""
_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerable": {"type": "boolean"},
        "title": {"type": "string"},
        "cwe": {"type": "string"},
        "severity": {
            "type": "string",
            "enum": ["Critical", "High", "Medium", "Low", "Informational"],
        },
        "rationale": {"type": "string"},
    },
    "required": ["vulnerable", "title", "cwe", "severity", "rationale"],
    "additionalProperties": False,
}


def _settings() -> tuple[str, int, Decimal]:
    model = os.getenv("SCCAP_LIVE_PROVIDER_MODEL", "gpt-4o-mini").strip()
    max_output_tokens = int(os.getenv("SCCAP_LIVE_MAX_OUTPUT_TOKENS", "400"))
    max_cost_usd = Decimal(os.getenv("SCCAP_LIVE_MAX_COST_USD", "0.01"))
    if not model:
        raise ValueError("SCCAP_LIVE_PROVIDER_MODEL must not be empty")
    if not 128 <= max_output_tokens <= 512:
        raise ValueError("SCCAP_LIVE_MAX_OUTPUT_TOKENS must be between 128 and 512")
    if not Decimal("0") < max_cost_usd <= Decimal("0.05"):
        raise ValueError("SCCAP_LIVE_MAX_COST_USD must be > 0 and <= 0.05")
    return model, max_output_tokens, max_cost_usd


def _request(model: str, max_output_tokens: int) -> dict[str, Any]:
    return {
        "model": model,
        "instructions": _INSTRUCTIONS,
        "input": _INPUT,
        "max_output_tokens": max_output_tokens,
        "store": False,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "sccap_security_finding",
                "strict": True,
                "schema": _SCHEMA,
            }
        },
    }


def _cost(
    model: str, *, input_tokens: int, output_tokens: int
) -> tuple[Decimal, Decimal]:
    input_cost, output_cost = litellm.cost_per_token(
        model=model,
        prompt_tokens=input_tokens,
        completion_tokens=output_tokens,
        call_type="responses",
    )
    return Decimal(str(input_cost)), Decimal(str(output_cost))


def _preflight(model: str, max_output_tokens: int, max_cost_usd: Decimal) -> int:
    input_tokens = int(
        litellm.token_counter(model=model, text=f"{_INSTRUCTIONS}\n{_INPUT}")
    )
    input_cost, output_cost = _cost(
        model,
        input_tokens=input_tokens,
        output_tokens=max_output_tokens,
    )
    upper_bound = input_cost + output_cost
    if upper_bound > max_cost_usd:
        raise AssertionError(
            "live evaluation refused before calling the provider: "
            f"estimated upper bound ${upper_bound:.6f} exceeds "
            f"${max_cost_usd:.6f}"
        )
    return input_tokens


def _output_text(response: dict[str, Any]) -> str:
    chunks: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str):
                    chunks.append(text)
    if not chunks:
        raise AssertionError("provider response contained no output_text")
    return "".join(chunks)


def _assert_security_result(result: object) -> None:
    if not isinstance(result, dict):
        raise AssertionError("structured provider result is not an object")
    if set(result) != set(_SCHEMA["required"]):
        raise AssertionError(f"unexpected structured fields: {sorted(result)}")
    if result["vulnerable"] is not True:
        raise AssertionError("provider did not identify the vulnerable code")
    if str(result["cwe"]).upper() != "CWE-89":
        raise AssertionError(f"expected CWE-89, got {result['cwe']!r}")
    if result["severity"] not in {"Critical", "High", "Medium"}:
        raise AssertionError(f"unexpected SQL-injection severity: {result['severity']}")
    if not str(result["title"]).strip() or not str(result["rationale"]).strip():
        raise AssertionError("provider returned an empty title or rationale")


async def _run(*, dry_run: bool) -> None:
    model, max_output_tokens, max_cost_usd = _settings()
    estimated_input_tokens = _preflight(model, max_output_tokens, max_cost_usd)
    if dry_run:
        print(
            "live-provider request validated without network call: "
            f"model={model} input_tokens~{estimated_input_tokens} "
            f"max_output_tokens={max_output_tokens} max_cost_usd={max_cost_usd}"
        )
        return

    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is required when the live-provider job is enabled"
        )
    api_url = os.getenv(
        "SCCAP_LIVE_PROVIDER_URL", "https://api.openai.com/v1/responses"
    )
    async with httpx.AsyncClient(timeout=90.0) as client:
        response = await client.post(
            api_url,
            headers={"Authorization": f"Bearer {api_key}"},
            json=_request(model, max_output_tokens),
        )
    if response.status_code != 200:
        raise AssertionError(
            f"live provider returned HTTP {response.status_code}: "
            f"{response.text[:500]}"
        )
    payload = response.json()
    if payload.get("status") != "completed":
        raise AssertionError(
            f"live provider did not complete: status={payload.get('status')!r} "
            f"incomplete_details={payload.get('incomplete_details')!r}"
        )
    _assert_security_result(json.loads(_output_text(payload)))

    usage = payload.get("usage") or {}
    input_tokens = int(usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("output_tokens") or 0)
    if output_tokens > max_output_tokens:
        raise AssertionError("provider exceeded the requested output-token ceiling")
    input_cost, output_cost = _cost(
        model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
    actual_cost = input_cost + output_cost
    if actual_cost > max_cost_usd:
        raise AssertionError(
            f"provider call cost ${actual_cost:.6f} exceeded ${max_cost_usd:.6f}"
        )
    print(
        "live provider identified CWE-89 within budget: "
        f"model={model} input_tokens={input_tokens} output_tokens={output_tokens} "
        f"estimated_cost_usd={actual_cost:.6f}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate schema and cost preflight without calling a provider",
    )
    args = parser.parse_args()

    import asyncio

    asyncio.run(_run(dry_run=args.dry_run))
