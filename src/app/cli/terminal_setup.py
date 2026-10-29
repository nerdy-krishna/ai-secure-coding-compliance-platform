"""Terminal-side first-run bootstrap.

The browser wizard used to ask for the superuser, LLM and deployment settings
that ``setup.sh`` had already half-asked for. That wizard is gone: the terminal
installer collects every answer and this client submits it to the API's existing
``POST /api/v1/setup`` endpoint, so first-run bootstrap still has exactly one
implementation (the endpoint) and the terminal is a thin client of it.

Secrets are read from the environment (``SCCAP_SETUP_ADMIN_PASSWORD``,
``SCCAP_SETUP_LLM_API_KEY``) so they never appear in a process list or in
``setup.sh``'s argv.

Usage (inside the app container):

    python -m app.cli.terminal_setup --check
    python -m app.cli.terminal_setup \
        --admin-email ops@example.com \
        --deployment-type cloud --frontend-url https://example.com \
        --llm-mode multi_provider --llm-provider openai \
        --llm-model gpt-4o --features scan,chat
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_API_BASE = "http://127.0.0.1:8000"

EXIT_PENDING = 3


def _request(
    url: str, *, payload: dict | None = None, timeout: float = 30.0
) -> tuple[int, str]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url, data=data, headers=headers, method="POST" if data else "GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, f"{type(exc).__name__}: {exc}"


def _setup_completed(api_base: str) -> bool | None:
    status, body = _request(f"{api_base}/api/v1/setup/status", timeout=10.0)
    if status != 200:
        return None
    try:
        return bool(json.loads(body).get("is_setup_completed"))
    except (json.JSONDecodeError, AttributeError):
        return None


def _wait_for_api(api_base: str, seconds: int) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if _setup_completed(api_base) is not None:
            return True
        time.sleep(2)
    return False


def build_payload(
    *,
    admin_email: str,
    admin_password: str,
    llm_provider: str,
    llm_model: str,
    llm_api_key: str,
    llm_mode: str,
    deployment_type: str,
    frontend_url: str | None = None,
    features: str | None = None,
) -> dict:
    """Payload for POST /api/v1/setup (mirrors api/v1/schemas/setup.py)."""
    payload: dict = {
        "admin_email": admin_email,
        "admin_password": admin_password,
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "llm_api_key": llm_api_key,
        "llm_optimization_mode": llm_mode,
        "deployment_type": deployment_type,
    }
    if frontend_url:
        payload["frontend_url"] = frontend_url
    if features:
        selected = [item.strip() for item in features.split(",") if item.strip()]
        if selected:
            payload["enabled_features"] = selected
    return payload


def _fail(message: str) -> int:
    print(f"[!] {message}", file=sys.stderr)
    return 1


def _redacted_detail(body: str) -> str:
    """Extract a human-readable detail without echoing secrets or tracebacks."""
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return body[:300]
    detail = parsed.get("detail") if isinstance(parsed, dict) else None
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):
        parts = []
        for item in detail:
            if not isinstance(item, dict):
                continue
            location = ".".join(
                str(part) for part in item.get("loc", []) if part != "body"
            )
            message = str(item.get("msg", "invalid value")).replace("Value error, ", "")
            parts.append(f"{location}: {message}" if location else message)
        return "; ".join(parts) or "validation failed"
    return "request rejected"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--api-base", default=os.environ.get("SCCAP_API_BASE", DEFAULT_API_BASE)
    )
    parser.add_argument(
        "--check", action="store_true", help="Report setup state and exit."
    )
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--admin-email")
    parser.add_argument("--deployment-type", choices=("local", "cloud"))
    parser.add_argument("--frontend-url")
    parser.add_argument(
        "--llm-mode",
        choices=("multi_provider", "anthropic_optimized"),
        default="multi_provider",
    )
    parser.add_argument(
        "--llm-provider", choices=("openai", "anthropic", "google", "deepseek", "xai")
    )
    parser.add_argument("--llm-model")
    parser.add_argument(
        "--features",
        help="Comma-separated feature list for the custom variant (omit for presets).",
    )
    args = parser.parse_args(argv)

    api_base = args.api_base.rstrip("/")

    if args.wait_seconds > 0 and not _wait_for_api(api_base, args.wait_seconds):
        return _fail(
            f"API did not answer /api/v1/setup/status within {args.wait_seconds}s at {api_base}."
        )

    completed = _setup_completed(api_base)
    if completed is None:
        return _fail(f"Could not read setup status from {api_base}.")

    if args.check:
        print("completed" if completed else "pending")
        return 0 if completed else EXIT_PENDING

    if completed:
        # Idempotent: a re-run must never try to create a second superuser.
        print("[+] Platform setup already completed; nothing to do.")
        return 0

    missing = [
        flag
        for flag, value in (
            ("--admin-email", args.admin_email),
            ("--deployment-type", args.deployment_type),
            ("--llm-provider", args.llm_provider),
            ("--llm-model", args.llm_model),
        )
        if not value
    ]
    password = os.environ.get("SCCAP_SETUP_ADMIN_PASSWORD", "")
    api_key = os.environ.get("SCCAP_SETUP_LLM_API_KEY", "")
    if not password:
        missing.append("SCCAP_SETUP_ADMIN_PASSWORD")
    if not api_key:
        missing.append("SCCAP_SETUP_LLM_API_KEY")
    if missing:
        return _fail("missing required setup input: " + ", ".join(missing))

    payload = build_payload(
        admin_email=args.admin_email,
        admin_password=password,
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
        llm_api_key=api_key,
        llm_mode=args.llm_mode,
        deployment_type=args.deployment_type,
        frontend_url=args.frontend_url,
        features=args.features,
    )

    status, body = _request(f"{api_base}/api/v1/setup", payload=payload, timeout=120.0)
    if status not in (200, 201):
        return _fail(f"setup failed (HTTP {status}): {_redacted_detail(body)}")

    print(
        "[+] Platform setup completed: superuser, LLM configuration and feature flags are in place."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
