"""CVE checks as reusable, Nuclei-style templates.

Verifying a CVE used to design a fresh set of requests for every asset: the same CVE,
the same product, the same version endpoint, re-invented per host. That is slow, and it
means two assets with the same software can be tested differently.

A check is now written **once per CVE** as a Nuclei-compatible template, stored with
the CVE in the corpus, and replayed across the inventory:

```yaml
id: CVE-2021-23017-nginx-version
info:
  name: nginx resolver off-by-one (version check)
  severity: high
  description: The nginx build is inside the affected range.
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words: ["nginx"]
      - type: regex
        part: header
        regex: ["nginx/(0\\.|1\\.[0-9]\\.|1\\.1[0-9]\\.|1\\.20\\.0)"]
```

The template is validated before it is stored (read-only methods only, no body, the
asset's hosts only, bounded request count), and executed by a small interpreter that
understands the subset used here: `status`, `word`, `regex` matchers over header/body,
`matchers-condition`, `{{BaseURL}}` and `{{Hostname}}`. Templates stay valid YAML for
real Nuclei, so a check can be exported and run by hand.

Read-only is a hard limit, not a preference: a template that needs a payload is
rejected with the reason recorded, and verification says so instead of pretending the
asset is clean.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional
from urllib.parse import urlparse
from uuid import UUID

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_REQUESTS = 6
REQUEST_TIMEOUT = 12.0
MAX_BODY_CHARS = 20_000
ALLOWED_MATCHERS = frozenset({"status", "word", "regex", "size"})


class TemplateInvalid(ValueError):
    """Raised when a template asks for something this runner will not do."""


class CheckTemplate(BaseModel):
    """A Nuclei-style template, narrowed to what is safe to run here."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=3, max_length=120)
    info: dict[str, Any] = Field(default_factory=dict)
    http: list[dict[str, Any]] = Field(default_factory=list)


def parse_template(text: str) -> tuple[CheckTemplate, list[dict[str, Any]]]:
    """Parse and validate a template; returns it with its normalised requests."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TemplateInvalid(f"the template is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise TemplateInvalid("the template must be a YAML mapping")
    template = CheckTemplate.model_validate(raw)

    requests: list[dict[str, Any]] = []
    for entry in template.http:
        if not isinstance(entry, dict):
            raise TemplateInvalid("each http entry must be a mapping")
        method = str(entry.get("method") or "GET").upper()
        if method not in SAFE_METHODS:
            # Read-only is the boundary: this tool verifies, it does not exploit.
            raise TemplateInvalid(
                f"method {method} is not read-only; only {', '.join(sorted(SAFE_METHODS))} "
                "may be used by a detection check"
            )
        if entry.get("body"):
            raise TemplateInvalid("a detection check may not send a request body")
        paths = entry.get("path") or ["{{BaseURL}}"]
        if isinstance(paths, str):
            paths = [paths]
        for path in paths:
            requests.append(
                {
                    "method": method,
                    "path": str(path),
                    "headers": entry.get("headers") or {},
                    "matchers_condition": str(
                        entry.get("matchers-condition") or "or"
                    ).lower(),
                    "matchers": entry.get("matchers") or [],
                }
            )
    if not requests:
        raise TemplateInvalid("the template contains no HTTP request")
    if len(requests) > MAX_REQUESTS:
        raise TemplateInvalid(f"a check may make at most {MAX_REQUESTS} requests")

    for request in requests:
        for matcher in request["matchers"]:
            if not isinstance(matcher, dict):
                raise TemplateInvalid("each matcher must be a mapping")
            kind = str(matcher.get("type") or "").lower()
            if kind not in ALLOWED_MATCHERS:
                raise TemplateInvalid(
                    f"matcher type {kind!r} is not supported by this runner "
                    f"({', '.join(sorted(ALLOWED_MATCHERS))})"
                )
    if not any(request["matchers"] for request in requests):
        raise TemplateInvalid("the template has no matchers, so it proves nothing")
    return template, requests


def _hosts_for(services: list[am.AssetService]) -> list[str]:
    hosts: list[str] = []
    for service in services:
        if not service.host:
            continue
        scheme = service.protocol if service.protocol in ("http", "https") else "https"
        default_port = (scheme == "https" and service.port == 443) or (
            scheme == "http" and service.port == 80
        )
        base = f"{scheme}://{service.host}"
        if service.port and not default_port:
            base += f":{service.port}"
        if base not in hosts:
            hosts.append(base)
    return hosts


def _render_path(path: str, base_url: str) -> str:
    hostname = urlparse(base_url).hostname or ""
    return (
        path.replace("{{BaseURL}}", base_url)
        .replace("{{RootURL}}", base_url)
        .replace("{{Hostname}}", hostname)
    )


def _matcher_matches(matcher: dict[str, Any], observation: dict[str, Any]) -> bool:
    kind = str(matcher.get("type") or "").lower()
    part = str(matcher.get("part") or "body").lower()
    payload = observation.get("body") if part == "body" else json_headers(observation)
    if kind == "status":
        statuses = matcher.get("status") or []
        return int(observation.get("status") or 0) in [int(s) for s in statuses]
    if kind == "size":
        sizes = matcher.get("size") or []
        return len(str(observation.get("body") or "")) in [int(s) for s in sizes]
    if kind == "word":
        words = [str(word) for word in (matcher.get("words") or [])]
        if not words:
            return False
        hits = [word in (payload or "") for word in words]
        return all(hits) if str(matcher.get("condition") or "or").lower() == "and" else any(hits)
    if kind == "regex":
        patterns = matcher.get("regex") or []
        return any(re.search(str(pattern), payload or "") for pattern in patterns)
    return False


def json_headers(observation: dict[str, Any]) -> str:
    headers = observation.get("headers") or {}
    return "\n".join(f"{key}: {value}" for key, value in headers.items())


async def run_template(
    template_text: str, *, services: list[am.AssetService]
) -> list[dict[str, Any]]:
    """Execute a template against the asset's endpoints, read-only and bounded."""
    _template, requests = parse_template(template_text)
    bases = _hosts_for(services)
    observations: list[dict[str, Any]] = []
    if not bases:
        return [{"error": "the asset has no endpoint to test"}]

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT, follow_redirects=True, verify=False, max_redirects=3
    ) as client:
        for base in bases:
            for request in requests:
                url = _render_path(request["path"], base)
                host = (urlparse(url).hostname or "").lower()
                if host not in {urlparse(b).hostname for b in bases}:
                    observations.append({"url": url, "error": "refused: host outside the asset"})
                    continue
                try:
                    response = await client.request(
                        request["method"], url, headers=request["headers"] or None
                    )
                except Exception as exc:  # noqa: BLE001 — an unreachable endpoint is data
                    observations.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
                    continue
                observation = {
                    "url": url,
                    "method": request["method"],
                    "status": response.status_code,
                    "headers": {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower() in ("server", "x-powered-by", "x-generator", "content-type")
                    },
                    "body": (response.text or "")[:MAX_BODY_CHARS],
                }
                results = [
                    _matcher_matches(matcher, observation)
                    for matcher in request["matchers"]
                ]
                matched = (
                    all(results)
                    if request["matchers_condition"] == "and"
                    else any(results)
                )
                observation["matched"] = matched
                observations.append(observation)
    return observations


def summarise(observations: list[dict[str, Any]]) -> dict[str, Any]:
    tested = [row for row in observations if "error" not in row]
    matched = [row for row in tested if row.get("matched")]
    return {
        "requests": len(observations),
        "reachable": len(tested),
        "matched": len(matched),
        "matched_urls": [row.get("url") for row in matched][:5],
        "errors": [row.get("error") for row in observations if row.get("error")][:5],
    }


# ── Storage ────────────────────────────────────────────────────────────────


async def store_template(
    cve_id: str, template_text: str, *, source: str = "model"
) -> str:
    """Validate and store a template for a CVE (one active check per CVE)."""
    parse_template(template_text)  # raises TemplateInvalid
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    async with AsyncSessionLocal() as db:
        statement = pg_insert(am.CveCheck).values(
            cve_id=cve_id, template=template_text, source=source
        )
        statement = statement.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={"template": statement.excluded.template, "source": statement.excluded.source},
        )
        await db.execute(statement)
        await db.commit()
    return template_text


async def load_template(cve_id: str) -> Optional[am.CveCheck]:
    async with AsyncSessionLocal() as db:
        return await db.scalar(select(am.CveCheck).where(am.CveCheck.cve_id == cve_id))


async def check_for_asset(asset_id: UUID) -> list[am.CveCheck]:
    async with AsyncSessionLocal() as db:
        rows = await db.scalars(select(am.CveCheck).order_by(am.CveCheck.created_at))
        return list(rows)
