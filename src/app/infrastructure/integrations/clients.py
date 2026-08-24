"""Mockable, SSRF-hardened GitHub, Jira, and SIEM HTTP clients."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
import jwt

from app.shared.lib.integration_contract import (
    IntegrationContractError,
    canonical_json_bytes,
    resolve_integration_endpoint,
    sign_envelope,
    validate_https_endpoint,
)


Resolver = Callable[[str, int], Awaitable[Sequence[str]]]
BUILTIN_OUTBOUND_HOSTS = frozenset({"api.github.com", "codeload.github.com"})


class PinnedHttpClient:
    """Resolve an approved hostname once, then connect to that exact address.

    The request URL passed to httpcore contains the validated IP, while the
    original hostname remains in both ``Host`` and ``sni_hostname``. This
    preserves certificate verification/SNI without a second DNS lookup.
    """

    def __init__(
        self,
        *,
        deployment_allowed_hosts: Sequence[str] = (),
        host_pins: Mapping[str, Sequence[str]] | None = None,
        resolver: Resolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.allowed_hosts = frozenset(
            {host.rstrip(".").casefold() for host in deployment_allowed_hosts}
            | set(BUILTIN_OUTBOUND_HOSTS)
        )
        self.host_pins = {
            host.rstrip(".").casefold(): tuple(addresses)
            for host, addresses in (host_pins or {}).items()
        }
        if not set(self.host_pins).issubset(self.allowed_hosts):
            raise IntegrationContractError(
                "outbound host pins must belong to the deployment allowlist"
            )
        self.resolver = resolver
        self.transport = transport
        self._clients: dict[tuple[str, str], httpx.AsyncClient] = {}

    async def __aenter__(self) -> PinnedHttpClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    async def request(
        self,
        method: str,
        url: str,
        *,
        allowed_hosts: Sequence[str],
        headers: Mapping[str, str],
        json_body: Mapping[str, Any] | None = None,
        content: bytes | None = None,
        stream: bool = False,
    ) -> httpx.Response:
        requested_hosts = {
            host.rstrip(".").casefold() for host in allowed_hosts if host.strip()
        }
        if not requested_hosts or not requested_hosts.issubset(self.allowed_hosts):
            raise IntegrationContractError(
                "integration endpoint is not in the deployment outbound allowlist"
            )
        resolved = await resolve_integration_endpoint(
            url,
            allowed_hosts=tuple(requested_hosts),
            host_pins=self.host_pins,
            resolver=self.resolver,
        )
        key = (resolved.hostname, resolved.address)
        client = self._clients.get(key)
        if client is None:
            client = httpx.AsyncClient(transport=self.transport, trust_env=False)
            self._clients[key] = client
        pinned_url = httpx.URL(url).copy_with(host=resolved.address)
        safe_headers = dict(headers)
        safe_headers["Host"] = resolved.hostname
        request = client.build_request(
            method,
            pinned_url,
            headers=safe_headers,
            json=dict(json_body) if json_body is not None else None,
            content=content,
            timeout=20.0,
        )
        request.extensions["sni_hostname"] = resolved.hostname
        return await client.send(request, follow_redirects=False, stream=stream)


def configured_pinned_http_client(
    *,
    resolver: Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> PinnedHttpClient:
    """Build the outbound client exclusively from operator-owned settings."""

    from app.config.config import settings

    return PinnedHttpClient(
        deployment_allowed_hosts=settings.INTEGRATION_OUTBOUND_ALLOWED_HOSTS,
        host_pins=settings.INTEGRATION_OUTBOUND_HOST_PINS,
        resolver=resolver,
        transport=transport,
    )


@dataclass(frozen=True)
class DeliveryResult:
    delivered: bool
    retryable: bool
    http_status: int | None
    error_code: str | None = None
    response_excerpt: str | None = None


def _bounded_response(response: httpx.Response) -> str | None:
    if not response.content:
        return None
    content_type = response.headers.get("content-type", "")
    if "json" not in content_type.casefold():
        return "[non-json response omitted]"
    try:
        value = response.json()
    except ValueError:
        return "[invalid json response omitted]"
    if isinstance(value, Mapping):
        allowlisted = {
            key: value[key]
            for key in ("id", "key", "status", "state", "message")
            if key in value and isinstance(value[key], (str, int, bool, type(None)))
        }
        return json.dumps(allowlisted, sort_keys=True)[:1024]
    return "[json response omitted]"


async def _request(
    client: PinnedHttpClient,
    method: str,
    url: str,
    *,
    allowed_hosts: Sequence[str],
    headers: Mapping[str, str],
    json_body: Mapping[str, Any] | None = None,
    content: bytes | None = None,
    stream: bool = False,
) -> httpx.Response:
    return await client.request(
        method,
        url,
        allowed_hosts=allowed_hosts,
        headers=dict(headers),
        json_body=json_body,
        content=content,
        stream=stream,
    )


class GitHubAppClient:
    API_HOST = "api.github.com"
    API_BASE = "https://api.github.com"
    ARCHIVE_HOST = "codeload.github.com"
    MAX_ARCHIVE_BYTES = 100 * 1024 * 1024

    def __init__(
        self,
        *,
        http: PinnedHttpClient,
    ) -> None:
        self.http = http

    @staticmethod
    def _validate_repository_identity(
        *, owner: str, repository: str, commit_sha: str
    ) -> None:
        for value in (owner, repository):
            if (
                not value
                or len(value) > 100
                or any(
                    ch
                    not in "-_.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                    for ch in value
                )
            ):
                raise IntegrationContractError("invalid GitHub repository identity")
        if len(commit_sha) not in (40, 64) or not all(
            ch in "0123456789abcdefABCDEF" for ch in commit_sha
        ):
            raise IntegrationContractError("GitHub source requires an immutable commit SHA")

    @staticmethod
    def app_jwt(*, app_id: str, private_key_pem: str, now: int | None = None) -> str:
        issued_at = now or int(time.time())
        return jwt.encode(
            {"iat": issued_at - 30, "exp": issued_at + 540, "iss": app_id},
            private_key_pem,
            algorithm="RS256",
        )

    async def installation_token(
        self,
        *,
        app_id: str,
        installation_id: str,
        private_key_pem: str,
        permissions: Mapping[str, str],
    ) -> str:
        allowed_permissions = {
            "contents": "read",
            "security_events": "write",
        }
        requested_permissions = {str(key): str(value) for key, value in permissions.items()}
        if not requested_permissions or any(
            allowed_permissions.get(key) != value
            for key, value in requested_permissions.items()
        ):
            raise IntegrationContractError(
                "GitHub installation token permissions exceed the operation grant"
            )
        url = f"{self.API_BASE}/app/installations/{quote(installation_id, safe='')}/access_tokens"
        response = await _request(
            self.http,
            "POST",
            url,
            allowed_hosts=(self.API_HOST,),
            headers={
                "Authorization": f"Bearer {self.app_jwt(app_id=app_id, private_key_pem=private_key_pem)}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json_body={"permissions": requested_permissions},
        )
        response.raise_for_status()
        token = response.json().get("token")
        if not isinstance(token, str) or not token:
            raise IntegrationContractError("GitHub installation response omitted token")
        return token

    async def download_repository_archive(
        self, *, owner: str, repository: str, commit_sha: str, token: str
    ) -> bytes:
        self._validate_repository_identity(
            owner=owner, repository=repository, commit_sha=commit_sha
        )
        url = f"{self.API_BASE}/repos/{owner}/{repository}/zipball/{commit_sha}"
        response = await _request(
            self.http,
            "GET",
            url,
            allowed_hosts=(self.API_HOST,),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            stream=True,
        )
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "")
            await response.aclose()
            validate_https_endpoint(location, allowed_hosts=(self.ARCHIVE_HOST,))
            response = await _request(
                self.http,
                "GET",
                location,
                allowed_hosts=(self.ARCHIVE_HOST,),
                # Do not forward the installation credential to codeload.
                headers={"Accept": "application/zip"},
                stream=True,
            )
        if response.is_redirect:
            await response.aclose()
            raise IntegrationContractError("GitHub archive exceeded one redirect")
        try:
            response.raise_for_status()
            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError as exc:
                    raise IntegrationContractError(
                        "GitHub archive returned an invalid Content-Length"
                    ) from exc
                if declared_length < 0 or declared_length > self.MAX_ARCHIVE_BYTES:
                    raise IntegrationContractError(
                        "GitHub repository archive exceeds 100 MiB"
                    )
            archive = bytearray()
            async for chunk in response.aiter_bytes():
                archive.extend(chunk)
                if len(archive) > self.MAX_ARCHIVE_BYTES:
                    raise IntegrationContractError(
                        "GitHub repository archive exceeds 100 MiB"
                    )
            return bytes(archive)
        finally:
            await response.aclose()

    async def upload_sarif(
        self,
        *,
        owner: str,
        repository: str,
        commit_sha: str,
        ref: str,
        sarif: bytes,
        token: str,
    ) -> DeliveryResult:
        self._validate_repository_identity(
            owner=owner, repository=repository, commit_sha=commit_sha
        )
        if not re.fullmatch(r"refs/(?:heads|tags|pull)/[-A-Za-z0-9_./]+", ref) or ".." in ref:
            raise IntegrationContractError("invalid GitHub SARIF ref")
        if len(sarif) > 10 * 1024 * 1024:
            raise IntegrationContractError("SARIF upload exceeds GitHub's bounded payload")
        url = f"{self.API_BASE}/repos/{quote(owner, safe='')}/{quote(repository, safe='')}/code-scanning/sarifs"
        encoded = base64.b64encode(sarif).decode("ascii")
        response = await _request(
            self.http,
            "POST",
            url,
            allowed_hosts=(self.API_HOST,),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json_body={"commit_sha": commit_sha, "ref": ref, "sarif": encoded},
        )
        return DeliveryResult(
            delivered=response.status_code in (200, 201, 202),
            retryable=response.status_code == 429 or response.status_code >= 500,
            http_status=response.status_code,
            error_code=None if response.is_success else "github_sarif_rejected",
            response_excerpt=_bounded_response(response),
        )


class JiraCloudClient:
    def __init__(
        self,
        *,
        base_url: str,
        allowed_host: str,
        email: str,
        api_token: str,
        http: PinnedHttpClient,
    ) -> None:
        host = (urlsplit(base_url).hostname or "").casefold()
        if host != allowed_host.casefold() or not host.endswith(".atlassian.net"):
            raise IntegrationContractError("Jira Cloud host must be the configured atlassian.net tenant")
        validate_https_endpoint(base_url, allowed_hosts=(allowed_host,))
        self.base_url = base_url.rstrip("/")
        self.allowed_host = allowed_host
        self.http = http
        credential = base64.b64encode(f"{email}:{api_token}".encode("utf-8")).decode("ascii")
        self.headers = {
            "Authorization": f"Basic {credential}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def find_issue_by_label(self, *, label: str) -> tuple[str, str] | None:
        jql = quote(f'labels = "{label}"', safe="")
        response = await _request(
            self.http,
            "GET",
            f"{self.base_url}/rest/api/3/search/jql?jql={jql}&maxResults=2&fields=key,status",
            allowed_hosts=(self.allowed_host,),
            headers=self.headers,
        )
        response.raise_for_status()
        issues = response.json().get("issues", [])
        if not isinstance(issues, list) or not issues:
            return None
        if len(issues) != 1 or not isinstance(issues[0], Mapping):
            raise IntegrationContractError("Jira canonical label is not unique")
        issue = issues[0]
        fields = issue.get("fields") if isinstance(issue.get("fields"), Mapping) else {}
        status = fields.get("status") if isinstance(fields.get("status"), Mapping) else {}
        key = issue.get("key")
        status_name = status.get("name")
        if not isinstance(key, str) or not isinstance(status_name, str):
            raise IntegrationContractError("Jira search response omitted issue identity")
        return key, status_name

    async def create_issue(
        self,
        *,
        project_key: str,
        issue_type: str,
        summary: str,
        description: str,
        canonical_label: str,
    ) -> tuple[DeliveryResult, str | None]:
        response = await _request(
            self.http,
            "POST",
            f"{self.base_url}/rest/api/3/issue",
            allowed_hosts=(self.allowed_host,),
            headers=self.headers,
            json_body={
                "fields": {
                    "project": {"key": project_key[:32]},
                    "issuetype": {"name": issue_type[:64]},
                    "summary": summary[:255],
                    "labels": [canonical_label],
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [{"type": "text", "text": description[:2000]}],
                            }
                        ],
                    },
                }
            },
        )
        result = DeliveryResult(
            delivered=response.status_code == 201,
            retryable=response.status_code == 429 or response.status_code >= 500,
            http_status=response.status_code,
            error_code=None if response.status_code == 201 else "jira_create_rejected",
            response_excerpt=_bounded_response(response),
        )
        key = response.json().get("key") if response.status_code == 201 else None
        return result, key if isinstance(key, str) else None

    async def transition_issue(self, *, issue_key: str, transition_id: str) -> DeliveryResult:
        response = await _request(
            self.http,
            "POST",
            f"{self.base_url}/rest/api/3/issue/{quote(issue_key, safe='')}/transitions",
            allowed_hosts=(self.allowed_host,),
            headers=self.headers,
            json_body={"transition": {"id": transition_id[:64]}},
        )
        return DeliveryResult(
            delivered=response.status_code == 204,
            retryable=response.status_code == 429 or response.status_code >= 500,
            http_status=response.status_code,
            error_code=None if response.status_code == 204 else "jira_transition_rejected",
            response_excerpt=_bounded_response(response),
        )


class SiemWebhookClient:
    def __init__(
        self,
        *,
        endpoint: str,
        allowed_host: str,
        signing_secret: str,
        http: PinnedHttpClient,
    ) -> None:
        validate_https_endpoint(endpoint, allowed_hosts=(allowed_host,))
        self.endpoint = endpoint
        self.allowed_host = allowed_host
        self.signing_secret = signing_secret
        self.http = http

    async def deliver(self, envelope: Mapping[str, Any]) -> DeliveryResult:
        body = canonical_json_bytes(envelope)
        response = await _request(
            self.http,
            "POST",
            self.endpoint,
            allowed_hosts=(self.allowed_host,),
            headers={
                "Content-Type": "application/json",
                "X-SCCAP-Event-ID": str(envelope["event_id"]),
                "X-SCCAP-Idempotency-Key": str(envelope["idempotency_key"]),
                "X-SCCAP-Signature": sign_envelope(self.signing_secret, envelope),
            },
            content=body,
        )
        return DeliveryResult(
            delivered=200 <= response.status_code < 300,
            retryable=response.status_code == 408
            or response.status_code == 429
            or response.status_code >= 500,
            http_status=response.status_code,
            error_code=None if response.is_success else "siem_delivery_rejected",
            response_excerpt=_bounded_response(response),
        )


def verify_github_webhook_signature(*, secret: str, body: bytes, signature: str) -> None:
    if len(body) > 1024 * 1024:
        raise IntegrationContractError("GitHub webhook exceeds 1 MiB")
    if len(secret.encode("utf-8")) < 32 or not signature.startswith("sha256="):
        raise IntegrationContractError("invalid GitHub webhook signature")
    supplied = signature.removeprefix("sha256=")
    if len(supplied) != 64:
        raise IntegrationContractError("invalid GitHub webhook signature")
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied):
        raise IntegrationContractError("GitHub webhook signature mismatch")
