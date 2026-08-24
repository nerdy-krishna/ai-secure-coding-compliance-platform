from __future__ import annotations

import json
import unittest
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from unittest.mock import patch

import httpx

from app.core.services.integration_service import IntegrationService
from app.infrastructure.integrations.clients import (
    GitHubAppClient,
    JiraCloudClient,
    PinnedHttpClient,
    SiemWebhookClient,
    verify_github_webhook_signature,
)
from app.infrastructure.integrations.secrets import (
    decrypt_integration_secrets,
    encrypt_integration_secrets,
)
from app.shared.lib.integration_contract import (
    IntegrationContractError,
    build_envelope,
    stable_idempotency_key,
    verify_envelope_signature,
)


async def public_resolver(host: str, port: int):
    del host, port
    return ["93.184.216.34"]


class _ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk


class IntegrationClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_github_webhook_rejects_repository_outside_connector_scope(self) -> None:
        import hashlib
        import hmac

        secret = "s" * 32
        body = b'{"repository":{"full_name":"attacker/other","private":true}}'
        encrypted, _ = encrypt_integration_secrets(
            {"private_key_pem": "unused", "webhook_secret": secret}
        )
        repo = SimpleNamespace(
            get_principal=AsyncMock(
                return_value=SimpleNamespace(
                    kind="github_app",
                    config={"owner": "acme", "repository": "widgets"},
                    secrets_encrypted=encrypted,
                )
            ),
            has_active_grant=AsyncMock(return_value=True),
            record_inbound_receipt=AsyncMock(),
        )
        signature = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()

        with self.assertRaisesRegex(IntegrationContractError, "grant scope"):
            await IntegrationService(repo).accept_github_webhook(
                tenant_id=uuid.uuid4(),
                principal_id=uuid.uuid4(),
                delivery_id="delivery-1",
                event_type="push",
                signature=signature,
                body=body,
            )

        repo.record_inbound_receipt.assert_not_awaited()

    def test_connector_config_rejects_unknown_or_secret_alias_fields(self) -> None:
        config = {
            "app_id": "123",
            "installation_id": "456",
            "owner": "acme",
            "repository": "widgets",
        }
        secret_values = {
            "private_key_pem": "-----BEGIN PRIVATE KEY-----",
            "webhook_secret": "s" * 32,
        }
        safe, _ = IntegrationService.validate_configuration(
            kind="github_app", config=config, secret_values=secret_values
        )
        self.assertEqual(safe["owner"], "acme")
        for alias in ("privatePem", "key", "data"):
            with self.subTest(alias=alias), self.assertRaisesRegex(
                IntegrationContractError, "unknown field"
            ):
                IntegrationService.validate_configuration(
                    kind="github_app",
                    config={**config, alias: "plaintext-secret"},
                    secret_values=secret_values,
                )

    def test_jira_mapping_rejects_unbounded_or_nested_extra_fields(self) -> None:
        base = {
            "base_url": "https://tenant.atlassian.net",
            "allowed_host": "tenant.atlassian.net",
            "project_key": "SEC",
            "waived_status": "waived",
            "reopen_status": "open",
        }
        secrets = {"email": "svc@example.invalid", "api_token": "token"}
        with self.assertRaisesRegex(IntegrationContractError, "only transition_id"):
            IntegrationService.validate_configuration(
                kind="jira_cloud",
                config={
                    **base,
                    "status_mapping": {
                        "open": {"transition_id": "1", "data": "secret"},
                        "waived": {"transition_id": "2"},
                    },
                },
                secret_values=secrets,
            )
        with self.assertRaisesRegex(IntegrationContractError, "1 to 32"):
            IntegrationService.validate_configuration(
                kind="jira_cloud",
                config={
                    **base,
                    "status_mapping": {
                        f"state-{index}": {"transition_id": str(index + 1)}
                        for index in range(33)
                    },
                },
                secret_values=secrets,
            )

    async def test_grant_scopes_are_exact_and_connector_bound(self) -> None:
        principal = SimpleNamespace(
            kind="github_app", config={"owner": "acme", "repository": "widgets"}
        )
        repo = SimpleNamespace(
            get_principal=AsyncMock(return_value=principal),
            grant_feature=AsyncMock(return_value=SimpleNamespace()),
        )
        service = IntegrationService(repo)
        with self.assertRaisesRegex(IntegrationContractError, "unknown field"):
            await service.grant_feature(
                tenant_id=uuid.uuid4(),
                principal_id=uuid.uuid4(),
                feature="repository_contents_read",
                scope={"repository": "acme/widgets", "data": "plaintext"},
                actor_user_id=1,
            )
        await service.grant_feature(
            tenant_id=uuid.uuid4(),
            principal_id=uuid.uuid4(),
            feature="repository_contents_read",
            scope={"repository": "ACME/WIDGETS"},
            actor_user_id=1,
        )
        self.assertEqual(
            repo.grant_feature.await_args.kwargs["scope"],
            {"repository": "acme/widgets"},
        )

    def test_connector_secret_roundtrip_is_ciphertext_only(self) -> None:
        ciphertext, fingerprint = encrypt_integration_secrets(
            {"api_token": "not-plaintext-in-db"}
        )
        self.assertNotIn(b"not-plaintext-in-db", ciphertext)
        self.assertEqual(len(fingerprint), 64)
        self.assertEqual(
            decrypt_integration_secrets(ciphertext),
            {"api_token": "not-plaintext-in-db"},
        )

    def test_github_native_webhook_hmac_rejects_tamper(self) -> None:
        import hashlib
        import hmac

        body = b'{"action":"completed"}'
        signature = "sha256=" + hmac.new(b"s" * 32, body, hashlib.sha256).hexdigest()
        verify_github_webhook_signature(secret="s" * 32, body=body, signature=signature)
        with self.assertRaisesRegex(IntegrationContractError, "mismatch"):
            verify_github_webhook_signature(
                secret="s" * 32, body=body + b" ", signature=signature
            )

    async def test_siem_delivery_signs_exact_body_and_stable_headers(self) -> None:
        observed = {}

        def handler(request: httpx.Request) -> httpx.Response:
            observed["body"] = request.content
            observed["signature"] = request.headers["X-SCCAP-Signature"]
            observed["idempotency"] = request.headers["X-SCCAP-Idempotency-Key"]
            return httpx.Response(202, json={"status": "accepted"})

        envelope = build_envelope(
            event_id="11111111-1111-4111-8111-111111111111",
            event_type="finding.changed",
            tenant_id="22222222-2222-4222-8222-222222222222",
            nonce="N" * 32,
            timestamp=1_787_526_400,
            idempotency_key=stable_idempotency_key("tenant", "finding", "one"),
            payload={"finding_id": "opaque", "status": "open"},
        )
        async with PinnedHttpClient(
            deployment_allowed_hosts=("events.example.com",),
            transport=httpx.MockTransport(handler),
            resolver=public_resolver,
        ) as http:
            result = await SiemWebhookClient(
                endpoint="https://events.example.com/v1/sccap",
                allowed_host="events.example.com",
                signing_secret="s" * 32,
                http=http,
            ).deliver(envelope)
        self.assertTrue(result.delivered)
        self.assertEqual(json.loads(observed["body"]), envelope)
        self.assertEqual(observed["idempotency"], envelope["idempotency_key"])
        verify_envelope_signature(
            secret="s" * 32,
            envelope=envelope,
            signature=observed["signature"],
            now=datetime.fromtimestamp(envelope["timestamp"], timezone.utc),
        )

    async def test_jira_canonical_label_search_precedes_create(self) -> None:
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            if "/search/jql" in request.url.path:
                return httpx.Response(
                    200,
                    json={
                        "issues": [
                            {
                                "key": "SEC-42",
                                "fields": {"status": {"name": "Open"}},
                            }
                        ]
                    },
                )
            return httpx.Response(500)

        async with PinnedHttpClient(
            deployment_allowed_hosts=("tenant.atlassian.net",),
            transport=httpx.MockTransport(handler),
            resolver=public_resolver,
        ) as http:
            client = JiraCloudClient(
                base_url="https://tenant.atlassian.net",
                allowed_host="tenant.atlassian.net",
                email="service@example.invalid",
                api_token="secret",
                http=http,
            )
            found = await client.find_issue_by_label(label="sccap-root-aabb")
        self.assertEqual(found, ("SEC-42", "Open"))
        self.assertEqual(len(requests), 1)

    async def test_github_token_requests_only_operation_permissions(self) -> None:
        observed: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            observed["body"] = json.loads(request.content)
            return httpx.Response(201, json={"token": "installation-token"})

        async with PinnedHttpClient(
            transport=httpx.MockTransport(handler),
            resolver=public_resolver,
        ) as http:
            with patch.object(GitHubAppClient, "app_jwt", return_value="signed-jwt"):
                token = await GitHubAppClient(http=http).installation_token(
                    app_id="123",
                    installation_id="456",
                    private_key_pem="not-used-by-mock",
                    permissions={"contents": "read"},
                )
        self.assertEqual(token, "installation-token")
        self.assertEqual(observed["body"], {"permissions": {"contents": "read"}})
        with self.assertRaisesRegex(IntegrationContractError, "exceed"):
            async with PinnedHttpClient() as http:
                await GitHubAppClient(http=http).installation_token(
                    app_id="123",
                    installation_id="456",
                    private_key_pem="not-used",
                    permissions={"contents": "write"},
                )

    async def test_github_operation_never_mints_token_without_active_grant(self) -> None:
        repo = SimpleNamespace(
            get_principal=AsyncMock(
                return_value=SimpleNamespace(kind="github_app", secrets_encrypted=b"unused")
            ),
            has_active_grant=AsyncMock(return_value=False),
        )
        with self.assertRaisesRegex(PermissionError, "grant is missing"):
            async with PinnedHttpClient() as http:
                await IntegrationService(repo).download_github_source(
                    tenant_id=uuid.uuid4(),
                    principal_id=uuid.uuid4(),
                    commit_sha="a" * 40,
                    http=http,
                )

    async def test_github_archive_allows_only_codeload_hop_and_strips_token(self) -> None:
        observed: list[tuple[str, str | None]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            observed.append((request.headers["Host"], request.headers.get("Authorization")))
            if request.headers["Host"] == "api.github.com":
                return httpx.Response(
                    302,
                    headers={
                        "location": "https://codeload.github.com/acme/repo/legacy.zip/"
                        + "a" * 40
                    },
                )
            return httpx.Response(200, stream=_ChunkStream([b"zip", b"data"]))

        async with PinnedHttpClient(
            transport=httpx.MockTransport(handler), resolver=public_resolver
        ) as http:
            archive = await GitHubAppClient(http=http).download_repository_archive(
                owner="acme",
                repository="repo",
                commit_sha="a" * 40,
                token="installation-secret",
            )
        self.assertEqual(archive, b"zipdata")
        self.assertEqual(
            observed,
            [
                ("api.github.com", "Bearer installation-secret"),
                ("codeload.github.com", None),
            ],
        )

    async def test_github_archive_rejects_unapproved_redirect_and_abbreviated_sha(self) -> None:
        requests = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal requests
            requests += 1
            return httpx.Response(
                302, headers={"location": "https://attacker.example/archive.zip"}
            )

        async with PinnedHttpClient(
            transport=httpx.MockTransport(handler), resolver=public_resolver
        ) as http:
            client = GitHubAppClient(http=http)
            with self.assertRaisesRegex(IntegrationContractError, "allowlisted"):
                await client.download_repository_archive(
                    owner="acme",
                    repository="repo",
                    commit_sha="a" * 40,
                    token="secret",
                )
            with self.assertRaisesRegex(IntegrationContractError, "immutable"):
                await client.download_repository_archive(
                    owner="acme",
                    repository="repo",
                    commit_sha="a" * 12,
                    token="secret",
                )
        self.assertEqual(requests, 1)

    async def test_github_archive_incremental_cap_handles_missing_or_lying_length(self) -> None:
        for headers in ({}, {"content-length": "4"}):
            with self.subTest(headers=headers):
                def handler(_request: httpx.Request) -> httpx.Response:
                    return httpx.Response(
                        200,
                        headers=headers,
                        stream=_ChunkStream([b"123", b"456"]),
                    )

                async with PinnedHttpClient(
                    transport=httpx.MockTransport(handler), resolver=public_resolver
                ) as http:
                    client = GitHubAppClient(http=http)
                    client.MAX_ARCHIVE_BYTES = 5
                    with self.assertRaisesRegex(IntegrationContractError, "exceeds"):
                        await client.download_repository_archive(
                            owner="acme",
                            repository="repo",
                            commit_sha="a" * 64,
                            token="secret",
                        )
    async def test_transport_pins_first_resolution_and_preserves_tls_hostname(self) -> None:
        resolutions = 0
        observed: dict[str, object] = {}

        async def rebinding_resolver(host: str, port: int):
            nonlocal resolutions
            resolutions += 1
            self.assertEqual((host, port), ("events.example.com", 443))
            return ["93.184.216.34"] if resolutions == 1 else ["10.0.0.7"]

        def handler(request: httpx.Request) -> httpx.Response:
            observed["url_host"] = request.url.host
            observed["host"] = request.headers["Host"]
            observed["sni"] = request.extensions["sni_hostname"]
            return httpx.Response(204)

        async with PinnedHttpClient(
            deployment_allowed_hosts=("events.example.com",),
            transport=httpx.MockTransport(handler),
            resolver=rebinding_resolver,
        ) as http:
            response = await http.request(
                "POST",
                "https://events.example.com/v1",
                allowed_hosts=("events.example.com",),
                headers={},
                content=b"{}",
            )

        self.assertEqual(response.status_code, 204)
        self.assertEqual(resolutions, 1)
        self.assertEqual(observed["url_host"], "93.184.216.34")
        self.assertEqual(observed["host"], "events.example.com")
        self.assertEqual(observed["sni"], "events.example.com")

    async def test_private_destination_requires_operator_owned_exact_pin(self) -> None:
        async def private_resolver(_host: str, _port: int):
            return ["10.20.30.40"]

        with self.assertRaisesRegex(IntegrationContractError, "non-public"):
            async with PinnedHttpClient(
                deployment_allowed_hosts=("siem.internal.example",),
                resolver=private_resolver,
                transport=httpx.MockTransport(lambda _request: httpx.Response(204)),
            ) as http:
                await http.request(
                    "POST",
                    "https://siem.internal.example/events",
                    allowed_hosts=("siem.internal.example",),
                    headers={},
                )

        observed: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            observed["url_host"] = request.url.host
            return httpx.Response(204)

        async with PinnedHttpClient(
            deployment_allowed_hosts=("siem.internal.example",),
            host_pins={"siem.internal.example": ("10.20.30.40",)},
            resolver=private_resolver,
            transport=httpx.MockTransport(handler),
        ) as http:
            await http.request(
                "POST",
                "https://siem.internal.example/events",
                allowed_hosts=("siem.internal.example",),
                headers={},
            )
        self.assertEqual(observed["url_host"], "10.20.30.40")

    def test_tenant_cannot_extend_deployment_allowlist_with_a_pin(self) -> None:
        with self.assertRaisesRegex(IntegrationContractError, "deployment allowlist"):
            PinnedHttpClient(
                deployment_allowed_hosts=("approved.example",),
                host_pins={"tenant-selected.example": ("10.20.30.40",)},
            )


if __name__ == "__main__":
    unittest.main()
