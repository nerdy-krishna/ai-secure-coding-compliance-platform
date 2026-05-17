# src/app/core/services/default_seed_service.py
"""Idempotent seeder for the default frameworks, agents, and prompt templates.

Single source of truth for what the platform ships with out of the box.
Called from three places:

- Application startup (auto-seed on empty DB) — see lifespan hook in main.py.
- Admin endpoint `POST /api/v1/admin/seed/defaults` for manual re-seed.
- CLI wrapper `scripts/populate_agents_and_frameworks.py`.

`seed_defaults(session, force_reset=False)` only inserts rows that are
missing. When `force_reset=True`, the same cleanup the original script
performed runs first (delete legacy framework names, then re-insert).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from importlib import resources
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.agent_repo import AgentRepository
from app.infrastructure.database.repositories.framework_repo import (
    FrameworkRepository,
)
from app.infrastructure.database.repositories.prompt_template_repo import (
    PromptTemplateRepository,
)

logger = logging.getLogger(__name__)


def _load_prompt(filename: str) -> str:
    """Read a canonical prompt template from `core/services/seed_prompts/`.

    Templates are kept in their own files so they're easy to diff and
    edit in isolation; the `_*_TEMPLATE` constants below preserve the
    historical import surface (e.g. `scripts/extract_eval_prompts.py`
    re-imports them by name).
    """
    return (
        resources.files("app.core.services.seed_prompts")
        .joinpath(filename)
        .read_text(encoding="utf-8")
    )


# --- Data ---------------------------------------------------------------------

FRAMEWORKS_DATA: List[Dict[str, str]] = [
    {
        "name": "asvs",
        "description": (
            "The OWASP Application Security Verification Standard (ASVS) is a "
            "standard for performing application security verifications."
        ),
    },
    {
        "name": "proactive_controls",
        "description": "OWASP Proactive Controls for Developers.",
    },
    {
        "name": "cheatsheets",
        "description": "OWASP Cheatsheets Series.",
    },
    {
        "name": "cwe_essentials",
        "description": (
            "CWE Essentials — the MITRE CWE Top 25 Most Dangerous "
            "Software Weaknesses (2025 edition) plus selected related "
            "CWE-699 development-view entries, organised into 14 "
            "concern-areas (memory safety, injection, authorization, "
            "concurrency, and more). Covers non-web / systems code "
            "(C, C++, Rust, Go, OS components, native programs) that "
            "the web-centric ASVS does not. Bundled with the platform; "
            "opt-in at scan time. Select this for systems / native "
            "codebases or for CWE-grounded weakness coverage."
        ),
    },
    {
        "name": "isvs",
        "description": (
            "OWASP IoT Security Verification Standard (ISVS) — covers "
            "firmware, hardware, and device-communication concerns that "
            "neither the web-centric ASVS nor CWE Essentials address. "
            "Seven concern-areas span secure development & provisioning, "
            "the user-space device application, firmware integrity & "
            "secure boot, software-platform hardening, communication "
            "transport & cryptography, pairing & network exposure, and "
            "the hardware platform. Opt-in at scan time. Select this "
            "for IoT / embedded / connected-device codebases."
        ),
    },
    {
        "name": "llm_top10",
        "description": (
            "OWASP Top 10 for Large Language Model Applications (2025). "
            "Covers LLM01 Prompt Injection, LLM02 Sensitive Information "
            "Disclosure, LLM03 Supply Chain, LLM04 Data and Model "
            "Poisoning, LLM05 Improper Output Handling, LLM06 Excessive "
            "Agency, LLM07 System Prompt Leakage, LLM08 Vector and "
            "Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded "
            "Consumption. Select this for AI / LLM-integrated apps."
        ),
    },
    {
        "name": "agentic_top10",
        "description": (
            "OWASP Top 10 for Agentic AI Applications (2026). Covers "
            "AGENT01 Memory Poisoning, AGENT02 Tool Misuse, AGENT03 "
            "Privilege Compromise, AGENT04 Resource Overload, AGENT05 "
            "Cascading Hallucination Attacks, AGENT06 Intent Breaking & "
            "Goal Manipulation, AGENT07 Misaligned & Deceptive Behaviors, "
            "AGENT08 Repudiation & Untraceability, AGENT09 Identity "
            "Spoofing & Impersonation, AGENT10 Overwhelming Human-in-the-"
            "Loop. Select this for autonomous-agent / multi-agent / MCP "
            "apps."
        ),
    },
]


# --- Agent roster (Framework Expansion #57) ---------------------------------
#
# Each framework owns a dedicated agent roster instead of sharing one
# AppSec pool. Agent names are framework-prefixed for discoverability in
# the admin UI; every agent declares an explicit `applicable_frameworks`
# (exactly one framework) so the mapping-refresh below never falls back
# to a shared default.
#
# The per-framework spec lists (`_ASVS_AGENT_SPECS` etc.) carry the
# bare concern name + domain_query; `_framework_roster` prefixes them
# into the final `Agent` definitions. ASVS keys RAG retrieval on the
# ASVS `control_family` taxonomy; Proactive Controls / Cheatsheets key
# on `framework_name` (their corpora carry no sub-facet).

# Legacy un-prefixed agent names from before the per-framework split.
# `force_reset` deletes these so "Restore defaults" on an existing
# deployment clears the pre-split roster (the data migration in #58
# covers the non-force upgrade path).
_LEGACY_AGENT_NAMES = [
    "AccessControlAgent",
    "ApiSecurityAgent",
    "ArchitectureAgent",
    "AuthenticationAgent",
    "BusinessLogicAgent",
    "CodeIntegrityAgent",
    "CommunicationAgent",
    "ConfigurationAgent",
    "CryptographyAgent",
    "DataProtectionAgent",
    "ErrorHandlingAgent",
    "FileHandlingAgent",
    "SessionManagementAgent",
    "ValidationAgent",
    "BuildDeploymentAgent",
    "ClientSideAgent",
    "CloudContainerAgent",
    # Prefixed ASVS agents superseded by the 1:1 chapter realignment —
    # listed here so "Restore defaults" clears them; the data migration
    # leaves them as unmapped orphans on the non-force upgrade path.
    "AsvsCodeIntegrityAgent",
    "AsvsBuildDeploymentAgent",
    "AsvsClientSideAgent",
    "AsvsCloudContainerAgent",
]


_ASVS_AGENT_SPECS: List[Dict[str, Any]] = [
    {
        "name": "AccessControlAgent",
        "description": (
            "Analyzes for vulnerabilities related to user permissions, "
            "authorization, and insecure direct object references."
        ),
        "domain_query": {
            "keywords": (
                "access control, authorization, user permissions, roles, "
                "insecure direct object reference (IDOR), privileges, broken "
                "object level authorization, function level authorization"
            ),
            "metadata_filter": {"control_family": ["Authorization"]},
        },
    },
    {
        "name": "ApiSecurityAgent",
        "description": (
            "Focuses on the security of API and web service endpoints — "
            "REST, GraphQL, and RPC — including schema validation, rate "
            "limiting, and HTTP message handling."
        ),
        "domain_query": {
            "keywords": (
                "API security, REST, GraphQL, RPC, API keys, rate "
                "limiting, API authentication, API authorization, endpoint "
                "security, mass assignment, HTTP method, content type, "
                "web service"
            ),
            "metadata_filter": {"control_family": ["API and Web Service"]},
        },
    },
    {
        "name": "ArchitectureAgent",
        "description": (
            "Assesses secure coding and architecture — design patterns, "
            "data flow, trust boundaries, dependency and supply-chain "
            "integrity, defensive coding, and safe concurrency."
        ),
        "domain_query": {
            "keywords": (
                "security architecture, design patterns, data flow, trust "
                "boundaries, defensive coding, dependency security, supply "
                "chain, software integrity, third-party libraries, safe "
                "concurrency, race conditions, secure coding"
            ),
            "metadata_filter": {"control_family": ["Secure Coding and Architecture"]},
        },
    },
    {
        "name": "AuthenticationAgent",
        "description": (
            "Scrutinizes login mechanisms, password policies, multi-factor "
            "authentication, and credential management."
        ),
        "domain_query": {
            "keywords": (
                "authentication, login, password policies, credential "
                "management, multi-factor authentication (MFA), single "
                "sign-on (SSO), password hashing, forgot password, "
                "remember me"
            ),
            "metadata_filter": {"control_family": ["Authentication"]},
        },
    },
    {
        "name": "BusinessLogicAgent",
        "description": (
            "Looks for flaws in the application's business logic that could "
            "be exploited."
        ),
        "domain_query": {
            "keywords": (
                "business logic vulnerabilities, workflow abuse, race "
                "conditions, unexpected application state, feature misuse, "
                "price manipulation, excessive computation"
            ),
            "metadata_filter": {"control_family": ["Validation and Business Logic"]},
        },
    },
    {
        "name": "CommunicationAgent",
        "description": (
            "Checks for secure data transmission, use of TLS, and protection "
            "against network-level attacks."
        ),
        "domain_query": {
            "keywords": (
                "secure communication, TLS, SSL, HTTPS, certificate "
                "validation, weak ciphers, transport layer security, data in "
                "transit, network security protocols"
            ),
            "metadata_filter": {"control_family": ["Secure Communication"]},
        },
    },
    {
        "name": "ConfigurationAgent",
        "description": (
            "Inspects for misconfigurations in the application, server, or "
            "third-party services."
        ),
        "domain_query": {
            "keywords": (
                "security misconfiguration, default credentials, verbose "
                "error messages, unnecessary features, improper server "
                "hardening, security headers, file permissions"
            ),
            "metadata_filter": {"control_family": ["Configuration"]},
        },
    },
    {
        "name": "CryptographyAgent",
        "description": (
            "Evaluates the use of encryption, hashing algorithms, and "
            "key management."
        ),
        "domain_query": {
            "keywords": (
                "cryptography, encryption, hashing algorithms, weak ciphers, "
                "key management, PRNG, random number generation, IV, "
                "initialization vector, broken cryptography"
            ),
            "metadata_filter": {"control_family": ["Cryptography"]},
        },
    },
    {
        "name": "DataProtectionAgent",
        "description": (
            "Focuses on the protection of sensitive data at rest and in "
            "transit, including PII."
        ),
        "domain_query": {
            "keywords": (
                "data protection, sensitive data exposure, PII, personally "
                "identifiable information, data at rest, data classification, "
                "data masking, tokenization, GDPR, CCPA"
            ),
            "metadata_filter": {"control_family": ["Data Protection"]},
        },
    },
    {
        "name": "ErrorHandlingAgent",
        "description": (
            "Analyzes error handling routines to prevent information leakage."
        ),
        "domain_query": {
            "keywords": (
                "error handling, information leakage, stack traces, verbose "
                "error messages, debugging information exposure, exception "
                "handling, logging sensitive information"
            ),
            "metadata_filter": {
                "control_family": ["Security Logging and Error Handling"]
            },
        },
    },
    {
        "name": "FileHandlingAgent",
        "description": (
            "Scrutinizes file upload, download, and processing functionality "
            "for vulnerabilities."
        ),
        "domain_query": {
            "keywords": (
                "file handling, file upload vulnerabilities, path traversal, "
                "directory traversal, unrestricted file upload, malware "
                "upload, remote file inclusion (RFI), local file inclusion "
                "(LFI)"
            ),
            "metadata_filter": {"control_family": ["File Handling"]},
        },
    },
    {
        "name": "SessionManagementAgent",
        "description": (
            "Checks for secure session handling, token management, and "
            "protection against session hijacking."
        ),
        "domain_query": {
            "keywords": (
                "session management, session fixation, session hijacking, "
                "cookie security, insecure session tokens, session timeout, "
                "CSRF, cross-site request forgery, JWT session tokens"
            ),
            "metadata_filter": {"control_family": ["Session Management"]},
        },
    },
    {
        "name": "ValidationAgent",
        "description": (
            "Focuses on input validation, output encoding, and prevention of "
            "injection attacks like SQLi and XSS."
        ),
        "domain_query": {
            "keywords": (
                "input validation, output encoding, SQL injection (SQLi), "
                "Cross-Site Scripting (XSS), command injection, type "
                "validation, sanitization, denylisting, allowlisting, "
                "parameter tampering"
            ),
            "metadata_filter": {"control_family": ["Encoding and Sanitization"]},
        },
    },
    {
        "name": "WebFrontendAgent",
        "description": (
            "Analyzes browser-facing security — content security policy, "
            "CORS, security headers, cookie attributes, DOM-based XSS, "
            "clickjacking, and subresource integrity."
        ),
        "domain_query": {
            "keywords": (
                "web frontend security, content security policy, CSP, "
                "CORS, security headers, cookie security, SameSite, DOM "
                "XSS, clickjacking, subresource integrity, postMessage, "
                "browser security"
            ),
            "metadata_filter": {"control_family": ["Web Frontend Security"]},
        },
    },
    {
        "name": "SelfContainedTokenAgent",
        "description": (
            "Reviews self-contained, stateless tokens such as JWT for "
            "signature verification, algorithm confusion, claims "
            "validation, expiry, and revocation."
        ),
        "domain_query": {
            "keywords": (
                "self-contained tokens, JWT, JSON web token, signature "
                "verification, algorithm confusion, none algorithm, claims "
                "validation, audience, issuer, token expiry, token "
                "revocation"
            ),
            "metadata_filter": {"control_family": ["Self-contained Tokens"]},
        },
    },
    {
        "name": "OauthOidcAgent",
        "description": (
            "Audits OAuth 2.0 and OpenID Connect flows — authorization "
            "code with PKCE, redirect URI validation, state and nonce, "
            "token handling, and client authentication."
        ),
        "domain_query": {
            "keywords": (
                "OAuth, OAuth 2.0, OpenID Connect, OIDC, authorization "
                "code, PKCE, redirect URI validation, state parameter, "
                "nonce, access token, refresh token, client "
                "authentication, ID token"
            ),
            "metadata_filter": {"control_family": ["OAuth and OIDC"]},
        },
    },
    {
        "name": "WebRtcAgent",
        "description": (
            "Analyzes WebRTC real-time communication security — DTLS-SRTP "
            "media encryption, signaling, ICE and TURN configuration, and "
            "peer connection handling."
        ),
        "domain_query": {
            "keywords": (
                "WebRTC, real-time communication, DTLS, SRTP, media "
                "encryption, signaling security, ICE, STUN, TURN, peer "
                "connection, RTCPeerConnection, SDP"
            ),
            "metadata_filter": {"control_family": ["WebRTC"]},
        },
    },
]


# OWASP Proactive Controls — developer-focused practices C1–C10.
# RAG retrieval is scoped by `framework_name`; the PC corpus carries no
# sub-facet, so the keywords drive the semantic match.
_PC_AGENT_SPECS: List[Dict[str, Any]] = [
    {
        "name": "AccessControlAgent",
        "description": (
            "C1 — Implement Access Control. Reviews enforcement of "
            "least privilege, deny-by-default, and consistent "
            "server-side authorization checks."
        ),
        "domain_query": {
            "keywords": (
                "access control, implement access control, least "
                "privilege, deny by default, server-side authorization, "
                "role-based access control, ownership checks, "
                "insecure direct object reference"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
    {
        "name": "CryptographyAgent",
        "description": (
            "C2 — Use Cryptography to protect data. Reviews encryption "
            "of data at rest and in transit, key management, and use of "
            "vetted cryptographic algorithms."
        ),
        "domain_query": {
            "keywords": (
                "use cryptography, protect data, encryption at rest, "
                "encryption in transit, key management, vetted "
                "algorithms, secrets management, strong hashing, "
                "secure random number generation"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
    {
        "name": "InputValidationAgent",
        "description": (
            "C3 — Validate all Input & Handle Exceptions. Reviews "
            "syntactic and semantic input validation, allowlisting, "
            "and safe exception handling."
        ),
        "domain_query": {
            "keywords": (
                "validate all input, input validation, allowlist "
                "validation, syntactic validation, semantic validation, "
                "handle exceptions, fail securely, exception handling, "
                "injection prevention, output encoding"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
    {
        "name": "SecureDesignAgent",
        "description": (
            "C4 — Address Security from the Start. Reviews secure "
            "design, threat modeling outcomes, trust boundaries, and "
            "secure architecture decisions."
        ),
        "domain_query": {
            "keywords": (
                "address security from the start, secure design, "
                "threat modeling, trust boundaries, secure architecture, "
                "security requirements, secure development lifecycle, "
                "defense in depth"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
    {
        "name": "SecureConfigurationAgent",
        "description": (
            "C5 — Secure By Default Configurations. Reviews hardened "
            "defaults, removal of unnecessary features, and absence of "
            "insecure default credentials or settings."
        ),
        "domain_query": {
            "keywords": (
                "secure by default, secure configuration, hardened "
                "defaults, default credentials, unnecessary features, "
                "security headers, server hardening, least functionality"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
    {
        "name": "ComponentSecurityAgent",
        "description": (
            "C6 — Keep your Components Secure. Reviews dependency "
            "management, known-vulnerable libraries, and software "
            "supply-chain integrity."
        ),
        "domain_query": {
            "keywords": (
                "keep components secure, dependency security, "
                "known vulnerable components, software composition "
                "analysis, supply chain security, third-party libraries, "
                "outdated dependencies, patch management"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
    {
        "name": "DigitalIdentityAgent",
        "description": (
            "C7 — Secure Digital Identities. Reviews authentication, "
            "credential storage, multi-factor authentication, and "
            "session lifecycle management."
        ),
        "domain_query": {
            "keywords": (
                "secure digital identities, authentication, credential "
                "storage, password hashing, multi-factor authentication, "
                "session management, session lifecycle, identity "
                "verification, account recovery"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
    {
        "name": "BrowserSecurityAgent",
        "description": (
            "C8 — Leverage Browser Security Features. Reviews use of "
            "security headers, Content Security Policy, cookie "
            "attributes, and other browser-enforced protections."
        ),
        "domain_query": {
            "keywords": (
                "leverage browser security features, content security "
                "policy, security headers, secure cookie attributes, "
                "SameSite cookies, HSTS, subresource integrity, "
                "clickjacking protection, CORS"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
    {
        "name": "LoggingMonitoringAgent",
        "description": (
            "C9 — Implement Security Logging and Monitoring. Reviews "
            "security-event logging, log integrity, and avoidance of "
            "sensitive data in logs."
        ),
        "domain_query": {
            "keywords": (
                "security logging, monitoring, audit logging, "
                "security event logging, log integrity, sensitive data "
                "in logs, detectable events, alerting, tamper-resistant "
                "logs"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
    {
        "name": "SsrfAgent",
        "description": (
            "C10 — Stop Server-Side Request Forgery. Reviews validation "
            "of outbound request destinations and protection of "
            "internal services from SSRF."
        ),
        "domain_query": {
            "keywords": (
                "server-side request forgery, SSRF, outbound request "
                "validation, URL allowlist, internal service protection, "
                "metadata endpoint access, blind SSRF, fetch user "
                "supplied URL"
            ),
            "metadata_filter": {"framework_name": ["proactive_controls"]},
        },
    },
]


# OWASP Cheat Sheet Series — topic-organised secure-coding guidance.
# RAG retrieval is scoped by `framework_name`.
_CS_AGENT_SPECS: List[Dict[str, Any]] = [
    {
        "name": "InjectionAgent",
        "description": (
            "Injection defenses — SQL, NoSQL, OS command, LDAP, and "
            "cross-site scripting. Reviews query parameterization and "
            "context-aware output encoding."
        ),
        "domain_query": {
            "keywords": (
                "SQL injection, NoSQL injection, OS command injection, "
                "LDAP injection, cross-site scripting, XSS, query "
                "parameterization, prepared statements, output "
                "encoding, context-aware escaping"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
    {
        "name": "AuthenticationAgent",
        "description": (
            "Authentication and password handling — login flows, "
            "password storage, multi-factor authentication, and "
            "credential recovery."
        ),
        "domain_query": {
            "keywords": (
                "authentication, password storage, password hashing, "
                "bcrypt, argon2, multi-factor authentication, login "
                "flow, forgot password, credential recovery, brute "
                "force protection"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
    {
        "name": "SessionManagementAgent",
        "description": (
            "Session management — session token generation, cookie "
            "attributes, session fixation, and CSRF protection."
        ),
        "domain_query": {
            "keywords": (
                "session management, session token, session fixation, "
                "session hijacking, secure cookie attributes, SameSite, "
                "cross-site request forgery, CSRF token, JWT session"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
    {
        "name": "AuthorizationAgent",
        "description": (
            "Authorization — access-control enforcement, insecure "
            "direct object references, and privilege boundaries."
        ),
        "domain_query": {
            "keywords": (
                "authorization, access control, insecure direct object "
                "reference, IDOR, privilege escalation, role-based "
                "access control, function-level authorization, "
                "ownership checks"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
    {
        "name": "CryptographyAgent",
        "description": (
            "Cryptographic storage and key management — encryption of "
            "data at rest, secrets management, and algorithm selection."
        ),
        "domain_query": {
            "keywords": (
                "cryptographic storage, encryption at rest, key "
                "management, secrets management, weak cipher, "
                "initialization vector, secure random, password "
                "hashing, algorithm selection"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
    {
        "name": "TransportSecurityAgent",
        "description": (
            "Transport-layer protection — TLS configuration, "
            "certificate validation, and HTTP Strict Transport "
            "Security."
        ),
        "domain_query": {
            "keywords": (
                "transport layer security, TLS configuration, HTTPS, "
                "certificate validation, certificate pinning, weak "
                "ciphers, HSTS, HTTP strict transport security, "
                "downgrade attack"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
    {
        "name": "InputValidationAgent",
        "description": (
            "Input validation and deserialization — allowlist "
            "validation, mass assignment, and unsafe deserialization."
        ),
        "domain_query": {
            "keywords": (
                "input validation, allowlist validation, mass "
                "assignment, unsafe deserialization, object "
                "deserialization, type confusion, parameter tampering, "
                "sanitization"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
    {
        "name": "FileHandlingAgent",
        "description": (
            "File handling — upload validation, path traversal, and "
            "safe storage of user-supplied files."
        ),
        "domain_query": {
            "keywords": (
                "file upload, unrestricted file upload, path "
                "traversal, directory traversal, file inclusion, "
                "content-type validation, file storage location, "
                "malicious file"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
    {
        "name": "ErrorLoggingAgent",
        "description": (
            "Error handling and logging — preventing information "
            "leakage through errors and avoiding sensitive data in "
            "logs."
        ),
        "domain_query": {
            "keywords": (
                "error handling, information leakage, stack trace "
                "exposure, verbose error messages, security logging, "
                "sensitive data in logs, log injection, exception "
                "handling"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
    {
        "name": "ApiSecurityAgent",
        "description": (
            "API and browser hardening — REST and GraphQL security, "
            "security headers, CORS, and Content Security Policy."
        ),
        "domain_query": {
            "keywords": (
                "REST API security, GraphQL security, rate limiting, "
                "mass assignment, security headers, CORS "
                "misconfiguration, content security policy, "
                "clickjacking, API authentication"
            ),
            "metadata_filter": {"framework_name": ["cheatsheets"]},
        },
    },
]


# CWE Essentials — MITRE CWE Top 25 (2025) + selected CWE-699 entries,
# grouped into 14 concern-areas. RAG retrieval is scoped by the
# framework-agnostic `concern_area` facet. Each agent carries a
# `gating` value in its `domain_query` consumed by per-file routing:
#   "systems" — runs only on C / C++ / Rust / Go files
#   "web"     — runs only on non-systems (web / scripting) files
#   "all"     — always runs
# All 25 Top 25 CWEs stay citable regardless of gating; gating only
# controls which agents execute against a given file set.
_CWE_AGENT_SPECS: List[Dict[str, Any]] = [
    {
        "name": "SpatialMemorySafetyAgent",
        "description": (
            "Spatial memory safety — out-of-bounds reads and writes. "
            "Covers CWE-787, CWE-125, CWE-119, CWE-122, CWE-121, "
            "CWE-786, CWE-788, CWE-805."
        ),
        "domain_query": {
            "keywords": (
                "CWE-787 out-of-bounds write, CWE-125 out-of-bounds "
                "read, CWE-119 improper restriction of operations "
                "within the bounds of a memory buffer, CWE-122 "
                "heap-based buffer overflow, CWE-121 stack-based "
                "buffer overflow, CWE-786 access of memory location "
                "before start of buffer, CWE-788 access of memory "
                "location after end of buffer, CWE-805 buffer access "
                "with incorrect length value, spatial memory safety, "
                "buffer overflow, bounds checking"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Spatial Memory Safety"],
            },
            "gating": "systems",
        },
    },
    {
        "name": "TemporalMemorySafetyAgent",
        "description": (
            "Temporal memory safety — use-after-free, null dereference, "
            "and lifetime errors. Covers CWE-416, CWE-476, CWE-415, "
            "CWE-401, CWE-824, CWE-825."
        ),
        "domain_query": {
            "keywords": (
                "CWE-416 use after free, CWE-476 NULL pointer "
                "dereference, CWE-415 double free, CWE-401 missing "
                "release of memory after effective lifetime, CWE-824 "
                "access of uninitialized pointer, CWE-825 expired "
                "pointer dereference, temporal memory safety, dangling "
                "pointer, memory leak, object lifetime"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Temporal Memory Safety"],
            },
            "gating": "systems",
        },
    },
    {
        "name": "NumericErrorsAgent",
        "description": (
            "Numeric, type, and conversion errors. Covers CWE-190, "
            "CWE-191, CWE-369, CWE-681, CWE-194, CWE-195, CWE-704, "
            "CWE-843."
        ),
        "domain_query": {
            "keywords": (
                "CWE-190 integer overflow or wraparound, CWE-191 "
                "integer underflow, CWE-369 divide by zero, CWE-681 "
                "incorrect conversion between numeric types, CWE-194 "
                "unexpected sign extension, CWE-195 signed to unsigned "
                "conversion error, CWE-704 incorrect type conversion "
                "or cast, CWE-843 type confusion, numeric error, "
                "integer truncation"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Numeric, Type & Conversion Errors"],
            },
            "gating": "all",
        },
    },
    {
        "name": "OsCommandInjectionAgent",
        "description": ("OS and command injection. Covers CWE-78, CWE-77, CWE-88."),
        "domain_query": {
            "keywords": (
                "CWE-78 improper neutralization of special elements "
                "used in an OS command, CWE-77 command injection, "
                "CWE-88 argument injection or modification, OS command "
                "injection, shell injection, subprocess, exec, "
                "untrusted command arguments"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["OS & Command Injection"],
            },
            "gating": "all",
        },
    },
    {
        "name": "CodeInjectionAgent",
        "description": (
            "Code injection and unsafe deserialization. Covers CWE-94, "
            "CWE-502, CWE-95, CWE-1336."
        ),
        "domain_query": {
            "keywords": (
                "CWE-94 improper control of generation of code, code "
                "injection, CWE-502 deserialization of untrusted data, "
                "CWE-95 eval injection, CWE-1336 improper neutralization "
                "of special elements used in a template engine, "
                "server-side template injection, unsafe deserialization, "
                "pickle, dynamic code execution"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Code Injection & Unsafe Deserialization"],
            },
            "gating": "all",
        },
    },
    {
        "name": "WebInjectionAgent",
        "description": (
            "Web injection — cross-site scripting and query injection. "
            "Covers CWE-79, CWE-89, CWE-90, CWE-91, CWE-943."
        ),
        "domain_query": {
            "keywords": (
                "CWE-79 cross-site scripting, XSS, CWE-89 SQL "
                "injection, CWE-90 LDAP injection, CWE-91 XML "
                "injection, CWE-943 improper neutralization of special "
                "elements in data query logic, NoSQL injection, "
                "output encoding, query parameterization"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Web Injection"],
            },
            "gating": "web",
        },
    },
    {
        "name": "InputValidationAgent",
        "description": (
            "Improper input validation. Covers CWE-20, CWE-129, " "CWE-1284, CWE-1287."
        ),
        "domain_query": {
            "keywords": (
                "CWE-20 improper input validation, CWE-129 improper "
                "validation of array index, CWE-1284 improper "
                "validation of specified quantity in input, CWE-1287 "
                "improper validation of specified type of input, "
                "input validation, allowlist validation, untrusted "
                "input"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Improper Input Validation"],
            },
            "gating": "all",
        },
    },
    {
        "name": "ExternalResourceAccessAgent",
        "description": (
            "External resource access — path traversal, unrestricted "
            "upload, SSRF, link following. Covers CWE-22, CWE-434, "
            "CWE-918, CWE-23, CWE-36, CWE-59, CWE-73."
        ),
        "domain_query": {
            "keywords": (
                "CWE-22 path traversal, CWE-434 unrestricted upload of "
                "file with dangerous type, CWE-918 server-side request "
                "forgery, SSRF, CWE-23 relative path traversal, CWE-36 "
                "absolute path traversal, CWE-59 improper link "
                "resolution before file access, CWE-73 external control "
                "of file name or path, directory traversal"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["External Resource Access"],
            },
            "gating": "all",
        },
    },
    {
        "name": "AuthenticationAgent",
        "description": (
            "Authentication and credential management. Covers CWE-287, "
            "CWE-306, CWE-798, CWE-259, CWE-522, CWE-521, CWE-384."
        ),
        "domain_query": {
            "keywords": (
                "CWE-287 improper authentication, CWE-306 missing "
                "authentication for critical function, CWE-798 use of "
                "hard-coded credentials, CWE-259 use of hard-coded "
                "password, CWE-522 insufficiently protected "
                "credentials, CWE-521 weak password requirements, "
                "CWE-384 session fixation, credential management"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Authentication & Credential Management"],
            },
            "gating": "all",
        },
    },
    {
        "name": "AuthorizationAgent",
        "description": (
            "Authorization and access control. Covers CWE-862, "
            "CWE-863, CWE-352, CWE-639, CWE-732, CWE-285."
        ),
        "domain_query": {
            "keywords": (
                "CWE-862 missing authorization, CWE-863 incorrect "
                "authorization, CWE-352 cross-site request forgery, "
                "CSRF, CWE-639 authorization bypass through "
                "user-controlled key, insecure direct object "
                "reference, CWE-732 incorrect permission assignment "
                "for critical resource, CWE-285 improper authorization"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Authorization & Access Control"],
            },
            "gating": "all",
        },
    },
    {
        "name": "PrivilegeManagementAgent",
        "description": (
            "Privilege management. Covers CWE-269, CWE-250, CWE-271, "
            "CWE-272, CWE-1390."
        ),
        "domain_query": {
            "keywords": (
                "CWE-269 improper privilege management, CWE-250 "
                "execution with unnecessary privileges, CWE-271 "
                "privilege dropping or lowering errors, CWE-272 least "
                "privilege violation, CWE-1390 weak authentication, "
                "privilege escalation, setuid, least privilege"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Privilege Management"],
            },
            "gating": "all",
        },
    },
    {
        "name": "ConcurrencyAgent",
        "description": (
            "Concurrency and race conditions. Covers CWE-362, CWE-367, "
            "CWE-364, CWE-1265, CWE-366."
        ),
        "domain_query": {
            "keywords": (
                "CWE-362 concurrent execution using shared resource "
                "with improper synchronization, race condition, "
                "CWE-367 time-of-check time-of-use TOCTOU race "
                "condition, CWE-364 signal handler race condition, "
                "CWE-1265 unintended reentrant invocation, CWE-366 "
                "race condition within a thread, deadlock, data race"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Concurrency & Race Conditions"],
            },
            "gating": "systems",
        },
    },
    {
        "name": "ResourceLifecycleAgent",
        "description": (
            "Resource lifecycle and exhaustion. Covers CWE-400, "
            "CWE-770, CWE-404, CWE-772."
        ),
        "domain_query": {
            "keywords": (
                "CWE-400 uncontrolled resource consumption, CWE-770 "
                "allocation of resources without limits or throttling, "
                "CWE-404 improper resource shutdown or release, "
                "CWE-772 missing release of resource after effective "
                "lifetime, resource exhaustion, denial of service, "
                "file descriptor leak"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Resource Lifecycle & Exhaustion"],
            },
            "gating": "all",
        },
    },
    {
        "name": "SensitiveInfoExposureAgent",
        "description": (
            "Sensitive information exposure. Covers CWE-200, CWE-209, "
            "CWE-532, CWE-312, CWE-319, CWE-359."
        ),
        "domain_query": {
            "keywords": (
                "CWE-200 exposure of sensitive information to an "
                "unauthorized actor, CWE-209 generation of error "
                "message containing sensitive information, CWE-532 "
                "insertion of sensitive information into log file, "
                "CWE-312 cleartext storage of sensitive information, "
                "CWE-319 cleartext transmission of sensitive "
                "information, CWE-359 exposure of private personal "
                "information, information leakage"
            ),
            "metadata_filter": {
                "framework_name": ["cwe_essentials"],
                "concern_area": ["Sensitive Information Exposure"],
            },
            "gating": "all",
        },
    },
]


# OWASP ISVS — IoT Security Verification Standard. Seven concern-area
# agents (breakdown signed off under Framework Expansion #61): ISVS
# chapters V1/V2/V5 map 1:1, V3 Software Platform splits into firmware
# integrity vs platform hardening, and V4 Communication splits into
# transport/crypto vs pairing/network exposure. RAG retrieval is scoped
# by the framework-agnostic `concern_area` facet. ISVS agents are
# ungated — the operator opts into ISVS explicitly, and device code
# spans too many file types for a language filter to help.
_ISVS_AGENT_SPECS: List[Dict[str, Any]] = [
    {
        "name": "SecureDevelopmentAgent",
        "description": (
            "ISVS V1 — IoT ecosystem and secure development. Reviews "
            "secure SDLC practices, threat modeling, device identity, "
            "provisioning and onboarding, and supply-chain integrity."
        ),
        "domain_query": {
            "keywords": (
                "IoT secure development lifecycle, threat modeling, "
                "device identity, secure provisioning, onboarding, "
                "device enrollment, supply chain security, "
                "bill of materials, secure defaults, decommissioning"
            ),
            "metadata_filter": {
                "framework_name": ["isvs"],
                "concern_area": ["Secure Development & Provisioning"],
            },
        },
    },
    {
        "name": "DeviceApplicationAgent",
        "description": (
            "ISVS V2 — user-space device application. Reviews on-device "
            "credential and sensitive-data storage, local IPC, and "
            "application-level access control on the device."
        ),
        "domain_query": {
            "keywords": (
                "user space application, on-device data storage, "
                "sensitive data at rest, credential storage on device, "
                "local inter-process communication, device application "
                "access control, local logging, application sandboxing"
            ),
            "metadata_filter": {
                "framework_name": ["isvs"],
                "concern_area": ["Device Application & Data Protection"],
            },
        },
    },
    {
        "name": "FirmwareIntegrityAgent",
        "description": (
            "ISVS V3 — firmware integrity and secure boot. Reviews the "
            "verified boot chain, bootloader, firmware image signing, "
            "anti-rollback, and over-the-air update authenticity."
        ),
        "domain_query": {
            "keywords": (
                "secure boot, verified boot chain, bootloader security, "
                "firmware image signing, firmware integrity, "
                "anti-rollback protection, over-the-air update, OTA "
                "update authenticity, firmware downgrade protection, "
                "root of trust"
            ),
            "metadata_filter": {
                "framework_name": ["isvs"],
                "concern_area": ["Firmware Integrity & Secure Boot"],
            },
        },
    },
    {
        "name": "PlatformHardeningAgent",
        "description": (
            "ISVS V3 — software platform hardening. Reviews OS / RTOS "
            "hardening, removal of unnecessary services, on-device "
            "cryptography and key storage, memory protections, and "
            "process isolation."
        ),
        "domain_query": {
            "keywords": (
                "operating system hardening, RTOS hardening, "
                "unnecessary services, on-device cryptography, key "
                "storage, secure key management, memory protection, "
                "process isolation, debug build disabled, least "
                "functionality"
            ),
            "metadata_filter": {
                "framework_name": ["isvs"],
                "concern_area": ["Software Platform Hardening"],
            },
        },
    },
    {
        "name": "TransportSecurityAgent",
        "description": (
            "ISVS V4 — communication transport and cryptography. "
            "Reviews transport encryption, mutual authentication, "
            "certificate validation, and the cryptography protecting "
            "device communications."
        ),
        "domain_query": {
            "keywords": (
                "transport encryption, TLS, DTLS, mutual "
                "authentication, certificate validation, certificate "
                "pinning, weak cipher suites, communication "
                "cryptography, key exchange, message integrity"
            ),
            "metadata_filter": {
                "framework_name": ["isvs"],
                "concern_area": ["Communication Transport & Cryptography"],
            },
        },
    },
    {
        "name": "NetworkExposureAgent",
        "description": (
            "ISVS V4 — pairing and network exposure. Reviews device "
            "pairing and bonding, exposed protocols and services, and "
            "the network-facing attack surface."
        ),
        "domain_query": {
            "keywords": (
                "device pairing, bonding, Bluetooth pairing, exposed "
                "network services, open ports, protocol exposure, "
                "network attack surface, default network services, "
                "unauthenticated endpoints, debug network interface"
            ),
            "metadata_filter": {
                "framework_name": ["isvs"],
                "concern_area": ["Pairing & Network Exposure"],
            },
        },
    },
    {
        "name": "HardwarePlatformAgent",
        "description": (
            "ISVS V5 — hardware platform. Reviews debug and test "
            "interfaces, tamper resistance, secure elements / TPM / "
            "TEE usage, and side-channel and fault-injection "
            "resistance."
        ),
        "domain_query": {
            "keywords": (
                "JTAG, SWD, UART debug interface, test interface "
                "disabled, tamper resistance, tamper detection, secure "
                "element, trusted platform module, TPM, trusted "
                "execution environment, TEE, side-channel resistance, "
                "fault injection resistance"
            ),
            "metadata_filter": {
                "framework_name": ["isvs"],
                "concern_area": ["Hardware Platform Security"],
            },
        },
    },
]


# The LLM / Agentic agents are framework-native already — they are not
# part of the AppSec pool, keep their own names, and declare explicit
# single-framework mappings.
_AI_AGENT_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "LLMSecurityAgent",
        "description": (
            "Audits LLM-integrated apps against OWASP LLM Top 10 (2025): "
            "prompt injection, sensitive-information disclosure, supply "
            "chain (model/dataset provenance), data and model poisoning, "
            "improper output handling, excessive agency, system-prompt "
            "leakage, vector/embedding weaknesses, misinformation, and "
            "unbounded consumption (token / cost / context-window DoS)."
        ),
        "domain_query": {
            "keywords": (
                "prompt injection, jailbreak, system prompt leakage, "
                "sensitive information disclosure, model poisoning, "
                "training data leakage, output handling, excessive "
                "agency, vector embedding weakness, RAG injection, "
                "indirect prompt injection, LLM denial of service, "
                "unbounded token consumption, hallucination misinformation"
            ),
            "metadata_filter": {"control_family": ["LLM Security"]},
        },
        "applicable_frameworks": ["llm_top10"],
    },
    {
        "name": "AgenticSecurityAgent",
        "description": (
            "Audits autonomous / multi-agent / MCP apps against OWASP "
            "Top 10 for Agentic AI (2026): memory poisoning, tool "
            "misuse, privilege compromise, resource overload, cascading "
            "hallucination, intent breaking and goal manipulation, "
            "misaligned/deceptive behaviors, repudiation and "
            "untraceability, identity spoofing/impersonation, and "
            "human-in-the-loop overwhelm."
        ),
        "domain_query": {
            "keywords": (
                "agent memory poisoning, tool misuse, privilege "
                "compromise, agent resource overload, cascading "
                "hallucination, intent breaking, goal manipulation, "
                "deceptive agent behavior, repudiation, untraceable "
                "agent action, identity spoofing, agent impersonation, "
                "human in the loop overwhelm, MCP server, agent "
                "permissions, agent identity, agent authorization, "
                "tool authorization"
            ),
            "metadata_filter": {"control_family": ["Agentic Security"]},
        },
        "applicable_frameworks": ["agentic_top10"],
    },
]


def _framework_roster(
    specs: List[Dict[str, Any]], framework: str, prefix: str
) -> List[Dict[str, Any]]:
    """Expand a per-framework spec list into dedicated `Agent` definitions.

    Each spec's bare concern name is prefixed with `prefix` (e.g.
    `AccessControlAgent` → `AsvsAccessControlAgent`) and tagged with a
    single-element `applicable_frameworks`. Keeping the specs prefix-free
    lets the three AppSec rosters share concern names without colliding
    on the unique `Agent.name`.
    """
    return [
        {
            "name": prefix + spec["name"],
            "description": spec["description"],
            "domain_query": spec["domain_query"],
            "applicable_frameworks": [framework],
        }
        for spec in specs
    ]


# The full default agent roster — 17 ASVS + 10 Proactive Controls + 10
# Cheatsheets + 14 CWE Essentials + 7 ISVS dedicated agents, plus the
# two framework-native AI agents.
AGENT_DEFINITIONS: List[Dict[str, Any]] = (
    _framework_roster(_ASVS_AGENT_SPECS, "asvs", "Asvs")
    + _framework_roster(_PC_AGENT_SPECS, "proactive_controls", "ProactiveControls")
    + _framework_roster(_CS_AGENT_SPECS, "cheatsheets", "Cheatsheets")
    + _framework_roster(_CWE_AGENT_SPECS, "cwe_essentials", "Cwe")
    + _framework_roster(_ISVS_AGENT_SPECS, "isvs", "Isvs")
    + _AI_AGENT_DEFINITIONS
)


# Prompt templates loaded from `core/services/seed_prompts/*.md` — see
# the `_load_prompt` helper at the top of this module for the loader.
# The `_AUDIT_TEMPLATE` / `_REMEDIATION_TEMPLATE` / `_CHAT_TEMPLATE`
# constants stay bound to the generic templates so historical importers
# (`scripts/extract_eval_prompts.py`) keep working without touching
# their import lines.
_AUDIT_TEMPLATE = _load_prompt("audit.md")
_REMEDIATION_TEMPLATE = _load_prompt("remediation.md")
_CHAT_TEMPLATE = _load_prompt("chat.md")

# Per-framework audit / remediation templates (Framework Expansion #57).
# One template text per framework, shared across that framework's
# agents. ASVS and the AI frameworks use the generic templates above;
# Proactive Controls and Cheatsheets get their own framework-tailored
# variants. `_build_prompt_templates` selects by the agent's framework.
_FRAMEWORK_TEMPLATES: Dict[str, Dict[str, str]] = {
    "proactive_controls": {
        "audit": _load_prompt("audit_proactive_controls.md"),
        "remediation": _load_prompt("remediation_proactive_controls.md"),
    },
    "cheatsheets": {
        "audit": _load_prompt("audit_cheatsheets.md"),
        "remediation": _load_prompt("remediation_cheatsheets.md"),
    },
    "cwe_essentials": {
        "audit": _load_prompt("audit_cwe.md"),
        "remediation": _load_prompt("remediation_cwe.md"),
    },
    "isvs": {
        "audit": _load_prompt("audit_isvs.md"),
        "remediation": _load_prompt("remediation_isvs.md"),
    },
}
_GENERIC_TEMPLATES: Dict[str, str] = {
    "audit": _AUDIT_TEMPLATE,
    "remediation": _REMEDIATION_TEMPLATE,
}


def _templates_for_agent(agent: Dict[str, Any]) -> Dict[str, str]:
    """Return the `{audit, remediation}` template text for an agent's framework."""
    frameworks = agent.get("applicable_frameworks") or []
    framework = frameworks[0] if frameworks else ""
    return _FRAMEWORK_TEMPLATES.get(framework, _GENERIC_TEMPLATES)


def _build_prompt_templates() -> List[Dict[str, Any]]:
    templates: List[Dict[str, Any]] = []
    for agent in AGENT_DEFINITIONS:
        texts = _templates_for_agent(agent)
        templates.append(
            {
                "name": f"{agent['name']} - Quick Audit",
                "template_type": "QUICK_AUDIT",
                "agent_name": agent["name"],
                "version": 2,
                "template_text": texts["audit"],
            }
        )
        templates.append(
            {
                "name": f"{agent['name']} - Detailed Remediation",
                "template_type": "DETAILED_REMEDIATION",
                "agent_name": agent["name"],
                "version": 2,
                "template_text": texts["remediation"],
            }
        )
    templates.append(
        {
            "name": "SecurityAdvisorPrompt",
            "template_type": "CHAT",
            "agent_name": "SecurityAdvisorAgent",
            "version": 2,
            "template_text": _CHAT_TEMPLATE,
        }
    )
    return templates


PROMPT_TEMPLATES: List[Dict[str, Any]] = _build_prompt_templates()


# Legacy framework display names cleaned up by force_reset.
_LEGACY_FRAMEWORK_NAMES = [
    "OWASP ASVS",
    "OWASP ASVS v5.0",
    "OWASP Cheatsheets",
    "OWASP Proactive Controls",
]


@dataclass
class SeedResult:
    frameworks_added: int
    agents_added: int
    templates_added: int
    mappings_refreshed: int
    reset: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "frameworks_added": self.frameworks_added,
            "agents_added": self.agents_added,
            "templates_added": self.templates_added,
            "mappings_refreshed": self.mappings_refreshed,
            "reset": self.reset,
        }


async def seed_defaults(
    session: AsyncSession,
    *,
    force_reset: bool = False,
    actor_user_id: Optional[int] = None,
) -> SeedResult:
    """Ensure default frameworks, agents, and prompt templates exist.

    When `force_reset=True`, delete the managed rows first — matches the
    old CLI script's behavior. When False (the default), only insert
    missing rows; existing customisations stay intact.

    All DB work runs inside a single transaction; SQLAlchemy commits on
    successful exit and rolls back on any exception (V02.3.3 atomicity).
    """
    frameworks_added = 0
    agents_added = 0
    templates_added = 0
    mappings_refreshed = 0

    # Per-call commits inside the repo methods (`framework_repo`,
    # `agent_repo`, `prompt_repo`) make this seed inherently
    # non-atomic — a wrapping `async with session.begin():` block
    # used to claim atomicity but actually broke the session
    # transaction state mid-flight (the inner commits release the
    # SessionTransaction the wrapper was managing, leaving the
    # subsequent `session.refresh()` calls operating on a closed
    # transaction). Treat the seed as best-effort: each repo call
    # is its own transaction, partial failures get logged below,
    # and the seed is idempotent on re-run.
    try:
        framework_repo = FrameworkRepository(session)
        agent_repo = AgentRepository(session)
        prompt_repo = PromptTemplateRepository(session)

        target_fw_names = [fw["name"] for fw in FRAMEWORKS_DATA]
        target_agent_names = [a["name"] for a in AGENT_DEFINITIONS] + [
            "SecurityAdvisorAgent"
        ]
        # force_reset also clears the pre-split un-prefixed agents so
        # "Restore defaults" on an existing deployment leaves a clean
        # per-framework roster.
        reset_agent_names = target_agent_names + _LEGACY_AGENT_NAMES

        if force_reset:
            logger.info(
                "seed: force_reset starting",
                extra={"actor_user_id": actor_user_id},
            )

            # 1. Clear framework-agent mappings for any target/legacy framework.
            frameworks_to_clear = await session.execute(
                select(db_models.Framework)
                .options(selectinload(db_models.Framework.agents))
                .where(
                    db_models.Framework.name.in_(
                        target_fw_names + _LEGACY_FRAMEWORK_NAMES
                    )
                )
            )
            for fw in frameworks_to_clear.scalars().all():
                fw.agents = []
            await session.flush()

            # 2. Drop prompt templates + agents + frameworks managed here
            #    (including the pre-split legacy agent names).
            await session.execute(
                delete(db_models.PromptTemplate).where(
                    db_models.PromptTemplate.agent_name.in_(reset_agent_names)
                )
            )
            await session.execute(
                delete(db_models.Agent).where(
                    db_models.Agent.name.in_(reset_agent_names)
                )
            )
            await session.execute(
                delete(db_models.Framework).where(
                    db_models.Framework.name.in_(
                        target_fw_names + _LEGACY_FRAMEWORK_NAMES
                    )
                )
            )
            await session.flush()

            logger.info(
                "seed: force_reset cleared managed rows",
                extra={
                    "actor_user_id": actor_user_id,
                    "target_frameworks": target_fw_names,
                    "target_agents": target_agent_names,
                },
            )

        # Existing-name lookup so we only insert missing rows.
        existing_fws = await session.execute(
            select(db_models.Framework.name).where(
                db_models.Framework.name.in_(target_fw_names)
            )
        )
        existing_fw_names = {row[0] for row in existing_fws.all()}

        existing_agents = await session.execute(
            select(db_models.Agent.name).where(
                db_models.Agent.name.in_(target_agent_names)
            )
        )
        existing_agent_names = {row[0] for row in existing_agents.all()}

        existing_tpls = await session.execute(
            select(db_models.PromptTemplate.name).where(
                db_models.PromptTemplate.name.in_(
                    [tpl["name"] for tpl in PROMPT_TEMPLATES]
                )
            )
        )
        existing_tpl_names = {row[0] for row in existing_tpls.all()}

        for fw_def in FRAMEWORKS_DATA:
            if fw_def["name"] in existing_fw_names:
                continue
            await framework_repo.create_framework(api_models.FrameworkCreate(**fw_def))
            frameworks_added += 1

        for agent_def in AGENT_DEFINITIONS:
            if agent_def["name"] in existing_agent_names:
                continue
            # `applicable_frameworks` is a seed-time concept consumed by the
            # mapping-refresh block below — it's not a DB column, so strip
            # it before passing the dict to `AgentCreate` (which would
            # otherwise reject the unknown field).
            agent_payload = {
                k: v for k, v in agent_def.items() if k != "applicable_frameworks"
            }
            await agent_repo.create_agent(api_models.AgentCreate(**agent_payload))
            agents_added += 1

        for tpl_def in PROMPT_TEMPLATES:
            if tpl_def["name"] in existing_tpl_names:
                continue
            await prompt_repo.create_template(
                api_models.PromptTemplateCreate(**tpl_def)
            )
            templates_added += 1

        # Framework↔agent mapping refresh. Always re-applies — cheap and keeps
        # the default roster consistent after this seed runs (including when
        # force_reset wasn't needed).
        #
        # Per-framework mapping (Framework Expansion #57): every agent
        # declares an explicit single-element `applicable_frameworks`,
        # so each framework maps only to its own dedicated, framework-
        # prefixed agents. There is no shared AppSec pool — selecting
        # `proactive_controls` runs only the Proactive Controls agents,
        # never the ASVS ones.
        fw_rows = await session.execute(
            select(db_models.Framework).where(
                db_models.Framework.name.in_(target_fw_names)
            )
        )
        agent_name_to_id = {
            row[0]: row[1]
            for row in (
                await session.execute(
                    select(db_models.Agent.name, db_models.Agent.id).where(
                        db_models.Agent.name.in_([a["name"] for a in AGENT_DEFINITIONS])
                    )
                )
            ).all()
        }
        # Build {framework_name: [agent_id, ...]} from the seed declarations.
        fw_to_agent_ids: Dict[str, List[int]] = {
            fw["name"]: [] for fw in FRAMEWORKS_DATA
        }
        for agent_def in AGENT_DEFINITIONS:
            applicable = agent_def.get("applicable_frameworks") or []
            agent_id = agent_name_to_id.get(agent_def["name"])
            if agent_id is None:
                continue
            for fw_name in applicable:
                if fw_name in fw_to_agent_ids:
                    fw_to_agent_ids[fw_name].append(agent_id)
        for fw in fw_rows.scalars().all():
            ids_for_fw = fw_to_agent_ids.get(fw.name, [])
            await framework_repo.update_agent_mappings_for_framework(fw.id, ids_for_fw)
            mappings_refreshed += 1
    except Exception:
        logger.error(
            "seed: failed mid-execution",
            extra={
                "force_reset": force_reset,
                "frameworks_added": frameworks_added,
                "agents_added": agents_added,
                "templates_added": templates_added,
            },
            exc_info=True,
        )
        raise

    return SeedResult(
        frameworks_added=frameworks_added,
        agents_added=agents_added,
        templates_added=templates_added,
        mappings_refreshed=mappings_refreshed,
        reset=force_reset,
    )


async def seed_if_empty(session: AsyncSession) -> SeedResult:
    """Auto-seed on startup. Runs only when the platform has zero agents
    AND zero prompt templates — treats that as "fresh install." Having
    fewer than this is considered a user choice we shouldn't override.
    """
    agent_count_result = await session.execute(select(db_models.Agent.id).limit(1))
    template_count_result = await session.execute(
        select(db_models.PromptTemplate.id).limit(1)
    )
    has_agents = agent_count_result.first() is not None
    has_templates = template_count_result.first() is not None

    if has_agents and has_templates:
        logger.debug("Auto-seed skipped: agents and templates already present.")
        return SeedResult(0, 0, 0, 0, False)

    logger.info(
        "Auto-seeding defaults on empty DB "
        f"(has_agents={has_agents}, has_templates={has_templates})."
    )
    return await seed_defaults(session, force_reset=False)
