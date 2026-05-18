---
title: Baseline Language Routing
sidebar_position: 8
---

# Baseline language curation (#80)

`baseline_languages` is the **deterministic routing floor** introduced by
PRD #74. When a file is in one of an agent's baseline languages, that
agent is **force-included** for the file regardless of the profiler's
content-based pick:

```
routed(file) = baseline(language) ∪ (profiler_domains ∩ gating_eligible)
```

The baseline exists because the profiler — an LLM — was silently
dropping relevant agents. The baseline is the human-curated, never-skip
guarantee.

## Curation rule

For each agent, the baseline languages are **the languages where that
agent's concern-area is a prevalent threat** per the CWE Top 25 and the
OWASP Top 10. It is deliberately *inclusive*: a false include costs one
extra LLM call; a false exclude is a missed vulnerability class.

The framework an agent belongs to is itself a coarse filter — agents
only enter routing if the operator selected their framework for the
scan. So MASVS agents only ever see a file when the operator chose a
mobile scan; the baseline then refines *which* file types within that
scan each agent runs against.

## Language sets

All codes are the canonical values from `shared/lib/files.py`
(`LANGUAGE_EXTENSIONS`). `["*"]` is the wildcard — matches every
language, including files with an unrecognised extension.

| Set | Languages | Used for |
|-----|-----------|----------|
| `_WEB_BACKEND_LANGS` | python, javascript, typescript, java, go, ruby, php, csharp, rust, scala, kotlin | Server-side web app concerns |
| `_WEB_FRONTEND_LANGS` | javascript, typescript, html, vue, svelte | Browser-facing concerns |
| `_WEB_ALL_LANGS` | backend ∪ frontend | Injection-class concerns (span client + server) |
| `_MOBILE_LANGS` | swift, kotlin, java, dart, javascript, typescript, csharp | Mobile app concerns (native + React Native + Flutter + MAUI) |
| `_EMBEDDED_LANGS` | c, cpp, rust, go, python | IoT firmware + gateway concerns |
| `_FIRMWARE_LANGS` | c, cpp, rust | Firmware / hardware-level concerns only |

## Per-framework mapping

CWE Essentials carries its baselines inline in `_CWE_AGENT_SPECS` (seeded
in #76) — not repeated here. The seven frameworks below are seeded from
the `_*_BASELINE_LANGUAGES` maps in `default_seed_service.py`.

### ASVS — web application security verification

| Agent | Baseline | Rationale |
|-------|----------|-----------|
| AccessControl, ApiSecurity, Architecture, Authentication, BusinessLogic, Communication, Configuration, Cryptography, DataProtection, ErrorHandling, FileHandling, SessionManagement, SelfContainedToken, OauthOidc | `_WEB_BACKEND_LANGS` | Server-side application concerns |
| Validation | `_WEB_ALL_LANGS` | Injection spans server (SQLi) and client (XSS) |
| WebFrontend, WebRtc | `_WEB_FRONTEND_LANGS` | Browser-only concerns |

### Proactive Controls — developer practices

| Agent | Baseline |
|-------|----------|
| AccessControl, Cryptography, SecureDesign, SecureConfiguration, ComponentSecurity, DigitalIdentity, LoggingMonitoring, Ssrf | `_WEB_BACKEND_LANGS` |
| InputValidation | `_WEB_ALL_LANGS` |
| BrowserSecurity | `_WEB_FRONTEND_LANGS` |

### Cheatsheets — OWASP cheat sheet series

| Agent | Baseline |
|-------|----------|
| Authentication, SessionManagement, Authorization, Cryptography, TransportSecurity, FileHandling, ErrorLogging, ApiSecurity | `_WEB_BACKEND_LANGS` |
| Injection, InputValidation | `_WEB_ALL_LANGS` |

### ISVS — IoT / embedded-systems security verification

| Agent | Baseline | Rationale |
|-------|----------|-----------|
| SecureDevelopment, DeviceApplication, PlatformHardening, TransportSecurity, NetworkExposure | `_EMBEDDED_LANGS` | Device firmware + gateway code |
| FirmwareIntegrity, HardwarePlatform | `_FIRMWARE_LANGS` | Low-level firmware / hardware only — no scripting layer |

### MASVS — mobile application security verification

Every agent → `_MOBILE_LANGS`. A MASVS concern (storage, crypto, auth,
network, platform, code quality, resilience, privacy) is a mobile-app
threat regardless of sub-domain.

### LLM Top 10 / Agentic Top 10

Every agent → `["*"]`. The threat is "the application integrates an LLM
/ is agentic", not the implementation language — so once the operator
selects the framework, every file is in scope.
