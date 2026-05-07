---
title: Python API Reference
---

# Python API Reference

Auto-generated from the SCCAP source tree at build time via
[mkdocstrings-python](https://mkdocstrings.github.io/python/). Update a
docstring in `src/app/...`, rebuild the docs, and this page reflects the
change.

The reference is intentionally narrow today — it covers the handful of
load-bearing utility modules that are stable enough to publish a contract
for. Operator-facing modules (auth, scan workflow, agents) are documented
separately in the [Architecture](../architecture/overview.md) and
[Development](../development/contributing.md) sections.

## Scan-status taxonomy

::: app.shared.lib.scan_status
    options:
      heading_level: 3

## CVSS-weighted risk score

::: app.shared.lib.risk_score
    options:
      heading_level: 3

## Visibility scope

::: app.shared.lib.scan_scope
    options:
      heading_level: 3

## Cost estimation (LiteLLM)

::: app.shared.lib.cost_estimation
    options:
      heading_level: 3
