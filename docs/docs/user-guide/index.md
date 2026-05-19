---
sidebar_position: 1
title: User Guide Overview
---

# User Guide

Walkthroughs for the SCCAP UI, organized by page. Every scan-related
page respects **visibility scope**: regular users see their own
scans plus any scan owned by a user they share a group with; admins
see everything.

## For developers + users

- [**Dashboard**](./dashboard-overview.md) — live risk ring, severity
  bar, 14-day scan trend, fixes-ready, monthly spend.
- **Submit + analyze code**
  - [Submitting Code](./code-analysis/submitting-code.md)
  - [Multi-Framework Scanning](./code-analysis/multi-framework-scanning.md)
  - [Understanding Results](./code-analysis/understanding-results.md)
  - [Managing Findings + Remediation](./code-analysis/managing-findings.md)
- **Security Advisor (chat)**
  - [Guideline-backed Q&A](./chat-interfaces/guideline-provision.md)
  - [Secure Code Generation](./chat-interfaces/secure-code-generation.md)
- [**Reporting**](./reporting.md) — HTML, CSV, and PDF findings reports.
- [Unit-test integration](./unit-test-integration.md) — roadmap note.

## For admins

All admin surfaces are superuser-gated server-side. A single
`AdminSubNav` strip in the `DashboardLayout` makes every admin page
one click apart. See the
[Platform Features → Admin console](../overview/features.md#admin-console)
section for the full index.
