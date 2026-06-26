"""Finding Lineage — unified graph builder supporting expansion, focus, filters, and overflow.

Produces render-ready nodes and edges for the Finding Lineage graph
from either exact scan artifacts or inferred findings.  Supports
server-side expand, focus, filter, and node-cap overflow.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Domain & colour helpers ──────────────────────────────────────────

_DOMAIN_MAP: Dict[str, str] = {}
for suffix, domain in [
    ("AccessControlAgent", "Access Control"),
    ("ApiSecurityAgent", "API Security"),
    ("ArchitectureAgent", "Architecture"),
    ("AuthenticationAgent", "Authentication"),
    ("BusinessLogicAgent", "Business Logic"),
    ("CommunicationAgent", "Communication"),
    ("ConfigurationAgent", "Configuration"),
    ("CryptographyAgent", "Cryptography"),
    ("DataProtectionAgent", "Data Protection"),
    ("ErrorHandlingAgent", "Error Handling"),
    ("FileHandlingAgent", "File Handling"),
    ("SessionManagementAgent", "Session Management"),
    ("ValidationAgent", "Input Validation"),
    ("WebFrontendAgent", "Web Frontend"),
    ("SelfContainedTokenAgent", "Token / OAuth"),
    ("OauthOidcAgent", "Token / OAuth"),
    ("CodeIntegrityAgent", "Code Integrity"),
    ("BuildDeploymentAgent", "Build / Deployment"),
    ("ClientSideAgent", "Client Side"),
    ("CloudContainerAgent", "Cloud / Container"),
    ("LLMSecurityAgent", "LLM Security"),
    ("AgenticSecurityAgent", "Agentic Security"),
]:
    _DOMAIN_MAP[suffix] = domain

_SAST_DOMAIN: Dict[str, str] = {
    "semgrep": "Static Analysis",
    "bandit": "Static Analysis",
    "gitleaks": "Secrets Management",
    "osv": "Dependency Security",
}

_CWE_DOMAIN: Dict[str, str] = {}
for cwe, domain in [
    ("CWE-22", "Access Control"),
    ("CWE-25", "Access Control"),
    ("CWE-32", "Access Control"),
    ("CWE-59", "Access Control"),
    ("CWE-73", "Access Control"),
    ("CWE-74", "Input Validation"),
    ("CWE-78", "Input Validation"),
    ("CWE-79", "Input Validation"),
    ("CWE-89", "Input Validation"),
    ("CWE-90", "Input Validation"),
    ("CWE-91", "Input Validation"),
    ("CWE-94", "Input Validation"),
    ("CWE-200", "Data Protection"),
    ("CWE-209", "Error Handling"),
    ("CWE-256", "Authentication"),
    ("CWE-287", "Authentication"),
    ("CWE-295", "Cryptography"),
    ("CWE-311", "Cryptography"),
    ("CWE-312", "Cryptography"),
    ("CWE-327", "Cryptography"),
    ("CWE-352", "Access Control"),
    ("CWE-384", "Session Management"),
    ("CWE-400", "API Security"),
    ("CWE-434", "File Handling"),
    ("CWE-502", "Input Validation"),
    ("CWE-601", "Input Validation"),
    ("CWE-639", "Access Control"),
    ("CWE-668", "Access Control"),
    ("CWE-732", "Access Control"),
    ("CWE-770", "API Security"),
    ("CWE-798", "Authentication"),
    ("CWE-862", "Access Control"),
    ("CWE-863", "Access Control"),
    ("CWE-918", "API Security"),
]:
    _CWE_DOMAIN[cwe] = domain


def resolve_domain(source: Optional[str], cwe: Optional[str]) -> str:
    if source:
        for suffix, domain in _DOMAIN_MAP.items():
            if suffix in (source or ""):
                return domain
    if cwe and cwe in _CWE_DOMAIN:
        return _CWE_DOMAIN[cwe]
    if source and (source or "").lower() in _SAST_DOMAIN:
        return _SAST_DOMAIN[(source or "").lower()]
    return "Uncategorized"


SEV_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
    "INFO": 1,
}
SAST_TOOLS = {"semgrep", "bandit", "gitleaks", "osv"}


# ── Node / edge build helpers ────────────────────────────────────────


def _node(id_: str, type_: str, label: str, column: int, **kw) -> Dict[str, Any]:
    return {"id": id_, "type": type_, "label": label, "column": column, **kw}


def _edge(src: str, tgt: str, value: int = 1, label: str = "") -> Dict[str, Any]:
    return {
        "id": f"edge:{src}->{tgt}",
        "source": src,
        "target": tgt,
        "value": value,
        "label": label,
    }


# ── Unified builder ──────────────────────────────────────────────────


def build_lineage_graph(
    *,
    raw_records: List[Dict[str, Any]],
    final_records: List[Dict[str, Any]],
    links: List[Dict[str, Any]],
    expanded_node_ids: Optional[List[str]] = None,
    focused_node_id: Optional[str] = None,
    filters: Optional[Dict[str, List[str]]] = None,
    max_nodes: int = 250,
    lineage_quality: str = "inferred",
    warnings: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build render-ready lineage graph from records.

    Returns dict with nodes, edges, lineage_quality, warnings,
    available_expansions.
    """
    expanded: Set[str] = set(expanded_node_ids or [])
    filter_set = _build_filter_set(filters)
    focused = focused_node_id

    # If focused mode, prune records to only what the focused node needs
    if focused:
        raw_records, final_records, links = _prune_focused(
            focused, raw_records, final_records, links
        )

    # Build stage nodes
    file_nodes, file_edges = _build_files(raw_records, expanded, filter_set)
    source_nodes, source_edges = _build_sources(raw_records, expanded, filter_set)
    domain_nodes, domain_edges = _build_domains(raw_records, expanded, filter_set)
    cons_nodes, cons_edges = _build_consolidation(links, expanded)
    output_nodes, output_edges = _build_outputs(
        raw_records, final_records, links, expanded, filter_set
    )

    nodes = file_nodes + source_nodes + domain_nodes + cons_nodes + output_nodes
    node_edges = file_edges + source_edges + domain_edges + cons_edges + output_edges

    # Node cap with overflow
    nodes, node_edges = _apply_node_cap(nodes, node_edges, max_nodes)

    # Build available_expansions
    avail: Dict[str, int] = {}
    for n in nodes:
        if n.get("has_children") and not n.get("expanded"):
            avail[n["id"]] = n.get("child_count", n.get("count", 0))

    return {
        "nodes": nodes,
        "edges": node_edges,
        "lineage_quality": lineage_quality,
        "warnings": warnings or ([f"Focused on: {focused}"] if focused else []),
        "available_expansions": avail,
    }


def _build_filter_set(filters: Optional[Dict[str, List[str]]]) -> Dict[str, Set[str]]:
    if not filters:
        return {}
    return {k: set(v) for k, v in filters.items() if v}


def _matches_filters(rec: Dict[str, Any], filter_set: Dict[str, Set[str]]) -> bool:
    if not filter_set:
        return True
    for key, values in filter_set.items():
        if key == "severity":
            if (rec.get("severity", "INFO") or "INFO").upper() not in values:
                return False
        elif key == "source":
            if (rec.get("source", "unknown") or "unknown") not in values:
                return False
        elif key == "domain":
            if resolve_domain(rec.get("source"), rec.get("cwe")) not in values:
                return False
        elif key == "status":
            # Only applies to links
            pass
        elif key == "file_path_contains":
            fp = (rec.get("file_path") or "").lower()
            if not any(v.lower() in fp for v in values):
                return False
        elif key == "text":
            txt = ((rec.get("title") or "") + " " + (rec.get("source") or "")).lower()
            if not any(v.lower() in txt for v in values):
                return False
    return True


# ── Prune for focus ──────────────────────────────────────────────────


def _prune_focused(
    focused: str,
    raw: List[Dict[str, Any]],
    final: List[Dict[str, Any]],
    links: List[Dict[str, Any]],
):
    """Keep only records relevant to the focused node."""
    # Find what node type we're focusing on
    if focused.startswith("final:"):
        ref = focused.replace("final:", "")
        f_recs = [r for r in final if r.get("lineage_ref") == ref]
        if not f_recs:
            # Try by title
            title = focused.split(":")[-1]
            f_recs = [r for r in final if r.get("title") == title]
        kept_raw_refs: Set[str] = set()
        for link in links:
            if link.get("final_ref") in {r.get("lineage_ref") for r in f_recs}:
                if link.get("raw_ref"):
                    kept_raw_refs.add(link["raw_ref"])
        kept_raw = [r for r in raw if r.get("lineage_ref") in kept_raw_refs]
        kept_links = [
            link
            for link in links
            if link.get("final_ref") in {r.get("lineage_ref") for r in f_recs}
        ]
        return kept_raw, f_recs, kept_links

    if focused.startswith("domain:"):
        domain = focused.replace("domain:", "")
        kept_raw = [
            r for r in raw if resolve_domain(r.get("source"), r.get("cwe")) == domain
        ]
        kept_raw_refs = {r.get("lineage_ref") for r in kept_raw}
        kept_links = [link for link in links if link.get("raw_ref") in kept_raw_refs]
        final_refs = {link.get("final_ref") for link in kept_links}
        kept_final = [r for r in final if r.get("lineage_ref") in final_refs]
        return kept_raw, kept_final, kept_links

    if focused.startswith("source:"):
        src = focused.replace("source:", "")
        kept_raw = [r for r in raw if (r.get("source") or "") == src]
        kept_raw_refs = {r.get("lineage_ref") for r in kept_raw}
        kept_links = [link for link in links if link.get("raw_ref") in kept_raw_refs]
        final_refs = {link.get("final_ref") for link in kept_links}
        kept_final = [r for r in final if r.get("lineage_ref") in final_refs]
        return kept_raw, kept_final, kept_links

    return raw, final, links


# ── Stage builders ───────────────────────────────────────────────────


def _build_files(
    raw: List[Dict[str, Any]], expanded: Set[str], filters: Dict[str, Set[str]]
):
    nodes, edges = [], []
    file_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in raw:
        if not _matches_filters(r, filters):
            continue
        file_map[r.get("file_path", "unknown") or "unknown"].append(r)

    if not file_map:
        return nodes, edges

    total_files = len(file_map)
    show_detail = total_files <= 10 or "file_group:*" in expanded

    for fp, records in sorted(file_map.items(), key=lambda x: -len(x[1])):
        short = fp.rsplit("/", 1)[-1] if "/" in fp else fp
        fid = f"file:{fp}"
        cnt = len(records)
        if show_detail:
            nodes.append(
                _node(
                    fid,
                    "file",
                    short,
                    0,
                    count=cnt,
                    expanded=fid in expanded,
                    expandable=False,
                )
            )
        else:
            d = "/".join(fp.split("/")[:-1]) if "/" in fp else "."
            gid = f"file_group:{d}"
            label = f"{d.split('/')[-1] if d != '.' else '.'}/ ({cnt} findings)"
            nodes.append(
                _node(
                    gid,
                    "file_group",
                    label,
                    0,
                    count=cnt,
                    expanded=gid in expanded,
                    expandable=True,
                    has_children=total_files > 10,
                    child_count=total_files,
                )
            )
            break  # one group node

    return nodes, edges


def _build_sources(
    raw: List[Dict[str, Any]], expanded: Set[str], filters: Dict[str, Set[str]]
):
    nodes, edges = [], []
    source_counts: Dict[str, int] = defaultdict(int)
    for r in raw:
        if not _matches_filters(r, filters):
            continue
        src = r.get("source", "unknown") or "unknown"
        source_counts[src] += 1

    llm_agents: Dict[str, int] = {}
    tool_counts: Dict[str, int] = {}
    for src, cnt in source_counts.items():
        if (src or "").lower() in SAST_TOOLS or (src or "").startswith("semgrep"):
            tool_counts[src] = cnt
        else:
            llm_agents[src] = cnt

    total_llm = sum(llm_agents.values())
    if total_llm:
        nodes.append(
            _node(
                "source:llm",
                "source",
                f"LLM ({total_llm})",
                1,
                count=total_llm,
                expanded="source:llm" in expanded,
                expandable=bool(llm_agents),
                has_children=bool(llm_agents),
                child_count=len(llm_agents),
            )
        )
        if "source:llm" in expanded:
            for agent, cnt in sorted(llm_agents.items(), key=lambda x: -x[1]):
                label = agent[:24]
                nodes.append(
                    _node(
                        f"source:llm:{agent}",
                        "source",
                        f"{label} ({cnt})",
                        1,
                        count=cnt,
                        expandable=False,
                    )
                )

    for tool, cnt in sorted(tool_counts.items(), key=lambda x: -x[1]):
        display = tool[:20]
        nodes.append(
            _node(
                f"source:{tool}",
                "source",
                f"{display} ({cnt})",
                1,
                count=cnt,
                expanded=f"source:{tool}" in expanded,
                expandable=len(raw) > 5,
            )
        )

    return nodes, edges


def _build_domains(
    raw: List[Dict[str, Any]], expanded: Set[str], filters: Dict[str, Set[str]]
):
    nodes, edges = [], []
    domain_counts: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in raw:
        if not _matches_filters(r, filters):
            continue
        domain = resolve_domain(r.get("source"), r.get("cwe"))
        domain_counts[domain].append(r)

    for domain, records in sorted(domain_counts.items(), key=lambda x: -len(x[1])):
        cnt = len(records)
        did = f"domain:{domain}"
        nodes.append(
            _node(
                did,
                "domain",
                f"{domain} ({cnt})",
                2,
                count=cnt,
                expanded=did in expanded,
                expandable=True,
                has_children=True,
                child_count=cnt,
            )
        )
        if did in expanded:
            # Show raw findings under this domain
            for r in records[:15]:  # cap expanded raw findings
                raw_title = (r.get("title") or "?")[:40]
                sev = (r.get("severity") or "INFO").upper()
                rid = f"raw:{r.get('lineage_ref', 'unknown')}"
                nodes.append(
                    _node(
                        rid,
                        "raw_finding",
                        f"{raw_title} [{sev}]",
                        3,
                        count=1,
                        expandable=False,
                        badges=[{"label": r.get("source", ""), "tone": "neutral"}],
                    )
                )
            if len(records) > 15:
                nodes.append(
                    _node(
                        f"domain:{domain}:overflow",
                        "overflow",
                        f"+{len(records) - 15} more",
                        3,
                        count=len(records) - 15,
                        expandable=True,
                    )
                )

    return nodes, edges


def _build_consolidation(links: List[Dict[str, Any]], expanded: Set[str]):
    nodes, edges = [], []
    merged = sum(1 for link in links if link.get("status") == "merged")
    dropped = sum(1 for link in links if link.get("status") == "dropped")
    passthrough = sum(
        1
        for link in links
        if link.get("status") == "passthrough" or not link.get("status")
    )

    if merged:
        nodes.append(
            _node("cons:merged", "cons", f"Merged ({merged})", 3, count=merged)
        )
    if dropped:
        nodes.append(
            _node("cons:dropped", "cons", f"Dropped ({dropped})", 3, count=dropped)
        )
    if passthrough:
        nodes.append(
            _node(
                "cons:passthrough",
                "cons",
                f"Passthrough ({passthrough})",
                3,
                count=passthrough,
            )
        )

    return nodes, edges


def _build_outputs(
    raw: List[Dict[str, Any]],
    final: List[Dict[str, Any]],
    links: List[Dict[str, Any]],
    expanded: Set[str],
    filters: Dict[str, Set[str]],
):
    nodes, edges = [], []
    show_individual = len(final) <= 25

    # Dropped count
    dropped_recs = [link for link in links if link.get("status") == "dropped"]
    for r in raw:
        if not _matches_filters(r, filters):
            continue

    if show_individual:
        for f in final:
            sev = (f.get("severity", "INFO") or "INFO").upper()
            fid = f"final:{f.get('lineage_ref', 'unknown')}"
            nodes.append(
                _node(
                    fid,
                    "final",
                    f"{(f.get('title','') or '?')[:40]} [{sev}]",
                    4,
                    count=1,
                    expanded=fid in expanded,
                    expandable=True,
                    has_children=True,
                    child_count=sum(
                        1
                        for link in links
                        if link.get("final_ref") == f.get("lineage_ref")
                    ),
                )
            )
            if fid in expanded:
                # Show contributing raw findings
                contrib = [
                    link
                    for link in links
                    if link.get("final_ref") == f.get("lineage_ref")
                ]
                for link in contrib[:10]:
                    raw_t = ""
                    for rf in raw:
                        if rf.get("lineage_ref") == link.get("raw_ref"):
                            raw_t = (rf.get("title") or "?")[:30]
                            break
                    nodes.append(
                        _node(
                            f"raw:{link.get('raw_ref', 'unknown')}",
                            "raw_finding",
                            f"{raw_t}",
                            4,
                            count=1,
                            expandable=False,
                        )
                    )
    else:
        sev_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in final:
            sev = (f.get("severity", "INFO") or "INFO").upper()
            sev_groups[sev].append(f)
        for sev, fs in sorted(sev_groups.items(), key=lambda x: -SEV_RANK.get(x[0], 0)):
            sid = f"final:sev:{sev}"
            nodes.append(
                _node(
                    sid,
                    "final",
                    f"{sev} ({len(fs)})",
                    4,
                    count=len(fs),
                    expanded=sid in expanded,
                    expandable=True,
                    has_children=True,
                    child_count=len(fs),
                )
            )

    if dropped_recs:
        nodes.append(
            _node(
                "final:dropped",
                "dropped",
                f"Dropped ({len(dropped_recs)})",
                4,
                count=len(dropped_recs),
                expanded="final:dropped" in expanded,
                expandable=True,
                has_children=True,
                child_count=len(dropped_recs),
            )
        )
        if "final:dropped" in expanded and dropped_recs:
            for link in dropped_recs[:10]:
                raw_t = ""
                for rf in raw:
                    if rf.get("lineage_ref") == link.get("raw_ref"):
                        raw_t = (rf.get("title") or "?")[:40]
                        break
                reason = link.get("drop_reason", "")
                nodes.append(
                    _node(
                        f"dropped:{link.get('raw_ref', 'unknown')}",
                        "dropped_finding",
                        f"✗ {raw_t}",
                        4,
                        count=1,
                        expandable=False,
                        badges=(
                            [{"label": reason[:60], "tone": "critical"}]
                            if reason
                            else []
                        ),
                    )
                )

    return nodes, edges


# ── Node cap with overflow ───────────────────────────────────────────


def _apply_node_cap(
    nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], max_nodes: int
):
    if len(nodes) <= max_nodes:
        return nodes, edges

    # Prioritize: keep aggregate nodes, push raw_finding overflow
    aggregate = [
        n for n in nodes if n["type"] not in ("raw_finding", "dropped_finding")
    ]
    detail = [n for n in nodes if n["type"] in ("raw_finding", "dropped_finding")]
    overflow = [n for n in nodes if n["type"] == "overflow"]

    available = max_nodes - len(aggregate) - len(overflow)
    if available < 0:
        # Even aggregates exceed limit — keep only columns 0-4 summary
        kept = []
        columns_seen = set()
        for n in aggregate:
            if n.get("expanded") and len(kept) < max_nodes:
                kept.append(n)
            elif n["column"] not in columns_seen:
                kept.append(n)
                columns_seen.add(n["column"])
        return kept[:max_nodes], edges

    kept_detail = detail[:available]
    result = aggregate + kept_detail + overflow

    # If there are clipped detail nodes, add an overflow node
    if len(detail) > available:
        overflow_count = len(detail) - available
        result.append(
            _node(
                "overflow:detail",
                "overflow",
                f"+{overflow_count} more findings",
                3,
                count=overflow_count,
                expandable=True,
            )
        )

    return result[:max_nodes], edges


# ── Top-level API for service layer ──────────────────────────────────


def build_lineage_from_records(
    raw_records: List[Dict[str, Any]],
    final_records: List[Dict[str, Any]],
    links: List[Dict[str, Any]],
    *,
    expanded_node_ids: Optional[List[str]] = None,
    focused_node_id: Optional[str] = None,
    filters: Optional[Dict[str, List[str]]] = None,
    max_nodes: int = 250,
) -> Dict[str, Any]:
    """Build lineage graph from structured lineage records."""
    return build_lineage_graph(
        raw_records=raw_records,
        final_records=final_records,
        links=links,
        expanded_node_ids=expanded_node_ids,
        focused_node_id=focused_node_id,
        filters=filters,
        max_nodes=max_nodes,
        lineage_quality="exact",
    )


def build_lineage_from_findings(
    sast_findings: List[Any],
    raw_llm_findings: List[Any],
    consolidated_findings: List[Any],
    *,
    flow_map: Optional[List[Dict[str, Any]]] = None,
    expanded_node_ids: Optional[List[str]] = None,
    focused_node_id: Optional[str] = None,
    filters: Optional[Dict[str, List[str]]] = None,
    max_nodes: int = 250,
) -> Dict[str, Any]:
    """Build inferred lineage from ORM/Pydantic findings."""
    all_raw = list(sast_findings) + list(raw_llm_findings)

    raw_records: List[Dict[str, Any]] = []
    for i, f in enumerate(all_raw):
        raw_records.append(
            {
                "lineage_ref": f"raw:inferred:{i}",
                "title": getattr(f, "title", "") or "",
                "source": getattr(f, "source", "")
                or getattr(f, "agent_name", "")
                or "unknown",
                "file_path": getattr(f, "file_path", "unknown") or "unknown",
                "severity": getattr(f, "severity", "INFO") or "INFO",
                "cwe": getattr(f, "cwe", "") or "",
                "line_number": getattr(f, "line_number", None),
            }
        )

    final_records: List[Dict[str, Any]] = []
    for i, f in enumerate(consolidated_findings):
        final_records.append(
            {
                "lineage_ref": f"final:inferred:{i}",
                "title": getattr(f, "title", "") or "",
                "severity": getattr(f, "severity", "INFO") or "INFO",
                "cwe": getattr(f, "cwe", "") or "",
            }
        )

    # Build links from flow_map if available, else direct
    links: List[Dict[str, Any]] = []
    if flow_map:
        for fm in flow_map:
            raw_title = fm.get("raw_title", "")
            status = (fm.get("status") or "passthrough").lower()
            cons_title = fm.get("consolidated_title", "")
            raw_ref = None
            for r in raw_records:
                if r["title"] == raw_title:
                    raw_ref = r["lineage_ref"]
                    break
            final_ref = None
            for r in final_records:
                if r["title"] == cons_title:
                    final_ref = r["lineage_ref"]
                    break
            links.append({"raw_ref": raw_ref, "final_ref": final_ref, "status": status})
    else:
        # No flow map: link all raw to first final
        for r in raw_records:
            first = final_records[0]["lineage_ref"] if final_records else None
            links.append(
                {"raw_ref": r["lineage_ref"], "final_ref": first, "status": "merged"}
            )

    return build_lineage_graph(
        raw_records=raw_records,
        final_records=final_records,
        links=links,
        expanded_node_ids=expanded_node_ids,
        focused_node_id=focused_node_id,
        filters=filters,
        max_nodes=max_nodes,
        lineage_quality="inferred",
        warnings=["Lineage inferred from legacy data."],
    )
