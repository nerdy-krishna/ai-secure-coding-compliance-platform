"""Pure construction of the code portion of analysis LLM envelopes."""

from __future__ import annotations

from typing import Any, List

from app.core.schemas import CodeChunk


CHUNK_ONLY_IF_LARGER_THAN = 150_000


def build_analysis_usage_unit_key(
    *,
    file_path: str,
    chunk_index: int,
    start_line: int,
    end_line: int,
    agent_name: str,
    lane: str,
    llm_config_id: object,
) -> str:
    """Identify one analysis invocation before the canonical key hashes it."""
    return (
        f"{file_path}::chunk:{chunk_index}:{start_line}-{end_line}"
        f"::agent:{agent_name}::lane:{lane}::llm:{llm_config_id}"
    )


def number_lines(code: str, start_line: int) -> str:
    lines = code.split("\n")
    width = len(str(start_line + len(lines) - 1))
    return "\n".join(
        f"{start_line + index:>{width}}| {line}" for index, line in enumerate(lines)
    )


def build_dependency_summary(
    file_path: str,
    dependency_graph: Any,
    repository_map: Any,
) -> str:
    if file_path not in dependency_graph:
        return ""
    dep_parts: List[str] = []
    for dep_path in dependency_graph.successors(file_path):
        dep_file_summary = repository_map.files.get(dep_path)
        if dep_file_summary and dep_file_summary.symbols:
            symbol_sigs = [
                f"  - {symbol.type} {symbol.name} (line {symbol.line_number})"
                for symbol in dep_file_summary.symbols[:15]
            ]
            dep_parts.append(f"# File: {dep_path}\n" + "\n".join(symbol_sigs))
    if not dep_parts:
        return ""
    return (
        "# --- [DEPENDENCY CONTEXT: symbols from imported files] ---\n"
        + "\n".join(dep_parts)
        + "\n# --- [END DEPENDENCY CONTEXT] ---\n\n"
    )


def build_code_chunks(
    file_path: str,
    file_content: str,
    repository_map: Any,
) -> list[CodeChunk]:
    file_summary = repository_map.files.get(file_path)
    if not file_summary:
        return []
    if (len(file_content) / 4) > CHUNK_ONLY_IF_LARGER_THAN:
        # Tree-sitter is a worker-only dependency; keep the import lazy so
        # pure envelope/identity helpers remain usable in the lean API image.
        from app.shared.analysis_tools.chunker import semantic_chunker

        return semantic_chunker(file_content, file_summary)
    return [
        {
            "symbol_name": file_path,
            "code": file_content,
            "start_line": 1,
            "end_line": len(file_content.splitlines()),
        }
    ]


def build_enriched_code(chunk: CodeChunk, dependency_summary: str) -> str:
    numbered_code = number_lines(chunk["code"], chunk["start_line"])
    code_under_review = (
        "=== CODE UNDER REVIEW "
        "(line-numbered; copy snippets WITHOUT the 'NNN| ' prefix) ===\n"
        f"{numbered_code}"
    )
    return (
        f"{dependency_summary}\n{code_under_review}"
        if dependency_summary
        else code_under_review
    )
