"""Deterministic, non-executing dependency-manifest evidence for patch plans."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Mapping

from app.shared.lib.patch_planner import PatchValidationCheck

if TYPE_CHECKING:
    from app.core.schemas import FixResult


MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 10
MAX_EVIDENCE_ITEM_CHARS = 200
_PYTHON_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?(.*)$")
_GO_REQUIRE = re.compile(r"^([A-Za-z0-9._~/-]+)\s+(v[^\s]+)")
_GRADLE_DEPENDENCY = re.compile(
    r"\b(?:api|implementation|compileOnly|runtimeOnly|testImplementation)\s*"
    r"(?:\(\s*)?['\"]([^'\"\s:]+:[^'\"\s:]+)(?::([^'\"\s]+))?['\"]"
)
_GEMFILE_DEPENDENCY = re.compile(
    r"^\s*gem\s*(?:\(\s*)?['\"]([^'\"]+)['\"]" r"(?:\s*,\s*['\"]([^'\"]+)['\"])?"
)


@dataclass
class DependencyInventory:
    declarations: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    evidence_files: set[str] = field(default_factory=set)
    parse_errors: set[str] = field(default_factory=set)

    def add(self, ecosystem: str, name: str, spec: str, source: str) -> None:
        normalized_name = _normalize_name(ecosystem, name)
        if not normalized_name:
            return
        self.declarations.setdefault(ecosystem, {}).setdefault(
            normalized_name, set()
        ).add(_normalize_spec(spec))
        self.evidence_files.add(source)


def _normalize_name(ecosystem: str, name: str) -> str:
    value = name.strip().lower()
    if ecosystem == "python":
        return re.sub(r"[-_.]+", "-", value)
    return value


def _normalize_spec(spec: str) -> str:
    return re.sub(r"\s+", "", spec.strip().lower())


def _display_list(values: set[str] | list[str]) -> str:
    ordered = sorted(
        re.sub(r"\s+", " ", str(value)).strip()[:MAX_EVIDENCE_ITEM_CHARS]
        for value in values
    )
    visible = ordered[:MAX_EVIDENCE_ITEMS]
    suffix = (
        f", and {len(ordered) - MAX_EVIDENCE_ITEMS} more"
        if len(ordered) > MAX_EVIDENCE_ITEMS
        else ""
    )
    return ", ".join(visible) + suffix


def _python_requirement(value: str) -> tuple[str, str] | None:
    candidate = value.split(";", 1)[0].strip()
    if not candidate or candidate.startswith(("-", "#")):
        return None
    match = _PYTHON_NAME.match(candidate)
    if not match:
        return None
    return match.group(1), match.group(2).strip()


def _npm_requirement(value: str) -> tuple[str, str] | None:
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.startswith("@"):
        separator = candidate.rfind("@")
        if separator <= candidate.find("/"):
            return candidate, ""
        return candidate[:separator], candidate[separator + 1 :]
    if "@" in candidate:
        name, spec = candidate.split("@", 1)
        return name, spec
    return candidate, ""


def _go_requirement(value: str) -> tuple[str, str] | None:
    candidate = value.strip()
    if "@" in candidate:
        name, spec = candidate.rsplit("@", 1)
        return name, spec
    parts = candidate.split()
    if len(parts) == 2:
        return parts[0], parts[1]
    return (candidate, "") if candidate else None


def _at_requirement(value: str) -> tuple[str, str] | None:
    candidate = value.strip()
    if not candidate:
        return None
    if "@" in candidate:
        name, spec = candidate.rsplit("@", 1)
        return (name, spec) if name else None
    parts = candidate.split(maxsplit=1)
    return (parts[0], parts[1] if len(parts) == 2 else "")


def _colon_requirement(value: str) -> tuple[str, str] | None:
    candidate = value.strip()
    if not candidate:
        return None
    if "@" in candidate:
        return _at_requirement(candidate)
    parts = candidate.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:-1]), parts[-1]
    if len(parts) == 2:
        return candidate, ""
    return None


def _php_requirement(value: str) -> tuple[str, str] | None:
    candidate = value.strip()
    if not candidate or "/" not in candidate:
        return None
    if "@" in candidate:
        return _at_requirement(candidate)
    if ":" in candidate:
        name, spec = candidate.rsplit(":", 1)
        return name, spec
    parts = candidate.split(maxsplit=1)
    return parts[0], parts[1] if len(parts) == 2 else ""


def _add_python_requirement(
    inventory: DependencyInventory, value: str, source: str
) -> None:
    parsed = _python_requirement(value)
    if parsed:
        inventory.add("python", parsed[0], parsed[1], source)


def _parse_pyproject(inventory: DependencyInventory, path: str, content: str) -> None:
    payload = tomllib.loads(content)
    project = payload.get("project") if isinstance(payload, dict) else None
    if isinstance(project, dict):
        dependencies = project.get("dependencies")
        if isinstance(dependencies, list):
            for value in dependencies:
                if isinstance(value, str):
                    _add_python_requirement(inventory, value, path)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    for value in values:
                        if isinstance(value, str):
                            _add_python_requirement(inventory, value, path)

    tool = payload.get("tool") if isinstance(payload, dict) else None
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if not isinstance(poetry, dict):
        return
    dependency_maps: list[dict] = []
    for key in ("dependencies", "dev-dependencies"):
        value = poetry.get(key)
        if isinstance(value, dict):
            dependency_maps.append(value)
    groups = poetry.get("group")
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
                dependency_maps.append(group["dependencies"])
    for dependencies in dependency_maps:
        for name, value in dependencies.items():
            if str(name).lower() == "python":
                continue
            if isinstance(value, str):
                spec = value
            elif isinstance(value, dict):
                spec = str(value.get("version") or "")
            else:
                spec = ""
            inventory.add("python", str(name), spec, path)


def _parse_requirements(
    inventory: DependencyInventory, path: str, content: str
) -> None:
    for line in content.splitlines():
        _add_python_requirement(inventory, line, path)


def _parse_pipfile(inventory: DependencyInventory, path: str, content: str) -> None:
    payload = tomllib.loads(content)
    for key in ("packages", "dev-packages"):
        dependencies = payload.get(key) if isinstance(payload, dict) else None
        if not isinstance(dependencies, dict):
            continue
        for name, value in dependencies.items():
            if isinstance(value, str):
                spec = "" if value == "*" else value
            elif isinstance(value, dict):
                spec = str(value.get("version") or "")
            else:
                spec = ""
            inventory.add("python", str(name), spec, path)


def _parse_package_json(
    inventory: DependencyInventory, path: str, content: str
) -> None:
    payload = json.loads(content)
    if not isinstance(payload, dict):
        return
    for key in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        values = payload.get(key)
        if not isinstance(values, dict):
            continue
        for name, spec in values.items():
            if isinstance(name, str) and isinstance(spec, str):
                inventory.add("npm", name, spec, path)


def _parse_go_mod(inventory: DependencyInventory, path: str, content: str) -> None:
    for line in content.splitlines():
        stripped = line.split("//", 1)[0].strip()
        if stripped.startswith("require "):
            stripped = stripped.removeprefix("require ").strip()
        match = _GO_REQUIRE.match(stripped)
        if match:
            inventory.add("go", match.group(1), match.group(2), path)


def _local_xml_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _parse_maven_pom(inventory: DependencyInventory, path: str, content: str) -> None:
    root = ET.fromstring(content)
    for dependency in root.iter():
        if _local_xml_name(dependency.tag) != "dependency":
            continue
        values = {
            _local_xml_name(child.tag): (child.text or "").strip()
            for child in dependency
        }
        group = values.get("groupid", "")
        artifact = values.get("artifactid", "")
        if group and artifact:
            inventory.add(
                "java", f"{group}:{artifact}", values.get("version", ""), path
            )


def _parse_gradle(inventory: DependencyInventory, path: str, content: str) -> None:
    for match in _GRADLE_DEPENDENCY.finditer(content):
        inventory.add("java", match.group(1), match.group(2) or "", path)


def _parse_dotnet_project(
    inventory: DependencyInventory, path: str, content: str
) -> None:
    root = ET.fromstring(content)
    for element in root.iter():
        if _local_xml_name(element.tag) != "packagereference":
            continue
        name = element.attrib.get("Include") or element.attrib.get("Update") or ""
        version = element.attrib.get("Version") or ""
        if not version:
            for child in element:
                if _local_xml_name(child.tag) == "version":
                    version = (child.text or "").strip()
                    break
        if name:
            inventory.add("dotnet", name, version, path)


def _parse_gemfile(inventory: DependencyInventory, path: str, content: str) -> None:
    for line in content.splitlines():
        match = _GEMFILE_DEPENDENCY.match(line)
        if match:
            inventory.add("ruby", match.group(1), match.group(2) or "", path)


def _parse_composer_json(
    inventory: DependencyInventory, path: str, content: str
) -> None:
    payload = json.loads(content)
    if not isinstance(payload, dict):
        return
    for key in ("require", "require-dev"):
        values = payload.get(key)
        if not isinstance(values, dict):
            continue
        for name, spec in values.items():
            if (
                isinstance(name, str)
                and isinstance(spec, str)
                and name.lower() != "php"
                and "/" in name
            ):
                inventory.add("php", name, spec, path)


def build_dependency_inventory(files: Mapping[str, str]) -> DependencyInventory:
    inventory = DependencyInventory()
    for path, content in sorted(files.items()):
        if len(content.encode("utf-8", "replace")) > MAX_MANIFEST_BYTES:
            continue
        normalized = path.replace("\\", "/")
        name = PurePosixPath(normalized).name.lower()
        try:
            if name == "pyproject.toml":
                _parse_pyproject(inventory, normalized, content)
            elif name == "pipfile":
                _parse_pipfile(inventory, normalized, content)
            elif name.endswith(".txt") and (
                name.startswith("requirements")
                or "requirements" in PurePosixPath(normalized).parts
            ):
                _parse_requirements(inventory, normalized, content)
            elif name == "package.json":
                _parse_package_json(inventory, normalized, content)
            elif name == "go.mod":
                _parse_go_mod(inventory, normalized, content)
            elif name == "pom.xml":
                _parse_maven_pom(inventory, normalized, content)
            elif name in {"build.gradle", "build.gradle.kts"}:
                _parse_gradle(inventory, normalized, content)
            elif name.endswith((".csproj", ".fsproj", ".vbproj")):
                _parse_dotnet_project(inventory, normalized, content)
            elif name == "gemfile":
                _parse_gemfile(inventory, normalized, content)
            elif name == "composer.json":
                _parse_composer_json(inventory, normalized, content)
        except (
            json.JSONDecodeError,
            tomllib.TOMLDecodeError,
            ET.ParseError,
            RecursionError,
            TypeError,
            ValueError,
        ):
            inventory.parse_errors.add(normalized)
    return inventory


def _candidate_ecosystem(candidate: FixResult) -> str | None:
    language = (candidate.language or "").lower()
    if language == "python":
        return "python"
    if language in {"javascript", "typescript"}:
        return "npm"
    if language == "go":
        return "go"
    if language in {"java", "kotlin"}:
        return "java"
    if language in {"csharp", "c_sharp", "fsharp", "visualbasic", "dotnet"}:
        return "dotnet"
    if language == "ruby":
        return "ruby"
    if language == "php":
        return "php"
    suffix = PurePosixPath(candidate.finding.file_path).suffix.lower()
    return {
        ".py": "python",
        ".js": "npm",
        ".jsx": "npm",
        ".ts": "npm",
        ".tsx": "npm",
        ".go": "go",
        ".java": "java",
        ".kt": "java",
        ".kts": "java",
        ".cs": "dotnet",
        ".fs": "dotnet",
        ".vb": "dotnet",
        ".rb": "ruby",
        ".php": "php",
    }.get(suffix)


def _parse_candidate_requirement(ecosystem: str, value: str) -> tuple[str, str] | None:
    if ecosystem == "python":
        return _python_requirement(value)
    if ecosystem == "npm":
        return _npm_requirement(value)
    if ecosystem == "go":
        return _go_requirement(value)
    if ecosystem == "java":
        return _colon_requirement(value)
    if ecosystem in {"dotnet", "ruby"}:
        return _at_requirement(value)
    if ecosystem == "php":
        return _php_requirement(value)
    return None


def _compatible(ecosystem: str, required: str, declared: str) -> bool:
    required_spec = _normalize_spec(required)
    declared_spec = _normalize_spec(declared)
    if not required_spec:
        return True
    if required_spec == declared_spec:
        return True
    if ecosystem == "python":
        required_terms = {term for term in required_spec.split(",") if term}
        declared_terms = {term for term in declared_spec.split(",") if term}
        return bool(required_terms) and required_terms.issubset(declared_terms)
    return False


def validate_candidate_dependencies(
    candidate: FixResult, inventory: DependencyInventory
) -> PatchValidationCheck:
    ecosystem = _candidate_ecosystem(candidate)
    candidate_id = str(candidate.candidate_id or "unknown")
    if ecosystem is None:
        return PatchValidationCheck(
            stage="dependency_requirements",
            status="not_run",
            tool="manifest-inventory",
            detail=(
                f"Candidate {candidate_id} has dependency requirements but its "
                "manifest ecosystem cannot be determined."
            ),
        )

    missing: list[str] = []
    ambiguous: list[str] = []
    declarations = inventory.declarations.get(ecosystem, {})
    for requirement in candidate.required_dependencies:
        parsed = _parse_candidate_requirement(ecosystem, requirement)
        if parsed is None:
            ambiguous.append(requirement)
            continue
        name, required_spec = parsed
        declared_specs = declarations.get(_normalize_name(ecosystem, name))
        if not declared_specs:
            missing.append(requirement)
            continue
        if not any(
            _compatible(ecosystem, required_spec, declared)
            for declared in declared_specs
        ):
            ambiguous.append(requirement)

    if missing or ambiguous:
        parts = []
        if missing:
            parts.append(f"not declared: {_display_list(missing)}")
        if ambiguous:
            parts.append(f"version compatibility unproven: {_display_list(ambiguous)}")
        if inventory.parse_errors:
            parts.append(
                f"unparseable manifests: {_display_list(inventory.parse_errors)}"
            )
        return PatchValidationCheck(
            stage="dependency_requirements",
            status="failed",
            tool="manifest-inventory",
            detail=f"Candidate {candidate_id} dependency requirements failed ({'; '.join(parts)}).",
        )

    evidence = _display_list(inventory.evidence_files) or "manifest inventory"
    return PatchValidationCheck(
        stage="dependency_requirements",
        status="passed",
        tool="manifest-inventory",
        detail=(
            f"Candidate {candidate_id} dependencies are already declared with "
            f"compatible constraints in {evidence}."
        ),
        return_code=0,
    )
