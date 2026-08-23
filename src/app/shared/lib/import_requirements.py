"""Bounded, non-executing import and local-name evidence for patch candidates."""

from __future__ import annotations

import ast
import builtins
import posixpath
import re
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Mapping

from app.shared.lib.dependency_requirements import DependencyInventory
from app.shared.lib.patch_planner import PatchValidationCheck, normalize_relative_path

if TYPE_CHECKING:
    from app.core.schemas import FixResult


MAX_SOURCE_FILES = 20_000
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_IMPORTS = 100
MAX_IMPORT_CHARS = 1_000
MAX_EVIDENCE_ITEMS = 10
MAX_EVIDENCE_ITEM_CHARS = 200

_JS_IMPORT = re.compile(
    r"(?:^|[;\n])\s*(?:"
    r"import\s+(?P<clause>[^;\n]*?)\s+from\s+"
    r"|import\s*\(\s*"
    r"|import\s+"
    r"|(?:const|let|var)\s+(?P<require_clause>[^=;\n]+?)\s*=\s*require\s*\(\s*"
    r"|require\s*\(\s*)"
    r"(?P<quote>['\"])(?P<module>[^'\"\r\n]+)(?P=quote)\s*\)?",
    re.MULTILINE,
)
_JAVA_IMPORT = re.compile(
    r"(?:^|\n)\s*import\s+(?P<static>static\s+)?"
    r"(?P<module>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$*][\w$]*)+)\s*;",
    re.MULTILINE,
)
_JS_EXPORT = re.compile(
    r"\bexport\s+(?:declare\s+)?(?:async\s+)?"
    r"(?:function|class|const|let|var|interface|type|enum)\s+([A-Za-z_$][\w$]*)"
)
_JS_EXPORT_LIST = re.compile(r"\bexport\s*\{([^}]*)\}")
_JS_COMMON_EXPORT = re.compile(r"\b(?:exports|module\.exports)\.([A-Za-z_$][\w$]*)\s*=")
_JAVA_PACKAGE = re.compile(r"\bpackage\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;")
_JAVA_TYPE = re.compile(
    r"\b(?:public\s+)?(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)"
)
_GO_MODULE = re.compile(r"(?m)^\s*module\s+([^\s]+)\s*$")
_GO_IMPORT_SPEC = re.compile(
    r"^(?:[A-Za-z_][\w]*|[._])?\s*(?P<quote>[`\"])(?P<module>[^`\"]+)(?P=quote)$"
)
_GO_STDLIB = {
    "bytes",
    "context",
    "crypto",
    "database",
    "embed",
    "encoding",
    "errors",
    "expvar",
    "flag",
    "fmt",
    "hash",
    "html",
    "image",
    "io",
    "log",
    "math",
    "mime",
    "net",
    "os",
    "path",
    "plugin",
    "reflect",
    "regexp",
    "runtime",
    "sort",
    "strconv",
    "strings",
    "sync",
    "syscall",
    "testing",
    "text",
    "time",
    "unicode",
    "unsafe",
}
_NODE_BUILTINS = {
    "assert",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "crypto",
    "dns",
    "events",
    "fs",
    "http",
    "https",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "querystring",
    "readline",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "worker_threads",
    "zlib",
}


@dataclass(frozen=True)
class _ImportRequest:
    statement: str
    module: str
    names: tuple[str, ...] = ()
    wildcard: bool = False
    static: bool = False


@dataclass
class StaticImportInventory:
    """Read-only projection of importable repository modules and declarations."""

    files: dict[str, str] = field(default_factory=dict)
    dependency_inventory: DependencyInventory = field(
        default_factory=DependencyInventory
    )
    skipped_files: set[str] = field(default_factory=set)
    python_exports: dict[str, set[str] | None] = field(default_factory=dict)
    javascript_exports: dict[str, set[str] | None] = field(default_factory=dict)
    java_types: dict[str, str] = field(default_factory=dict)
    java_packages: set[str] = field(default_factory=set)
    go_modules: dict[str, str] = field(default_factory=dict)
    go_packages: dict[str, str] = field(default_factory=dict)


def _display_list(values: list[str] | set[str]) -> str:
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


def _python_exports(content: str) -> set[str] | None:
    try:
        module = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return None
    exports: set[str] = set()
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            exports.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    exports.add(target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    continue
                exports.add(alias.asname or alias.name.split(".", 1)[0])
    return exports


def _python_external_names(content: str) -> set[str] | None:
    """Return loaded bare names not declared inside a bounded snippet."""
    try:
        module = ast.parse(textwrap.dedent(content))
    except (SyntaxError, ValueError, RecursionError):
        return None
    loaded = {
        node.id
        for node in ast.walk(module)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    bound = {
        node.id
        for node in ast.walk(module)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }
    for node in ast.walk(module):
        if isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name != "*":
                    bound.add(alias.asname or alias.name.split(".", 1)[0])
    return loaded - bound - set(dir(builtins))


def _javascript_exports(content: str) -> set[str]:
    exports = set(_JS_EXPORT.findall(content))
    exports.update(_JS_COMMON_EXPORT.findall(content))
    for match in _JS_EXPORT_LIST.finditer(content):
        for item in match.group(1).split(","):
            name = item.strip().split(" as ", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                exports.add(name)
    if re.search(r"\bexport\s+default\b|\bmodule\.exports\s*=", content):
        exports.add("default")
    return exports


def build_static_import_inventory(
    files: Mapping[str, str], dependency_inventory: DependencyInventory
) -> StaticImportInventory:
    """Build import evidence without importing modules or evaluating source code."""
    inventory = StaticImportInventory(dependency_inventory=dependency_inventory)
    bounded_files: list[tuple[str, str]] = []
    for index, (raw_path, content) in enumerate(sorted(files.items())):
        normalized = normalize_relative_path(raw_path)
        if normalized is None:
            continue
        if (
            index >= MAX_SOURCE_FILES
            or len(content.encode("utf-8", "replace")) > MAX_SOURCE_BYTES
        ):
            inventory.skipped_files.add(normalized)
            continue
        inventory.files[normalized] = content
        bounded_files.append((normalized, content))
        suffix = PurePosixPath(normalized).suffix.lower()
        if suffix == ".py":
            inventory.python_exports[normalized] = _python_exports(content)
        elif suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            inventory.javascript_exports[normalized] = _javascript_exports(content)
        elif suffix == ".java":
            package_match = _JAVA_PACKAGE.search(content)
            package = package_match.group(1) if package_match else ""
            if package:
                inventory.java_packages.add(package)
            for type_name in _JAVA_TYPE.findall(content):
                qualified = f"{package}.{type_name}" if package else type_name
                inventory.java_types[qualified] = normalized
        elif PurePosixPath(normalized).name == "go.mod":
            match = _GO_MODULE.search(content)
            if match:
                inventory.go_modules[match.group(1)] = str(
                    PurePosixPath(normalized).parent
                )
    for normalized, _content in bounded_files:
        if PurePosixPath(normalized).suffix.lower() != ".go":
            continue
        directory = str(PurePosixPath(normalized).parent)
        for module, root in inventory.go_modules.items():
            if root == ".":
                relative = "" if directory == "." else directory.removeprefix("./")
            elif directory == root:
                relative = ""
            elif directory.startswith(f"{root}/"):
                relative = directory[len(root) + 1 :]
            else:
                continue
            import_path = f"{module}/{relative}" if relative else module
            inventory.go_packages[import_path] = directory
    return inventory


def _candidate_language(candidate: FixResult) -> str:
    language = (candidate.language or "").lower()
    if language:
        return language
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
    }.get(PurePosixPath(candidate.finding.file_path).suffix.lower(), "")


def _python_requests(value: str) -> list[_ImportRequest] | None:
    try:
        module = ast.parse(value.strip())
    except (SyntaxError, ValueError, RecursionError):
        return None
    if not module.body or any(
        not isinstance(node, (ast.Import, ast.ImportFrom)) for node in module.body
    ):
        return None
    requests: list[_ImportRequest] = []
    for node in module.body:
        if isinstance(node, ast.Import):
            requests.extend(
                _ImportRequest(statement=value, module=alias.name)
                for alias in node.names
            )
        else:
            names = tuple(alias.name for alias in node.names)
            requests.append(
                _ImportRequest(
                    statement=value,
                    module="." * node.level + (node.module or ""),
                    names=names,
                    wildcard="*" in names,
                )
            )
    return requests


def _javascript_request(match: re.Match[str], statement: str) -> _ImportRequest:
    clause = (match.group("clause") or match.group("require_clause") or "").strip()
    names: list[str] = []
    if clause:
        named = re.search(r"\{([^}]*)\}", clause)
        if named:
            names.extend(
                item.strip().split(" as ", 1)[0].strip()
                for item in named.group(1).split(",")
                if item.strip()
            )
        remainder = re.sub(r"\{[^}]*\}", "", clause).strip(" ,")
        remainder = re.sub(r"^type(?:\s+|$)", "", remainder)
        if (
            match.group("require_clause") is None
            and remainder
            and not remainder.startswith("*")
        ):
            names.append("default")
    return _ImportRequest(
        statement=statement,
        module=match.group("module"),
        names=tuple(names),
    )


def _javascript_requests(value: str) -> list[_ImportRequest] | None:
    matches = list(_JS_IMPORT.finditer(value))
    if not matches:
        return None
    unmatched = value
    for match in reversed(matches):
        unmatched = unmatched[: match.start()] + unmatched[match.end() :]
    if unmatched.strip(" ;\r\n\t"):
        return None
    return [_javascript_request(match, value) for match in matches]


def _java_requests(value: str) -> list[_ImportRequest] | None:
    matches = list(_JAVA_IMPORT.finditer(value))
    if not matches:
        return None
    unmatched = value
    for match in reversed(matches):
        unmatched = unmatched[: match.start()] + unmatched[match.end() :]
    if unmatched.strip(" \r\n\t"):
        return None
    return [
        _ImportRequest(
            statement=value,
            module=match.group("module"),
            wildcard=match.group("module").endswith(".*"),
            static=bool(match.group("static")),
        )
        for match in matches
    ]


def _go_requests(value: str, *, strict: bool) -> list[_ImportRequest] | None:
    requests: list[_ImportRequest] = []
    in_block = False
    unmatched: list[str] = []
    for line in value.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped == "import (":
            in_block = True
            continue
        candidate = stripped
        if stripped.startswith("import "):
            candidate = stripped.removeprefix("import ").strip()
        elif not in_block:
            unmatched.append(stripped)
            continue
        match = _GO_IMPORT_SPEC.fullmatch(candidate)
        if match:
            requests.append(
                _ImportRequest(statement=line.strip(), module=match.group("module"))
            )
        else:
            unmatched.append(stripped)
    if in_block or (strict and unmatched):
        return None
    return requests or None


def _parse_required_import(language: str, value: str) -> list[_ImportRequest] | None:
    if language == "python":
        return _python_requests(value)
    if language in {"javascript", "typescript"}:
        return _javascript_requests(value)
    if language == "java":
        return _java_requests(value)
    if language == "go":
        return _go_requests(value, strict=True)
    return None


def _introduced_imports(language: str, replacement: str) -> list[_ImportRequest]:
    if language == "python":
        for candidate in (
            textwrap.dedent(replacement),
            textwrap.indent(textwrap.dedent(replacement), "    "),
        ):
            source = (
                candidate
                if candidate == textwrap.dedent(replacement)
                else f"def _candidate_scope():\n{candidate}"
            )
            try:
                module = ast.parse(source)
            except (SyntaxError, ValueError, RecursionError):
                continue
            requests: list[_ImportRequest] = []
            for node in ast.walk(module):
                if isinstance(node, ast.Import):
                    requests.extend(
                        _ImportRequest(statement=ast.unparse(node), module=alias.name)
                        for alias in node.names
                    )
                elif isinstance(node, ast.ImportFrom):
                    names = tuple(alias.name for alias in node.names)
                    requests.append(
                        _ImportRequest(
                            statement=ast.unparse(node),
                            module="." * node.level + (node.module or ""),
                            names=names,
                            wildcard="*" in names,
                        )
                    )
            return requests
        return []
    if language in {"javascript", "typescript"}:
        return [
            _javascript_request(match, match.group(0).strip())
            for match in _JS_IMPORT.finditer(replacement)
        ]
    if language == "java":
        return [
            _ImportRequest(
                statement=match.group(0).strip(),
                module=match.group("module"),
                wildcard=match.group("module").endswith(".*"),
                static=bool(match.group("static")),
            )
            for match in _JAVA_IMPORT.finditer(replacement)
        ]
    if language == "go":
        return _go_requests(replacement, strict=False) or []
    return []


def _python_local_candidates(target_path: str, module: str) -> list[str]:
    target_dir = str(PurePosixPath(target_path).parent)
    leading = len(module) - len(module.lstrip("."))
    dotted = module[leading:]
    parts = [part for part in dotted.split(".") if part]
    bases: list[str] = []
    if leading:
        base = target_dir
        for _ in range(max(0, leading - 1)):
            base = posixpath.dirname(base)
        bases.append(posixpath.join(base, *parts))
    else:
        bases.append(posixpath.join(*parts) if parts else "")
        bases.append(posixpath.join(target_dir, *parts))
    candidates: list[str] = []
    for base in dict.fromkeys(bases):
        if not base:
            continue
        candidates.extend((f"{base}.py", posixpath.join(base, "__init__.py")))
    return list(dict.fromkeys(candidates))


def _resolve_python(
    request: _ImportRequest, target_path: str, inventory: StaticImportInventory
) -> tuple[bool, str]:
    if request.wildcard:
        return False, f"wildcard import has unbounded names: {request.statement}"
    local_paths = [
        path
        for path in _python_local_candidates(target_path, request.module)
        if path in inventory.python_exports
    ]
    if len(local_paths) > 1:
        return False, f"local module is ambiguous: {request.module}"
    if local_paths:
        path = local_paths[0]
        exports = inventory.python_exports[path]
        if exports is None:
            return False, f"local module could not be parsed: {path}"
        missing = []
        for name in request.names:
            submodule = posixpath.join(
                path.removesuffix("/__init__.py").removesuffix(".py"), name
            )
            if name not in exports and not any(
                candidate in inventory.python_exports
                for candidate in (
                    f"{submodule}.py",
                    posixpath.join(submodule, "__init__.py"),
                )
            ):
                missing.append(name)
        if missing:
            return (
                False,
                f"local names not exported by {path}: {_display_list(missing)}",
            )
        return True, path

    root = request.module.lstrip(".").split(".", 1)[0]
    if request.module.startswith("."):
        return False, f"relative module is absent from snapshot: {request.module}"
    if root in sys.stdlib_module_names:
        return True, f"Python standard library module {root}"
    normalized = re.sub(r"[-_.]+", "-", root.lower())
    if normalized in inventory.dependency_inventory.declarations.get("python", {}):
        return True, f"declared Python dependency {normalized}"
    return (
        False,
        f"module has no local, standard-library, or manifest evidence: {request.module}",
    )


def _javascript_local_candidates(target_path: str, module: str) -> list[str]:
    base = posixpath.normpath(posixpath.join(posixpath.dirname(target_path), module))
    suffix = PurePosixPath(base).suffix.lower()
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return [base]
    extensions = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
    return [f"{base}{suffix}" for suffix in extensions] + [
        posixpath.join(base, f"index{suffix}") for suffix in extensions
    ]


def _npm_package(module: str) -> str:
    parts = module.split("/")
    return "/".join(parts[:2]) if module.startswith("@") else parts[0]


def _resolve_javascript(
    request: _ImportRequest, target_path: str, inventory: StaticImportInventory
) -> tuple[bool, str]:
    if request.module.startswith(("./", "../")):
        paths = [
            path
            for path in _javascript_local_candidates(target_path, request.module)
            if path in inventory.javascript_exports
        ]
        if len(paths) != 1:
            reason = "ambiguous" if paths else "absent"
            return False, f"relative module is {reason} in snapshot: {request.module}"
        path = paths[0]
        exports = inventory.javascript_exports[path]
        missing = [name for name in request.names if name not in (exports or set())]
        if missing:
            return (
                False,
                f"local names not exported by {path}: {_display_list(missing)}",
            )
        return True, path
    root = request.module.removeprefix("node:").split("/", 1)[0]
    if request.module.startswith("node:") or root in _NODE_BUILTINS:
        return True, f"Node.js built-in module {request.module}"
    package = _npm_package(request.module).lower()
    if package in inventory.dependency_inventory.declarations.get("npm", {}):
        return True, f"declared npm dependency {package}"
    return (
        False,
        f"module has no local, built-in, or manifest evidence: {request.module}",
    )


def _resolve_java(
    request: _ImportRequest, inventory: StaticImportInventory
) -> tuple[bool, str]:
    module = request.module
    owner = module[:-2] if module.endswith(".*") else module
    if request.static and not request.wildcard and "." in owner:
        owner = owner.rsplit(".", 1)[0]
    if owner in inventory.java_types:
        return True, inventory.java_types[owner]
    if module.endswith(".*") and owner in inventory.java_packages:
        return True, f"local Java package {owner}"
    if owner.startswith(("java.", "javax.", "jdk.")):
        return True, f"JDK namespace {owner.split('.', 1)[0]}"
    for coordinate in inventory.dependency_inventory.declarations.get("java", {}):
        group = coordinate.split(":", 1)[0]
        if owner == group or owner.startswith(f"{group}."):
            return True, f"declared Java dependency group {group}"
    return False, f"type/package has no local, JDK, or manifest evidence: {module}"


def _resolve_go(
    request: _ImportRequest, inventory: StaticImportInventory
) -> tuple[bool, str]:
    module = request.module
    if module in inventory.go_packages:
        return True, f"local Go package {module}"
    if module.split("/", 1)[0] in _GO_STDLIB:
        return True, f"Go standard library package {module}"
    normalized_module = module.lower()
    for required_module in inventory.dependency_inventory.declarations.get("go", {}):
        if normalized_module == required_module or normalized_module.startswith(
            f"{required_module}/"
        ):
            return True, f"declared Go module {required_module}"
    return (
        False,
        f"package has no local, standard-library, or manifest evidence: {module}",
    )


def validate_candidate_imports(
    candidate: FixResult, inventory: StaticImportInventory
) -> PatchValidationCheck:
    """Fail closed unless required and replacement-introduced imports resolve."""
    candidate_id = str(candidate.candidate_id or "unknown")
    language = _candidate_language(candidate)
    required = list(candidate.required_imports)
    malformed: list[str] = []
    requests: list[_ImportRequest] = []
    if len(required) > MAX_IMPORTS:
        malformed.append(f"more than {MAX_IMPORTS} required imports")
    for value in required[:MAX_IMPORTS]:
        if not value.strip() or len(value) > MAX_IMPORT_CHARS:
            malformed.append(value or "empty import")
            continue
        parsed = _parse_required_import(language, value)
        if parsed is None:
            malformed.append(value)
        else:
            requests.extend(parsed)

    original_keys = {
        (request.module, request.names, request.wildcard, request.static)
        for request in _introduced_imports(
            language, candidate.suggestion.original_snippet
        )
    }
    introduced = [
        request
        for request in _introduced_imports(language, candidate.suggestion.code)
        if (request.module, request.names, request.wildcard, request.static)
        not in original_keys
    ]
    requests.extend(introduced[:MAX_IMPORTS])
    if len(introduced) > MAX_IMPORTS:
        malformed.append(f"more than {MAX_IMPORTS} replacement imports")
    if len(requests) > MAX_IMPORTS:
        requests = requests[:MAX_IMPORTS]
        malformed.append(f"more than {MAX_IMPORTS} resolved import declarations")
    if language not in {"python", "javascript", "typescript", "java", "go"}:
        malformed.append(
            f"unsupported import grammar for {language or 'unknown language'}"
        )

    unresolved: list[str] = []
    evidence: set[str] = set()
    target_path = normalize_relative_path(candidate.finding.file_path)
    if target_path is None:
        unresolved.append("invalid target path")
    else:
        if language == "python" and not requests and not required:
            original_names = _python_external_names(
                candidate.suggestion.original_snippet
            )
            replacement_names = _python_external_names(candidate.suggestion.code)
            if original_names is not None and replacement_names is not None:
                target_bindings = inventory.python_exports.get(target_path)
                for name in sorted(replacement_names - original_names):
                    if target_bindings is None or name not in target_bindings:
                        unresolved.append(
                            f"new bare symbol has no declaration or import evidence: {name}"
                        )
        unique_requests = {
            (request.module, request.names, request.wildcard, request.static): request
            for request in requests
        }.values()
        for request in unique_requests:
            if language == "python":
                passed, detail = _resolve_python(request, target_path, inventory)
            elif language in {"javascript", "typescript"}:
                passed, detail = _resolve_javascript(request, target_path, inventory)
            elif language == "java":
                passed, detail = _resolve_java(request, inventory)
            elif language == "go":
                passed, detail = _resolve_go(request, inventory)
            else:
                passed, detail = False, f"unsupported import: {request.statement}"
            if passed:
                evidence.add(detail)
            else:
                unresolved.append(detail)

    if unresolved and inventory.skipped_files:
        unresolved.append(
            f"snapshot files exceeded resolver bounds: {_display_list(inventory.skipped_files)}"
        )
    if malformed or unresolved:
        parts = []
        if malformed:
            parts.append(
                f"malformed/unprovable declarations: {_display_list(malformed)}"
            )
        if unresolved:
            parts.append(f"unresolved: {_display_list(unresolved)}")
        return PatchValidationCheck(
            stage="import_requirements",
            status="failed",
            tool="static-import-resolver",
            detail=f"Candidate {candidate_id} import requirements failed ({'; '.join(parts)}).",
        )
    detail = (
        f"Candidate {candidate_id} imports resolve against bounded static evidence: "
        f"{_display_list(evidence)}."
        if evidence
        else f"Candidate {candidate_id} introduces no unresolved imports or bare symbols."
    )
    return PatchValidationCheck(
        stage="import_requirements",
        status="passed",
        tool="static-import-resolver",
        detail=detail,
        return_code=0,
    )
