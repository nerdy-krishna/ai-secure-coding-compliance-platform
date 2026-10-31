"""One source of truth for "which language is this file, and who can read it".

Before this module the answer lived in three places that disagreed: an extension →
language map used for display, a hardcoded 15-extension Semgrep allow-list in the
scanner registry, and a different allow-list in the git path that silently dropped
anything else. A Kotlin, Rust or shell file therefore had a language, and often had
Semgrep rules in the database, but never reached a scanner.

Everything now derives from one table, including files whose language lives in their
*name* rather than their extension (`Dockerfile`, `Makefile`, `Jenkinsfile`,
`requirements.txt`, `.env`).
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterable, Optional

BANDIT = "bandit"
SEMGREP = "semgrep"
GITLEAKS = "gitleaks"
OSV = "osv"  # repository-level: OSV scans the manifest tree, not individual files

#: Per-file scanners. OSV is excluded on purpose: it runs once per repository against
#: the manifest tree, and the prescan records it under the "<repository>" input path.
ALL_SCANNERS: tuple[str, ...] = (BANDIT, SEMGREP, GITLEAKS)

#: extension → (language, scanners that can read it).
_EXTENSIONS: dict[str, tuple[str, frozenset[str]]] = {}


def _register(exts: Iterable[str], language: str, scanners: Iterable[str]) -> None:
    for ext in exts:
        _EXTENSIONS[ext.lower()] = (language, frozenset(scanners))


# --- languages Bandit parses natively ------------------------------------
_register((".py", ".pyi"), "python", (BANDIT, SEMGREP, GITLEAKS))

# --- languages Semgrep parses; also secret- and dependency-scanned ---------
_register(
    (".js", ".mjs", ".cjs", ".jsx"),
    "javascript",
    (SEMGREP, GITLEAKS),
)
_register((".ts", ".tsx", ".mts", ".cts"), "typescript", (SEMGREP, GITLEAKS))
_register((".java",), "java", (SEMGREP, GITLEAKS))
_register((".kt", ".kts"), "kotlin", (SEMGREP, GITLEAKS))
_register((".scala",), "scala", (SEMGREP, GITLEAKS))
_register((".go",), "go", (SEMGREP, GITLEAKS))
_register((".rb", ".rake"), "ruby", (SEMGREP, GITLEAKS))
_register((".php",), "php", (SEMGREP, GITLEAKS))
_register((".cs",), "csharp", (SEMGREP, GITLEAKS))
_register((".fs", ".fsx"), "fsharp", (SEMGREP, GITLEAKS))
_register((".vb",), "visualbasic", (SEMGREP, GITLEAKS))
_register((".c", ".h"), "c", (SEMGREP, GITLEAKS))
_register((".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".ipp"), "cpp", (SEMGREP, GITLEAKS))
_register((".rs",), "rust", (SEMGREP, GITLEAKS))
_register((".swift",), "swift", (SEMGREP, GITLEAKS))
_register((".m", ".mm"), "objectivec", (SEMGREP, GITLEAKS))
_register((".dart",), "dart", (SEMGREP, GITLEAKS))
_register((".lua",), "lua", (SEMGREP, GITLEAKS))
_register((".pl", ".pm"), "perl", (SEMGREP, GITLEAKS))
_register((".ex", ".exs"), "elixir", (SEMGREP, GITLEAKS))
_register((".erl", ".hrl"), "erlang", (SEMGREP, GITLEAKS))
_register((".hs", ".lhs"), "haskell", (SEMGREP, GITLEAKS))
_register((".clj", ".cljs", ".cljc"), "clojure", (SEMGREP, GITLEAKS))
_register((".groovy", ".gvy"), "groovy", (SEMGREP, GITLEAKS))
_register((".vue",), "vue", (SEMGREP, GITLEAKS))
_register((".svelte",), "svelte", (SEMGREP, GITLEAKS))
_register((".html", ".htm"), "html", (GITLEAKS,))
_register((".css", ".scss", ".sass", ".less"), "css", (GITLEAKS,))
_register((".sql",), "sql", (SEMGREP, GITLEAKS))
_register((".sol",), "solidity", (SEMGREP, GITLEAKS))
_register((".tf", ".tfvars", ".hcl"), "terraform", (SEMGREP, GITLEAKS))
_register((".graphql", ".gql"), "graphql", (GITLEAKS,))
_register((".sh", ".bash", ".zsh", ".ksh"), "shell", (GITLEAKS,))
_register((".ps1", ".psm1"), "powershell", (GITLEAKS,))
_register((".bat", ".cmd"), "batch", (GITLEAKS,))
_register((".r", ".rmd"), "r", (GITLEAKS,))

# --- configuration, data and docs: secrets live here ----------------------
_register((".json", ".json5"), "json", (GITLEAKS))
_register((".yaml", ".yml"), "yaml", (GITLEAKS,))
_register((".toml",), "toml", (GITLEAKS,))
_register((".ini", ".cfg", ".conf", ".properties"), "config", (GITLEAKS,))
_register((".xml", ".plist"), "xml", (GITLEAKS,))
_register((".env",), "dotenv", (GITLEAKS,))
_register((".md", ".markdown", ".txt", ".rst"), "text", (GITLEAKS,))
_register((".csv", ".tsv"), "tabular", (GITLEAKS,))
_register((".lock", ".sum"), "lockfile", (GITLEAKS,))

#: Files identified by *name* — no useful extension, or the extension is a
#: suffix the table above would misread (`requirements.txt` is not prose).
_FILENAMES: dict[str, tuple[str, frozenset[str]]] = {
    "dockerfile": ("dockerfile", frozenset({GITLEAKS})),
    "containerfile": ("dockerfile", frozenset({GITLEAKS})),
    "makefile": ("makefile", frozenset({GITLEAKS})),
    "gnumakefile": ("makefile", frozenset({GITLEAKS})),
    "cmakelists.txt": ("cmake", frozenset({GITLEAKS})),
    "jenkinsfile": ("groovy", frozenset({SEMGREP, GITLEAKS})),
    "vagrantfile": ("ruby", frozenset({SEMGREP, GITLEAKS})),
    "gemfile": ("ruby", frozenset({GITLEAKS})),
    "rakefile": ("ruby", frozenset({SEMGREP, GITLEAKS})),
    "podfile": ("ruby", frozenset({GITLEAKS})),
    "procfile": ("config", frozenset({GITLEAKS})),
    "requirements.txt": ("requirements", frozenset({GITLEAKS})),
    "requirements-dev.txt": ("requirements", frozenset({GITLEAKS})),
    "pipfile": ("requirements", frozenset({GITLEAKS})),
    "go.mod": ("gomod", frozenset({GITLEAKS})),
    "cargo.toml": ("cargo", frozenset({GITLEAKS})),
    "package.json": ("npm", frozenset({GITLEAKS})),
    "composer.json": ("composer", frozenset({GITLEAKS})),
    "pom.xml": ("maven", frozenset({GITLEAKS})),
    "build.gradle": ("gradle", frozenset({GITLEAKS})),
    "build.gradle.kts": ("gradle", frozenset({GITLEAKS})),
    ".env": ("dotenv", frozenset({GITLEAKS})),
    ".npmrc": ("npm", frozenset({GITLEAKS})),
    ".pypirc": ("config", frozenset({GITLEAKS})),
    ".htaccess": ("config", frozenset({GITLEAKS})),
    ".gitignore": ("config", frozenset()),
    ".dockerignore": ("config", frozenset()),
    ".editorconfig": ("config", frozenset()),
}

#: Languages for which the database may hold Semgrep rules. Used only to explain a
#: skip; the actual rule selection still queries ingested rules.
SEMGREP_LANGUAGES = frozenset(
    language for language, scanners in _EXTENSIONS.values() if SEMGREP in scanners
) | frozenset(
    language for language, scanners in _FILENAMES.values() if SEMGREP in scanners
)


def resolve(rel_path: str) -> tuple[Optional[str], frozenset[str]]:
    """Return ``(language, scanners)`` for a path.

    Name matching wins over extension matching, so `requirements.txt` is treated as a
    dependency manifest rather than prose and `Dockerfile` is recognised at all.
    """
    name = PurePosixPath(rel_path).name.lower()
    if name in _FILENAMES:
        return _FILENAMES[name]
    # `.env.local`, `.env.production` … are all dotenv files.
    if name == ".env" or name.startswith(".env."):
        return ("dotenv", frozenset({GITLEAKS}))
    suffix = PurePosixPath(name).suffix.lower()
    if suffix in _EXTENSIONS:
        return _EXTENSIONS[suffix]
    # Composite suffixes we care about: `.min.js` still resolves through `.js`,
    # but `foo.d.ts` should read as TypeScript rather than as a `.ts` unknown.
    if name.endswith(".d.ts"):
        return ("typescript", frozenset({SEMGREP, GITLEAKS}))
    return (None, frozenset())


def language_for(rel_path: str) -> Optional[str]:
    return resolve(rel_path)[0]


def scanners_for(rel_path: str) -> list[str]:
    """Scanners eligible for this path, in a stable order."""
    scanners = resolve(rel_path)[1]
    return [name for name in ALL_SCANNERS if name in scanners]


def extensions_for_language(language: str) -> set[str]:
    return {ext for ext, (lang, _) in _EXTENSIONS.items() if lang == language}
