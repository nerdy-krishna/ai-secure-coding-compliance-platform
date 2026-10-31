# src/app/shared/lib/files.py

import os
from typing import Optional

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".html": "html",
    ".css": "css",
    ".scss": "css",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".md": "markdown",
    ".sh": "shell",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rs": "rust",
    ".scala": "scala",
    ".pl": "perl",
    ".pm": "perl",
    ".r": "r",
    ".lua": "lua",
    ".sql": "sql",
    ".xml": "xml",
    ".dart": "dart",
    ".vue": "vue",
    ".svelte": "svelte",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hrl": "erlang",
    ".hs": "haskell",
    ".lhs": "haskell",
    ".clj": "clojure",
    ".cljs": "clojure",
    ".cljc": "clojure",
    ".fs": "fsharp",
    ".fsx": "fsharp",
    ".vb": "visualbasic",
    ".m": "objectivec",
    ".mm": "objectivecpp",
    ".groovy": "groovy",
    ".gvy": "groovy",
    ".sol": "solidity",
    ".tf": "terraform",
    ".hcl": "terraform",
    ".graphql": "graphql",
    ".gql": "graphql",
    ".toml": "toml",
    ".txt": "text",
}


def get_language_from_filename(filename: str) -> Optional[str]:
    """Language for a path, from the shared registry.

    The registry also knows name-only languages (`Dockerfile`, `Makefile`,
    `requirements.txt`) and the wider language set the scanners support, which the
    original extension table here did not.
    """
    if not filename:
        return None
    from app.shared.lib.language_registry import language_for

    resolved = language_for(filename)
    if resolved is not None:
        return resolved
    ext = os.path.splitext(filename)[1].lower()
    return LANGUAGE_EXTENSIONS.get(ext)


#: Compiled-binary magics. A shebang (`#!`) is deliberately NOT here: a script that
#: starts with `#!/usr/bin/env python3` is plain text and is exactly the kind of file
#: an audit needs to read. Rejecting it made every real-world Python, Node and shell
#: entry point unsubmittable.
_EXECUTABLE_MAGIC: tuple[bytes, ...] = (
    b"MZ",  # PE/DOS
    b"\x7fELF",  # ELF
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary / Java class
)

#: How much of the file is sampled to decide whether it is binary.
_BINARY_SAMPLE_BYTES = 8192
#: Below this share of printable bytes a decodable-as-latin-1 sample is treated as
#: binary rather than as unusual text.
_PRINTABLE_FLOOR = 0.85


def looks_binary(content: bytes) -> bool:
    """True only for content that is genuinely not text.

    Text files are what the scanners read, so this is intentionally conservative:
    NUL bytes, an undecodable UTF-8 body with a low printable ratio, or a compiled
    binary magic. Anything else is handed to the scanners and classified there.
    """
    if not content:
        return False
    sample = content[:_BINARY_SAMPLE_BYTES]
    if any(magic for magic in _EXECUTABLE_MAGIC if sample.startswith(magic)):
        return True
    if b"\x00" in sample:
        return True
    try:
        sample.decode("utf-8")
        return False
    except UnicodeDecodeError:
        printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
        return printable / len(sample) < _PRINTABLE_FLOOR


def source_line_at(body: Optional[str], line_number: Optional[int]) -> Optional[str]:
    """Return the stripped source line at a 1-based line number, if available."""
    if not body or not line_number or line_number < 1:
        return None
    lines = body.splitlines()
    if line_number > len(lines):
        return None
    snippet = lines[line_number - 1].strip()
    return snippet[:500] if snippet else None
