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
    """Infers language from file extension."""
    if not filename:
        return None
    ext = os.path.splitext(filename)[1].lower()
    return LANGUAGE_EXTENSIONS.get(ext)
