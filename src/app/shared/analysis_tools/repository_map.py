# src/app/shared/analysis_tools/repository_map.py

import concurrent.futures
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Tuple
import fnmatch

from pydantic import BaseModel, Field
from tree_sitter import Language, Node, Parser, Tree
from tree_sitter_languages import get_language


# Custom exception for grammar loading issues
class GrammarLoadingError(Exception):
    pass


# --- ADD a global ignore list ---
IGNORE_PATTERNS = {
    # Lock files
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "go.sum",
    "Pipfile.lock",
    "poetry.lock",
    # Dependency directories
    "node_modules/*",
    "venv/*",
    ".venv/*",
    "vendor/*",
    # Build artifacts
    "dist/*",
    "build/*",
    "*.pyc",
    "*.pyo",
    "*.o",
    # IDE/Editor configs
    ".vscode/*",
    ".idea/*",
    # OS files
    ".DS_Store",
    "Thumbs.db",
}


# --- Pydantic Models for Repository Structure ---


class Symbol(BaseModel):
    """Represents a defined symbol in a file, like a function or class."""

    name: str = Field(..., description="The name of the symbol.")
    type: str = Field(
        ..., description="The type of the symbol (e.g., 'function', 'class')."
    )
    line_number: int = Field(
        ..., description="The line number where the symbol is defined."
    )
    end_line_number: int = Field(
        ..., description="The line number where the symbol's definition ends."
    )


class FileSummary(BaseModel):
    """A summary of a single file's structure."""

    path: str = Field(..., description="The path to the file.")
    imports: List[str] = Field(
        default_factory=list, description="A list of imported modules."
    )
    symbols: List[Symbol] = Field(
        default_factory=list, description="A list of symbols defined in the file."
    )
    errors: List[str] = Field(
        default_factory=list, description="Any errors encountered during parsing."
    )


class RepositoryMap(BaseModel):
    """The complete map of the repository's structure."""

    files: Dict[str, FileSummary] = Field(
        default_factory=dict,
        description="A mapping from file paths to their summaries.",
    )


# --- Language-Specific Queries for Tree-sitter ---

LANGUAGE_QUERIES = {
    "python": {
        "imports": """
            (import_statement name: (dotted_name) @import)
            (import_from_statement module_name: (dotted_name) @import)
        """,
        "symbols": """
            (function_definition name: (identifier) @name) @type
            (class_definition name: (identifier) @name) @type
        """,
    },
    "java": {
        "imports": "(import_declaration (scoped_identifier) @import)",
        "symbols": """
            (class_declaration name: (identifier) @name) @type
            (method_declaration name: (identifier) @name) @type
            (interface_declaration name: (identifier) @name) @type
        """,
    },
    "javascript": {
        "imports": """
            (import_statement source: (string) @import)
            (call_expression function: (identifier) @_func (#eq? @_func "require") arguments: (arguments (string) @import))
        """,
        "symbols": """
            (function_declaration name: (identifier) @name) @type
            (class_declaration name: (identifier) @name) @type
            (method_definition name: (property_identifier) @name) @type
            (variable_declarator name: (identifier) @name value: [(arrow_function) (function)]) @type
        """,
    },
    "typescript": {
        "imports": """
            (import_statement source: (string) @import)
        """,
        "symbols": """
            (function_declaration name: (identifier) @name) @type
            (class_declaration name: (type_identifier) @name) @type
            (method_definition name: (property_identifier) @name) @type
            (interface_declaration name: (type_identifier) @name) @type
        """,
    },
    "go": {
        "imports": "(import_spec (interpreted_string_literal) @import)",
        "symbols": """
            (function_declaration name: (identifier) @name) @type
            (method_declaration name: (field_identifier) @name) @type
            (type_spec (type_identifier) @name) @type
        """,
    },
    "c_sharp": {
        "imports": "(using_directive (name_equals) @import)",
        "symbols": """
            (class_declaration name: (identifier) @name) @type
            (method_declaration name: (identifier) @name) @type
            (interface_declaration name: (identifier) @name) @type
            (struct_declaration name: (identifier) @name) @type
        """,
    },
    "c_plus_plus": {
        "imports": "(preproc_include path: [ (string_literal) (system_lib_string) ] @import)",
        "symbols": """
            (function_definition declarator: (function_declarator declarator: (identifier) @name)) @type
            (class_specifier name: (type_identifier) @name) @type
            (struct_specifier name: (type_identifier) @name) @type
        """,
    },
    "php": {
        "imports": """
            (use_declaration) @import
            (require_expression) @import
            (include_expression) @import
        """,
        "symbols": """
            (function_definition name: (name) @name) @type
            (class_declaration name: (name) @name) @type
            (method_declaration name: (name) @name) @type
        """,
    },
    "ruby": {
        "imports": """
            (call method: (identifier) @_func (#eq? @_func "require") argument: (string) @import)
        """,
        "symbols": """
            (class name: (constant) @name) @type
            (module name: (constant) @name) @type
            (method name: (identifier) @name) @type
        """,
    },
    "rust": {
        "imports": "(use_declaration (use_wildcard) @import)",
        "symbols": """
            (function_item name: (identifier) @name) @type
            (struct_item name: (type_identifier) @name) @type
            (enum_item name: (type_identifier) @name) @type
            (impl_item) @type
        """,
    },
    "kotlin": {
        "imports": "(import_header (identifier) @import)",
        "symbols": """
            (class_declaration name: (simple_identifier) @name) @type
            (function_declaration name: (simple_identifier) @name) @type
        """,
    },
    "swift": {
        "imports": "(import_declaration import_path: (identifier) @import)",
        "symbols": """
            (class_declaration name: (identifier) @name) @type
            (struct_declaration name: (identifier) @name) @type
            (function_declaration name: (identifier) @name) @type
        """,
    },
    "sql": {
        "imports": "",  # SQL does not have a standard import mechanism
        "symbols": """
            (create_function_statement) @type
            (create_procedure_statement) @type
            (create_table_statement) @type
            (create_view_statement) @type
        """,
    },
    "bash": {
        "imports": '(command name: (command_name (word) @_cmd) (#eq? @_cmd "source") argument: (word) @import)',
        "symbols": "(function_definition (word) @name) @type",
    },
    "html": {
        "imports": """
            (element (start_tag (tag_name) @_tag (#eq? @_tag "script")) (attribute (attribute_name) @_attr (#eq? @_attr "src") (quoted_attribute_value (attribute_value) @import)))
            (element (self_closing_tag (tag_name) @_tag (#eq? @_tag "link")) (attribute (attribute_name) @_attr (#eq? @_attr "href") (quoted_attribute_value (attribute_value) @import)))
        """,
        "symbols": "",  # Not applicable in the same way
    },
    "css": {
        "imports": "(import_statement (string_value) @import)",
        "symbols": "(class_selector (class_name) @name) @type",
    },
    "r": {"imports": "", "symbols": ""},
    "matlab": {"imports": "", "symbols": ""},
    "terraform": {
        "imports": """
            (module_call name: (string_literal) @import)
        """,
        "symbols": """
            (resource_block type: (identifier) @name) @type
            (variable_block name: (string_literal) @name) @type
            (data_block type: (string_literal) @name) @type
            (provider_block name: (string_literal) @name) @type
            (output_block name: (string_literal) @name) @type
        """,
    },
    # --- ADDED for new file types ---
    "yaml": {"imports": "", "symbols": ""},
    "json": {"imports": "", "symbols": ""},
    "dockerfile": {"imports": "", "symbols": ""},
    "ini": {"imports": "", "symbols": ""},
    "toml": {"imports": "", "symbols": ""},
}


class RepositoryMappingEngine:
    """
    Parses a collection of source code files using tree-sitter to create a
    structured map of the repository, identifying imports and key symbols.
    """

    def __init__(self):
        self.supported_languages: Dict[str, Language] = {}
        self.logger = logging.getLogger(__name__)

    def _get_language_handler(self, file_path: str) -> Tuple[str, Language]:
        """
        Determines the tree-sitter language based on the file extension.
        Raises GrammarLoadingError if the language cannot be loaded.
        """
        # Handle extension-less files first
        filename = Path(file_path).name
        if filename == "Dockerfile":
            lang_name = "dockerfile"
        else:
            lang_map = {
                ".py": "python",
                ".java": "java",
                ".js": "javascript",
                ".mjs": "javascript",
                ".cs": "c_sharp",
                ".sql": "sql",
                ".ts": "typescript",
                ".tsx": "typescript",
                ".go": "go",
                ".cpp": "c_plus_plus",
                ".hpp": "c_plus_plus",
                ".h": "c_plus_plus",
                ".c": "c",
                ".php": "php",
                ".kt": "kotlin",
                ".kts": "kotlin",
                ".swift": "swift",
                ".rb": "ruby",
                ".r": "r",
                ".rs": "rust",
                ".m": "matlab",
                ".sh": "bash",
                ".html": "html",
                ".css": "css",
                ".tf": "terraform",
                ".tfvars": "terraform",
                ".yml": "yaml",
                ".yaml": "yaml",
                ".json": "json",
                ".ini": "ini",
                ".conf": "toml",
            }
            extension = Path(file_path).suffix
            lang_name = lang_map.get(extension)

        if not lang_name:
            raise GrammarLoadingError(f"No language configured for file: {file_path}")

        try:
            self.logger.info("grammar.load lang=%s", lang_name)
            language = get_language(
                lang_name
            )  # This is where the original error occurs
            if (
                language is None
            ):  # Defensive check, get_language usually raises on failure
                raise GrammarLoadingError(f"get_language('{lang_name}') returned None")
            return lang_name, language
        except Exception as e:
            # This catches the original "TypeError: __init__()..." and other loading issues
            self.logger.error("grammar.load_failed lang=%s", lang_name, exc_info=True)
            raise GrammarLoadingError(
                f"Could not load grammar for language '{lang_name}': {e}"
            ) from e

    def _execute_query(
        self, tree: Tree, language: Language, lang_name: str, query_name: str
    ) -> List[Tuple[Node, str]]:
        """Executes a named tree-sitter query and returns the captures."""
        if lang_name == "csharp":
            lang_name = "c_sharp"
        if lang_name == "cpp":
            lang_name = "c_plus_plus"

        query_string = LANGUAGE_QUERIES.get(lang_name, {}).get(query_name)
        if not query_string:
            return []

        try:
            query = language.query(query_string)
            captures = query.captures(tree.root_node)
            return captures  # type: ignore
        except Exception as e:
            self.logger.error(
                f"Failed to execute query '{query_name}' for {lang_name}: {e}"
            )
            return []

    def _parse_file(self, file_path: str, content: str) -> FileSummary:
        """Parses a single file and extracts its structure."""
        summary = FileSummary(path=file_path)

        # V02.2.1: enforce per-file content size cap (2 MB)
        if len(content) > 2_000_000:
            summary.errors.append("Skipped: file exceeds 2MB cap")
            return summary

        # _get_language_handler now raises GrammarLoadingError if it fails.
        # The error will propagate up to create_map if not caught here.
        lang_name, language = self._get_language_handler(file_path)

        # V15.4.1: construct a local Parser per call to avoid shared-state
        # concurrency hazards when the engine is used across threads/tasks.
        parser = Parser()
        parser.set_language(language)  # type: ignore

        try:
            # V02.4.1: enforce a 5-second parse budget via a background thread.
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(parser.parse, bytes(content, "utf8"))
                tree = future.result(timeout=5.0)
        except concurrent.futures.TimeoutError:
            summary.errors.append("Tree-sitter parse timed out")
            return summary
        except Exception as e:
            summary.errors.append(f"Tree-sitter failed to parse file: {e}")
            return summary

        import_captures = self._execute_query(tree, language, lang_name, "imports")
        for node, _ in import_captures:
            # FIX: Check if node.text is not None before decoding
            if node.text:
                summary.imports.append(node.text.decode("utf8").strip("'\"<>"))

        # V02.3.2: cap imports list
        summary.imports = summary.imports[:1000]

        symbol_captures = self._execute_query(tree, language, lang_name, "symbols")

        # V02.2.3: total line count for range validation
        total_lines = content.count("\n") + 1

        processed_symbols = {}
        for node, capture_name in symbol_captures:
            if capture_name == "type":
                symbol_type = node.type
                name_node = next(
                    (
                        n
                        for n, c in symbol_captures
                        if c == "name"
                        and n.start_byte >= node.start_byte
                        and n.end_byte <= node.end_byte
                    ),
                    None,
                )

                if name_node and name_node.text:
                    # FIX: Check if name_node.text is not None before decoding
                    symbol_name = name_node.text.decode("utf8")
                    line_number = node.start_point[0] + 1
                    end_line_number = node.end_point[0] + 1

                    # V02.2.3: enforce consistent line-range bounds
                    if not (1 <= line_number <= end_line_number <= total_lines):
                        continue

                    if (symbol_name, line_number) not in processed_symbols:
                        symbol = Symbol(
                            name=symbol_name,
                            type=symbol_type,
                            line_number=line_number,
                            end_line_number=end_line_number,
                        )
                        summary.symbols.append(symbol)
                        processed_symbols[(symbol_name, line_number)] = symbol

        # V02.3.2: cap symbols list
        summary.symbols = summary.symbols[:5000]

        return summary

    def create_map(self, files: Dict[str, str]) -> RepositoryMap:
        """
        Creates a complete repository map from a dictionary of file paths to content.
        If any file fails critical parsing due to grammar issues, this method
        will raise a GrammarLoadingError.
        """
        # V02.2.1: enforce upper bound on number of files processed
        MAX_FILES = 20_000
        MAX_PATH_LEN = 1024

        self.logger.info("repo_map.start file_count=%d", len(files))

        if len(files) > MAX_FILES:
            raise ValueError(
                f"Repository exceeds maximum file limit of {MAX_FILES} files."
            )

        repo_map = RepositoryMap()
        for file_path, content in files.items():
            # V02.2.1: skip paths that exceed the length cap
            if len(file_path) > MAX_PATH_LEN:
                continue

            # Use a short hash of the path for log messages to avoid log-injection
            # via attacker-controlled filenames (V16.2.5 / V16.4.1).
            path_hash = hashlib.sha256(file_path.encode()).hexdigest()[:12]

            # Check against ignore patterns first
            if any(fnmatch.fnmatch(file_path, pattern) for pattern in IGNORE_PATTERNS):
                self.logger.debug("repo_map.skip_ignored path_hash=%s", path_hash)
                repo_map.files[file_path] = FileSummary(
                    path=file_path,
                    errors=["Skipped: File matches global ignore pattern."],
                )
                continue

            if not content.strip():
                self.logger.debug("repo_map.skip_empty path_hash=%s", path_hash)
                repo_map.files[file_path] = FileSummary(
                    path=file_path, errors=["Skipped empty file."]
                )
                continue

            self.logger.debug("repo_map.parse path_hash=%s", path_hash)
            try:
                file_summary = self._parse_file(file_path, content)
                repo_map.files[file_path] = file_summary
            except GrammarLoadingError as e:
                # Instead of halting, log a warning and create a placeholder summary.
                self.logger.warning("repo_map.no_grammar path_hash=%s", path_hash)
                repo_map.files[file_path] = FileSummary(
                    path=file_path,
                    errors=[
                        f"Skipped: No language grammar found for this file type. Error: {e}"
                    ],
                )
            except (
                Exception
            ) as e:  # Catch other unexpected errors during _parse_file for this specific file
                self.logger.error(
                    "repo_map.parse_error path_hash=%s", path_hash, exc_info=True
                )
                summary = FileSummary(path=file_path)
                summary.errors.append(f"Unexpected error during parsing: {str(e)}")
                repo_map.files[file_path] = summary
                # Continue with other files for non-GrammarLoadingError issues

        self.logger.info("Repository mapping complete.")
        return repo_map


# --- Call-site extraction (#79) -------------------------------------------
#
# Cross-file finding validation needs the call graph, not just the symbol
# index. `_CALLS_QUERIES` captures call-expression callee names per
# language; `extract_call_sites` runs the query for one file. Queries are
# deliberately conservative — a grammar that rejects one degrades to no
# call sites for that language (callers simply aren't found), never an
# error. Co-located with `LANGUAGE_QUERIES` as part of the repo-map
# query set.

_CALLS_QUERIES: Dict[str, str] = {
    "python": """
        (call function: (identifier) @name)
        (call function: (attribute attribute: (identifier) @name))
    """,
    "java": "(method_invocation name: (identifier) @name)",
    "javascript": """
        (call_expression function: (identifier) @name)
        (call_expression function: (member_expression property: (property_identifier) @name))
    """,
    "typescript": """
        (call_expression function: (identifier) @name)
        (call_expression function: (member_expression property: (property_identifier) @name))
    """,
    "go": """
        (call_expression function: (identifier) @name)
        (call_expression function: (selector_expression field: (field_identifier) @name))
    """,
    "c": "(call_expression function: (identifier) @name)",
    "c_plus_plus": """
        (call_expression function: (identifier) @name)
        (call_expression function: (field_expression field: (field_identifier) @name))
    """,
    "c_sharp": """
        (invocation_expression function: (identifier) @name)
        (invocation_expression function: (member_access_expression name: (identifier) @name))
    """,
    "php": """
        (function_call_expression function: (name) @name)
        (member_call_expression name: (name) @name)
    """,
    "ruby": "(call method: (identifier) @name)",
    "rust": """
        (call_expression function: (identifier) @name)
        (call_expression function: (field_expression field: (field_identifier) @name))
        (call_expression function: (scoped_identifier name: (identifier) @name))
    """,
}


class CallSite(BaseModel):
    """One call expression found in a file: the callee name + its line."""

    name: str = Field(..., description="The callee identifier.")
    line_number: int = Field(..., description="1-based line of the call.")


def extract_call_sites(file_path: str, content: str) -> List[CallSite]:
    """Return the call sites in one file (callee name + line number).

    Best-effort and deterministic: an unknown language, a missing
    `calls` query, a parse failure, or a query that the bundled grammar
    rejects all yield an empty list rather than raising — so a caller
    that can't be resolved simply isn't found.
    """
    if not content.strip():
        return []
    engine = RepositoryMappingEngine()
    try:
        lang_name, language = engine._get_language_handler(file_path)
    except GrammarLoadingError:
        return []
    query_string = _CALLS_QUERIES.get(lang_name)
    if not query_string:
        return []
    parser = Parser()
    parser.set_language(language)  # type: ignore
    try:
        tree = parser.parse(bytes(content, "utf8"))
    except Exception:  # noqa: BLE001 — never raise out of extraction
        return []
    try:
        captures = language.query(query_string).captures(tree.root_node)
    except Exception as exc:  # noqa: BLE001 — bad query → no call sites
        logging.getLogger(__name__).warning(
            "calls query failed for %s: %s", lang_name, exc
        )
        return []
    sites: List[CallSite] = []
    for node, capture_name in captures:
        if capture_name == "name" and node.text:
            sites.append(
                CallSite(
                    name=node.text.decode("utf8", "replace"),
                    line_number=node.start_point[0] + 1,
                )
            )
    return sites[:20_000]
