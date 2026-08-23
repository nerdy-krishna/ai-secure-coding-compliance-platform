"""Networkless validation-job runner used by the dedicated sandbox image.

This module is intentionally standard-library only. The validation image copies
this file, not the SCCAP application, and receives no SCCAP environment file.
"""

from __future__ import annotations

import json
import os
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 110 * 1024 * 1024
MAX_FILES = 5_000
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_TIMEOUT_SECONDS = 120
MAX_CONCURRENT_JOBS = 3
MAX_COMPILER_FILES = 2_000
MAX_COMPILER_ARG_BYTES = 256 * 1024
MAX_OPEN_FILES = 256
CHILD_INFRASTRUCTURE_ERROR = 125
CHILD_TOOL_MISSING = 126
SANDBOX_UID = int(os.environ.get("SCCAP_VALIDATION_CHILD_UID", "1002"))
SANDBOX_GID = int(os.environ.get("SCCAP_VALIDATION_CHILD_GID", "1002"))
RUNNER_PATH = "/opt/sccap-validation/runner.py"

PROFILE_COMMANDS: dict[str, tuple[str, ...]] = {
    "python_compile": ("python", "-I", "-m", "compileall", "-q", "."),
    "python_pytest": (
        "python",
        "-I",
        "-m",
        "pytest",
        "-q",
        "--disable-warnings",
        "--maxfail=1",
    ),
    "javascript_syntax": (
        "python",
        "-I",
        RUNNER_PATH,
        "--child-profile",
        "javascript_syntax",
    ),
    "typescript_check": (
        "python",
        "-I",
        RUNNER_PATH,
        "--child-profile",
        "typescript_check",
    ),
    "go_compile": (
        "python",
        "-I",
        RUNNER_PATH,
        "--child-profile",
        "go_compile",
    ),
    "java_compile": (
        "python",
        "-I",
        RUNNER_PATH,
        "--child-profile",
        "java_compile",
    ),
}
PROFILE_TOOLS = {
    "python_compile": "python",
    "python_pytest": "pytest",
    "javascript_syntax": "node",
    "typescript_check": "tsc",
    "go_compile": "go",
    "java_compile": "javac",
}
PROFILE_VERSION_COMMANDS = {
    "python_compile": ("python", "--version"),
    "python_pytest": ("python", "-m", "pytest", "--version"),
    "javascript_syntax": ("node", "--version"),
    "typescript_check": ("tsc", "--version"),
    "go_compile": ("go", "version"),
    "java_compile": ("javac", "-version"),
}
_TOOL_VERSION_CACHE: dict[str, str | None] = {}


def _safe_path(root: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative.replace("\\", "/"))
    if (
        candidate.is_absolute()
        or not relative
        or ".." in candidate.parts
        or any(ord(character) < 32 for character in relative)
    ):
        raise ValueError("invalid relative file path")
    target = root.joinpath(*candidate.parts)
    if root not in target.parents:
        raise ValueError("file path escapes validation workspace")
    return target


def _bounded_request(payload: dict[str, Any]) -> tuple[dict[str, str], list[str], int]:
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported validation job schema")
    files = payload.get("files")
    profiles = payload.get("profiles")
    if not isinstance(files, dict) or not isinstance(profiles, list):
        raise ValueError("validation job requires files and profiles")
    if len(files) > MAX_FILES:
        raise ValueError("validation job exceeds file-count limit")
    total = 0
    checked_files: dict[str, str] = {}
    for path, content in files.items():
        if not isinstance(path, str) or not isinstance(content, str):
            raise ValueError("validation files must be text path/content pairs")
        total += len(content.encode("utf-8", "replace"))
        if total > MAX_TOTAL_BYTES:
            raise ValueError("validation job exceeds total-byte limit")
        checked_files[path] = content
    checked_profiles: list[str] = []
    for profile in profiles:
        if not isinstance(profile, str) or profile not in PROFILE_COMMANDS:
            raise ValueError("validation profile is not allowlisted")
        if profile not in checked_profiles:
            checked_profiles.append(profile)
    timeout = payload.get("timeout_seconds", 60)
    if not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError("validation timeout is outside the allowed range")
    return checked_files, checked_profiles, timeout


def _child_setup(timeout_seconds: int) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (timeout_seconds, timeout_seconds + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_OPEN_FILES, MAX_OPEN_FILES))
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(SANDBOX_GID)
        os.setuid(SANDBOX_UID)


def _source_paths(workspace: Path, suffixes: tuple[str, ...]) -> list[str]:
    paths = [
        f"./{path.relative_to(workspace).as_posix()}"
        for path in workspace.rglob("*")
        if path.is_file() and path.name.lower().endswith(suffixes)
    ]
    paths.sort()
    if len(paths) > MAX_COMPILER_FILES or sum(map(len, paths)) > MAX_COMPILER_ARG_BYTES:
        raise ValueError("compiler input exceeds the bounded argument limit")
    return paths


def _run_tool(command: list[str], environment: dict[str, str] | None = None) -> int:
    completed = subprocess.run(  # noqa: S603 - fixed tools and flags only
        command,
        stdin=subprocess.DEVNULL,
        shell=False,
        check=False,
        env=environment,
    )
    return completed.returncode


def _run_child_profile(profile: str, workspace: Path) -> int:
    """Execute a fixed compiler adapter without evaluating repository scripts."""
    if profile == "javascript_syntax":
        for path in _source_paths(workspace, (".js", ".mjs", ".cjs")):
            return_code = _run_tool(["node", "--check", path])
            if return_code:
                return return_code
        return 0
    if profile == "typescript_check":
        command = ["tsc", "--noEmit", "--pretty", "false"]
        if (workspace / "tsconfig.json").is_file():
            command.extend(["--project", "./tsconfig.json"])
        else:
            command.extend(["--jsx", "preserve"])
            source_paths = _source_paths(
                workspace, (".ts", ".tsx", ".mts", ".cts", ".jsx")
            )
            if any(path.endswith(".jsx") for path in source_paths):
                command.append("--allowJs")
            command.extend(source_paths)
        return _run_tool(command)
    if profile == "go_compile":
        environment = dict(os.environ)
        environment.update(
            {
                "CGO_ENABLED": "0",
                "GOCACHE": str(workspace / ".sccap-go-cache"),
                "GOMODCACHE": str(workspace / ".sccap-go-modcache"),
                "GONOPROXY": "none",
                "GONOSUMDB": "*",
                "GOPROXY": "off",
                "GOSUMDB": "off",
                "GOTOOLCHAIN": "local",
                "GOVCS": "off",
            }
        )
        if not (workspace / "go.mod").is_file():
            environment["GO111MODULE"] = "off"
        # The fixed wrapper replaces the compiled test binary, proving package
        # compilation without executing uploaded init or test code.
        return _run_tool(
            ["go", "test", "-run", "^$", "-exec", "/usr/bin/true", "./..."],
            environment,
        )
    if profile == "java_compile":
        output_dir = workspace / ".sccap-java-classes"
        output_dir.mkdir(mode=0o700)
        command = [
            "javac",
            "-proc:none",
            "-implicit:none",
            "-d",
            str(output_dir),
        ]
        command.extend(_source_paths(workspace, (".java",)))
        return _run_tool(command)
    raise ValueError("unsupported child validation profile")


def _tool_version(profile: str) -> str | None:
    if profile in _TOOL_VERSION_CACHE:
        return _TOOL_VERSION_CACHE[profile]
    version_command = PROFILE_VERSION_COMMANDS.get(profile)
    if version_command is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed version commands only
            version_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            check=False,
            timeout=5,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        version = completed.stdout.decode("utf-8", "replace").strip().splitlines()[0]
        _TOOL_VERSION_CACHE[profile] = version[:200] if version else None
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired, IndexError):
        _TOOL_VERSION_CACHE[profile] = None
    return _TOOL_VERSION_CACHE[profile]


def _run_profile(profile: str, workspace: Path, timeout_seconds: int) -> dict[str, Any]:
    command = PROFILE_COMMANDS[profile]
    tool = PROFILE_TOOLS.get(profile, command[0])
    tool_version = _tool_version(profile)
    tool_temp = workspace / ".sccap-tmp"
    output_path = workspace / f".{profile}.output"
    started = time.monotonic()
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(workspace),
        "TMPDIR": str(tool_temp),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "NO_PROXY": "*",
        "no_proxy": "*",
    }
    try:
        with output_path.open("wb") as output:
            process = subprocess.Popen(  # noqa: S603 - fixed allowlist only
                command,
                cwd=workspace,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                shell=False,
                start_new_session=True,
                preexec_fn=lambda: _child_setup(timeout_seconds),
            )
            try:
                return_code = process.wait(timeout=timeout_seconds)
                if return_code == 0:
                    status = "passed"
                    detail = "Allowlisted profile exited with status 0."
                elif return_code == CHILD_TOOL_MISSING:
                    status = "tool_missing"
                    detail = "The allowlisted child tool is unavailable."
                elif return_code == CHILD_INFRASTRUCTURE_ERROR:
                    status = "infrastructure_error"
                    detail = (
                        "The allowlisted compiler adapter could not prepare its inputs."
                    )
                else:
                    status = "failed"
                    detail = f"Allowlisted profile exited with status {return_code}."
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                return_code = None
                status = "timeout"
                detail = f"Allowlisted profile exceeded {timeout_seconds} seconds."
    except FileNotFoundError:
        return_code = None
        status = "tool_missing"
        detail = "The pinned validation tool is unavailable in the sandbox image."
    except OSError as exc:
        return_code = None
        status = "infrastructure_error"
        detail = f"Sandbox process launch failed with {type(exc).__name__}."
    output_text = ""
    if output_path.exists():
        output_text = output_path.read_bytes()[:MAX_OUTPUT_BYTES].decode(
            "utf-8", "replace"
        )
        output_path.unlink(missing_ok=True)
    if tool_version:
        detail = f"{detail} Toolchain: {tool_version}."
    return {
        "stage": profile,
        "status": status,
        "blocking": True,
        "tool": tool,
        "detail": detail,
        "return_code": return_code,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "output": output_text,
    }


def process_job(payload: dict[str, Any]) -> dict[str, Any]:
    files, profiles, timeout_seconds = _bounded_request(payload)
    with tempfile.TemporaryDirectory(prefix="sccap-validation-") as temp_dir:
        workspace = Path(temp_dir).resolve()
        for relative, content in files.items():
            target = _safe_path(workspace, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", errors="strict")
        (workspace / ".sccap-tmp").mkdir(mode=0o700)
        if os.geteuid() == 0:
            for directory, _, names in os.walk(workspace):
                os.chown(directory, SANDBOX_UID, SANDBOX_GID)
                Path(directory).chmod(0o770)
                for name in names:
                    os.chown(Path(directory, name), SANDBOX_UID, SANDBOX_GID)
                    Path(directory, name).chmod(0o660)
        checks = [
            _run_profile(profile, workspace, timeout_seconds) for profile in profiles
        ]
    return {"schema_version": SCHEMA_VERSION, "checks": checks}


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        temp_path = Path(handle.name)
    temp_path.chmod(0o660)
    os.replace(temp_path, path)


def _error_result(exc: Exception) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "checks": [
            {
                "stage": "sandbox",
                "status": "infrastructure_error",
                "blocking": True,
                "tool": None,
                "detail": f"Validation job failed with {type(exc).__name__}.",
                "return_code": None,
                "duration_ms": 0,
                "output": "",
            }
        ],
    }


def _process_request(request_path: Path, response_path: Path) -> None:
    try:
        metadata = request_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("validation request is not a regular file")
        if metadata.st_uid != 1001:
            raise ValueError("validation request has an unexpected owner")
        if metadata.st_size > MAX_REQUEST_BYTES:
            raise ValueError("validation request exceeds serialized size limit")
        payload = json.loads(request_path.read_text(encoding="utf-8"))
        request_path.unlink(missing_ok=True)
        result = process_job(payload)
    except Exception as exc:  # noqa: BLE001 - protocol error becomes evidence
        request_path.unlink(missing_ok=True)
        result = _error_result(exc)
    _write_atomic(response_path, result)


def serve(job_dir: Path) -> None:
    job_dir.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        # API/worker processes use gid 1001 to submit jobs. Validation child
        # processes use gid 1002 and therefore cannot traverse this spool.
        os.chown(job_dir, 0, 1001)
        job_dir.chmod(0o770)
        os.setgid(1001)
    ready_path = job_dir / ".ready"
    ready_path.unlink(missing_ok=True)
    ready_path.write_text(str(os.getpid()), encoding="ascii")
    ready_path.chmod(0o660)

    # Recover atomically claimed jobs after an unclean daemon restart.
    for running_path in job_dir.glob("*.running.json"):
        request_path = running_path.with_name(
            running_path.name.replace(".running.json", ".request.json")
        )
        os.replace(running_path, request_path)

    children: set[int] = set()
    while True:
        for child_pid in list(children):
            reaped, _ = os.waitpid(child_pid, os.WNOHANG)
            if reaped:
                children.remove(child_pid)

        available = MAX_CONCURRENT_JOBS - len(children)
        for request_path in sorted(job_dir.glob("*.request.json"))[:available]:
            running_path = request_path.with_name(
                request_path.name.replace(".request.json", ".running.json")
            )
            response_path = request_path.with_name(
                request_path.name.replace(".request.json", ".response.json")
            )
            try:
                os.replace(request_path, running_path)
            except FileNotFoundError:
                continue
            child_pid = os.fork()
            if child_pid == 0:
                try:
                    _process_request(running_path, response_path)
                finally:
                    os._exit(0)
            children.add(child_pid)
        time.sleep(0.05)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--child-profile":
        try:
            raise SystemExit(_run_child_profile(sys.argv[2], Path.cwd()))
        except FileNotFoundError:
            print("Compiler adapter tool is unavailable.")
            raise SystemExit(CHILD_TOOL_MISSING) from None
        except (OSError, ValueError) as exc:
            print(f"Compiler adapter failed with {type(exc).__name__}.")
            raise SystemExit(CHILD_INFRASTRUCTURE_ERROR) from None
    serve(Path(os.environ.get("SCCAP_VALIDATION_JOB_DIR", "/jobs")))
