"""Bounded Python-only execution for managed Agent Skill scripts.

The public coroutine validates every input again, launches the dedicated
sandbox entrypoint with an isolated interpreter, drains both output streams
without back-pressure, and returns a JSON-compatible result.  Invalid caller
inputs raise :class:`RunnerError`; script outcomes are represented in the
returned result.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a project dependency
    psutil = None  # type: ignore[assignment]

from ._sandbox_runner import (
    EXIT_MISSING_MODULE,
    EXIT_SANDBOX_VIOLATION,
    MISSING_MODULE_MARKER,
    SANDBOX_VIOLATION_MARKER,
)


@dataclass(frozen=True, slots=True)
class RunnerLimits:
    """Resource and input limits applied to one script run."""

    max_argv_items: int = 32
    max_arg_bytes: int = 4096
    max_argv_bytes: int = 16 * 1024
    max_script_bytes: int = 1024 * 1024
    max_stdout_bytes: int = 128 * 1024
    max_stderr_bytes: int = 128 * 1024
    max_artifacts: int = 64
    max_artifact_directories: int = 64
    max_artifact_bytes: int = 16 * 1024 * 1024
    max_total_artifact_bytes: int = 64 * 1024 * 1024
    max_timeout_seconds: int = 300
    poll_interval_seconds: float = 0.05
    terminate_grace_seconds: float = 1.0

    def validate(self) -> None:
        """Raise ``RunnerError`` when a limit set is not usable."""

        integer_limits = {
            "max_argv_items": self.max_argv_items,
            "max_arg_bytes": self.max_arg_bytes,
            "max_argv_bytes": self.max_argv_bytes,
            "max_script_bytes": self.max_script_bytes,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
            "max_artifacts": self.max_artifacts,
            "max_artifact_directories": self.max_artifact_directories,
            "max_artifact_bytes": self.max_artifact_bytes,
            "max_total_artifact_bytes": self.max_total_artifact_bytes,
            "max_timeout_seconds": self.max_timeout_seconds,
        }
        for name, value in integer_limits.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise RunnerError(
                    "invalid_limits", f"{name} must be a positive integer"
                )
        if self.max_argv_bytes < self.max_arg_bytes:
            raise RunnerError(
                "invalid_limits",
                "max_argv_bytes must be at least max_arg_bytes",
            )
        if self.max_total_artifact_bytes < self.max_artifact_bytes:
            raise RunnerError(
                "invalid_limits",
                "max_total_artifact_bytes must be at least max_artifact_bytes",
            )
        if self.poll_interval_seconds <= 0 or self.poll_interval_seconds > 1:
            raise RunnerError(
                "invalid_limits",
                "poll_interval_seconds must be greater than zero and at most one",
            )
        if self.terminate_grace_seconds <= 0 or self.terminate_grace_seconds > 30:
            raise RunnerError(
                "invalid_limits",
                "terminate_grace_seconds must be greater than zero and at most 30",
            )


DEFAULT_RUNNER_LIMITS = RunnerLimits()
# ``-I`` ignores PYTHONIOENCODING/PYTHONUTF8, so UTF-8 must be explicit for
# Windows pipes and the runner's UTF-8 bounded-output protocol.
_PYTHON_SANDBOX_FLAGS = ("-I", "-B", "-u", "-X", "utf8")


class RunnerError(RuntimeError):
    """A stable validation or runner setup failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible error object."""

        result: dict[str, object] = {"code": self.code, "message": self.message}
        if self.details:
            result["details"] = dict(self.details)
        return result


def validate_argv(
    argv: list[str],
    limits: RunnerLimits = DEFAULT_RUNNER_LIMITS,
) -> list[str]:
    """Validate untrusted script arguments and return a detached copy."""

    limits.validate()
    if not isinstance(argv, list):
        raise RunnerError("invalid_argv", "argv must be a list of strings")
    if len(argv) > limits.max_argv_items:
        raise RunnerError(
            "argv_too_large",
            f"argv contains more than {limits.max_argv_items} items",
        )

    normalized: list[str] = []
    total_bytes = 0
    for index, value in enumerate(argv):
        if not isinstance(value, str):
            raise RunnerError(
                "invalid_argv",
                f"argv item {index} must be a string",
            )
        if "\x00" in value:
            raise RunnerError(
                "invalid_argv",
                f"argv item {index} contains a NUL character",
            )
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise RunnerError(
                "invalid_argv",
                f"argv item {index} is not valid UTF-8 text",
            ) from exc
        if len(encoded) > limits.max_arg_bytes:
            raise RunnerError(
                "argv_too_large",
                f"argv item {index} exceeds {limits.max_arg_bytes} bytes",
            )
        total_bytes += len(encoded)
        if total_bytes > limits.max_argv_bytes:
            raise RunnerError(
                "argv_too_large",
                f"argv exceeds {limits.max_argv_bytes} bytes in total",
            )
        normalized.append(value)
    return normalized


def detect_python_runtime() -> dict[str, object]:
    """Describe the current interpreter without searching arbitrary PATH entries."""

    raw_executable = str(sys.executable or "").strip()
    if not raw_executable:
        return {
            "available": False,
            "kind": "python",
            "executable": None,
            "message": "The current Python interpreter path is unavailable.",
        }
    try:
        executable = Path(os.path.abspath(raw_executable))
        info = executable.stat()
    except OSError as exc:
        return {
            "available": False,
            "kind": "python",
            "executable": None,
            "message": f"The current Python interpreter cannot be used: {exc}",
        }
    if not executable.is_absolute() or not stat.S_ISREG(info.st_mode):
        return {
            "available": False,
            "kind": "python",
            "executable": None,
            "message": "The current Python interpreter is not a regular absolute file.",
        }
    if not os.access(executable, os.X_OK):
        return {
            "available": False,
            "kind": "python",
            "executable": str(executable),
            "message": "The current Python interpreter is not executable.",
        }
    return {
        "available": True,
        "kind": "python",
        "executable": str(executable),
        "version": (
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
        "isolated_flags": list(_PYTHON_SANDBOX_FLAGS),
        "message": "Python script execution is available in the isolated runtime.",
    }


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_reparse_point(info: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(flag and attributes & flag)


def _prepare_sandbox_entry(path: Path) -> Path:
    """Return one canonical, ordinary launcher file or fail closed."""

    lexical = Path(os.path.abspath(os.fspath(path)))
    try:
        initial_info = os.stat(lexical, follow_symlinks=False)
        resolved = lexical.resolve(strict=True)
        final_info = os.stat(resolved, follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise RunnerError(
            "sandbox_unavailable",
            f"the Python sandbox entrypoint cannot be verified: {exc}",
        ) from exc
    for info in (initial_info, final_info):
        if (
            stat.S_ISLNK(info.st_mode)
            or _is_reparse_point(info)
            or not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_nlink", 0) != 1
        ):
            raise RunnerError(
                "sandbox_unavailable",
                "the Python sandbox entrypoint is not an ordinary unlinked file",
            )
    if resolved != lexical or initial_info.st_size != final_info.st_size:
        raise RunnerError(
            "sandbox_unavailable",
            "the Python sandbox entrypoint did not remain canonical and stable",
        )
    return resolved


def _normalize_script_rel(script_rel: str) -> PurePosixPath:
    if not isinstance(script_rel, str) or not script_rel:
        raise RunnerError("invalid_script", "script_rel must be a non-empty string")
    if "\x00" in script_rel:
        raise RunnerError("invalid_script", "script_rel contains a NUL character")
    if "\\" in script_rel or ":" in script_rel:
        raise RunnerError(
            "invalid_script",
            "script_rel must use a portable forward-slash relative path",
        )
    relative = PurePosixPath(script_rel)
    if relative.is_absolute() or not relative.parts:
        raise RunnerError("invalid_script", "script_rel must be relative")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise RunnerError(
            "invalid_script", "script_rel contains an unsafe path segment"
        )
    if relative.parts[0] != "scripts":
        raise RunnerError(
            "invalid_script", "script must be inside the scripts directory"
        )
    if relative.suffix.lower() != ".py":
        raise RunnerError("unsupported_script", "only .py skill scripts are supported")
    return relative


def _prepare_skill_root(raw_root: Path) -> tuple[Path, Path]:
    lexical = Path(os.path.abspath(os.fspath(raw_root)))
    if lexical.is_symlink():
        raise RunnerError("unsafe_skill_root", "skill_root must not be a symbolic link")
    try:
        resolved = lexical.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise RunnerError(
            "invalid_skill_root",
            f"skill_root is not readable: {exc}",
        ) from exc
    if not stat.S_ISDIR(info.st_mode):
        raise RunnerError("invalid_skill_root", "skill_root must be a directory")
    return lexical, resolved


def _walk_existing_components(root: Path, target: Path, *, label: str) -> None:
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise RunnerError(
            f"unsafe_{label}",
            f"{label} is outside the managed skill root",
        ) from exc
    current = root
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise RunnerError(
                f"invalid_{label}",
                f"{label} cannot be inspected: {exc}",
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise RunnerError(
                f"unsafe_{label}",
                f"{label} must not contain symbolic links",
            )


def _prepare_script(
    *,
    lexical_root: Path,
    resolved_root: Path,
    script_rel: PurePosixPath,
    limits: RunnerLimits,
) -> Path:
    lexical_script = lexical_root.joinpath(*script_rel.parts)
    _walk_existing_components(lexical_root, lexical_script, label="script")
    try:
        resolved_script = lexical_script.resolve(strict=True)
        info = resolved_script.stat()
    except OSError as exc:
        raise RunnerError("invalid_script", f"script is not readable: {exc}") from exc
    if not _is_relative_to(resolved_script, resolved_root):
        raise RunnerError(
            "unsafe_script",
            "script resolves outside the managed skill root",
        )
    if (
        not stat.S_ISREG(info.st_mode)
        or resolved_script.is_symlink()
        or info.st_nlink != 1
    ):
        raise RunnerError(
            "unsafe_script",
            "script must be a regular non-linked file",
        )
    if info.st_size > limits.max_script_bytes:
        raise RunnerError(
            "script_too_large",
            f"script exceeds {limits.max_script_bytes} bytes",
        )
    return resolved_script


def _prepare_output_root(
    *,
    raw_output_root: Path,
    lexical_root: Path,
    resolved_root: Path,
) -> Path:
    lexical_output = (
        Path(os.path.abspath(os.fspath(raw_output_root)))
        if raw_output_root.is_absolute()
        else lexical_root / raw_output_root
    )
    lexical_output = Path(os.path.abspath(os.fspath(lexical_output)))
    if lexical_output == lexical_root:
        raise RunnerError(
            "unsafe_output_root",
            "output_root must be below the managed skill root",
        )
    _walk_existing_components(lexical_root, lexical_output, label="output_root")
    try:
        lexical_output.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise RunnerError(
            "invalid_output_root",
            f"output_root cannot be created: {exc}",
        ) from exc
    _walk_existing_components(lexical_root, lexical_output, label="output_root")
    try:
        resolved_output = lexical_output.resolve(strict=True)
        info = resolved_output.stat()
    except OSError as exc:
        raise RunnerError(
            "invalid_output_root",
            f"output_root is not readable: {exc}",
        ) from exc
    if not _is_relative_to(resolved_output, resolved_root):
        raise RunnerError(
            "unsafe_output_root",
            "output_root resolves outside the managed skill root",
        )
    if not stat.S_ISDIR(info.st_mode) or lexical_output.is_symlink():
        raise RunnerError(
            "unsafe_output_root",
            "output_root must be a regular non-symlink directory",
        )
    return resolved_output


def _create_run_output(output_root: Path, resolved_root: Path) -> Path:
    for _ in range(8):
        name = f"run-{time.time_ns()}-{uuid.uuid4().hex[:10]}"
        run_dir = output_root / name
        try:
            run_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError:
            continue
        except OSError as exc:
            raise RunnerError(
                "output_create_failed",
                f"run output directory cannot be created: {exc}",
            ) from exc
        try:
            resolved_run = run_dir.resolve(strict=True)
            info = resolved_run.stat()
        except OSError as exc:
            raise RunnerError(
                "output_create_failed",
                f"run output directory cannot be verified: {exc}",
            ) from exc
        if (
            not _is_relative_to(resolved_run, resolved_root)
            or run_dir.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise RunnerError(
                "unsafe_output_root",
                "run output directory failed containment validation",
            )
        return run_dir
    raise RunnerError(
        "output_create_failed",
        "a unique run output directory could not be allocated",
    )


def _minimal_environment(
    *,
    executable: Path,
    skill_root: Path,
    output_dir: Path,
) -> dict[str, str]:
    path_entries = [str(executable.parent)]
    env: dict[str, str] = {}
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE"):
            value = os.environ.get(name)
            if value:
                env[name] = value
        system_root = env.get("SYSTEMROOT") or env.get("WINDIR")
        if system_root:
            path_entries.append(str(Path(system_root) / "System32"))
    env.update(
        {
            "HOME": str(output_dir),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NEKO_SKILL_OUTPUT_DIR": str(output_dir),
            "NEKO_SKILL_ROOT": str(skill_root),
            "PATH": os.pathsep.join(path_entries),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONUTF8": "1",
            "TEMP": str(output_dir),
            "TMP": str(output_dir),
            "TMPDIR": str(output_dir),
            "USERPROFILE": str(output_dir),
        }
    )
    return env


@dataclass(slots=True)
class _BoundedPipe:
    limit: int
    marker_tail_limit: int = 16 * 1024
    data: bytearray = field(default_factory=bytearray)
    marker_tail: bytearray = field(default_factory=bytearray)
    total_bytes: int = 0
    error: str | None = None

    def drain(self, pipe: Any) -> None:
        try:
            while True:
                chunk = pipe.read(64 * 1024)
                if not chunk:
                    break
                self.total_bytes += len(chunk)
                remaining = self.limit - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
                self.marker_tail.extend(chunk)
                if len(self.marker_tail) > self.marker_tail_limit:
                    del self.marker_tail[
                        : len(self.marker_tail) - self.marker_tail_limit
                    ]
        except (OSError, ValueError) as exc:
            self.error = str(exc)
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    @property
    def truncated(self) -> bool:
        return self.total_bytes > self.limit

    def text(self) -> str:
        return bytes(self.data).decode("utf-8", errors="replace")

    def marker_text(self) -> str:
        return bytes(self.marker_tail).decode("utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class _ProcessIdentity:
    process: Any
    create_time: float


def _capture_descendants(pid: int) -> list[_ProcessIdentity]:
    if psutil is None:
        return []
    try:
        root = psutil.Process(pid)
        processes = root.children(recursive=True)
    except (psutil.Error, OSError):
        return []
    identities: list[_ProcessIdentity] = []
    for process in processes:
        try:
            identities.append(
                _ProcessIdentity(process=process, create_time=process.create_time())
            )
        except (psutil.Error, OSError):
            continue
    identities.reverse()
    return identities


def _identity_alive(identity: _ProcessIdentity) -> bool:
    try:
        return (
            identity.process.is_running()
            and identity.process.create_time() == identity.create_time
        )
    except Exception:
        return False


def _signal_identities(
    identities: list[_ProcessIdentity],
    *,
    force: bool,
) -> None:
    for identity in identities:
        if not _identity_alive(identity):
            continue
        try:
            if force:
                identity.process.kill()
            else:
                identity.process.terminate()
        except Exception:
            continue


def _wait_identities(
    identities: list[_ProcessIdentity],
    *,
    timeout: float,
) -> None:
    if psutil is None:
        return
    alive = [item.process for item in identities if _identity_alive(item)]
    if not alive:
        return
    try:
        psutil.wait_procs(alive, timeout=timeout)
    except Exception:
        return


def _windows_taskkill(pid: int, *, timeout: float) -> None:
    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR")
    candidate = Path(system_root) / "System32" / "taskkill.exe" if system_root else None
    executable = (
        str(candidate)
        if candidate is not None and candidate.is_file()
        else shutil.which("taskkill")
    )
    if not executable:
        return
    try:
        subprocess.run(
            [executable, "/PID", str(pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(timeout, 0.1),
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float,
) -> None:
    descendants = _capture_descendants(process.pid)
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.terminate()
            except OSError:
                pass
        _signal_identities(descendants, force=False)
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    process.kill()
                except OSError:
                    pass
        _wait_identities(descendants, timeout=grace_seconds)
        _signal_identities(descendants, force=True)
        _wait_identities(descendants, timeout=grace_seconds)
    else:
        _signal_identities(descendants, force=False)
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            _windows_taskkill(process.pid, timeout=grace_seconds)
            try:
                process.kill()
            except OSError:
                pass
        _wait_identities(descendants, timeout=grace_seconds)
        _signal_identities(descendants, force=True)
        _wait_identities(descendants, timeout=grace_seconds)
    try:
        process.wait(timeout=max(grace_seconds, 0.1))
    except (subprocess.TimeoutExpired, OSError):
        try:
            process.kill()
            process.wait(timeout=max(grace_seconds, 0.1))
        except (subprocess.SubprocessError, OSError):
            pass


def _scan_artifacts(
    output_dir: Path,
    *,
    limits: RunnerLimits,
    include_records: bool,
) -> tuple[list[dict[str, object]], int]:
    files: list[dict[str, object]] = []
    file_count = 0
    directory_count = 0
    total_size = 0
    stack = [output_dir]
    try:
        resolved_output_dir = output_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RunnerError(
            "artifact_scan_failed",
            f"run output cannot be resolved: {exc}",
        ) from exc

    while stack:
        directory = stack.pop()
        try:
            directory_info = os.stat(directory, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RunnerError(
                "artifact_scan_failed",
                f"run output directory cannot be inspected: {exc}",
            ) from exc
        if (
            stat.S_ISLNK(directory_info.st_mode)
            or _is_reparse_point(directory_info)
            or not stat.S_ISDIR(directory_info.st_mode)
        ):
            raise RunnerError(
                "unsafe_artifact",
                "run output contains an unsafe directory",
            )
        try:
            resolved_directory = directory.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RunnerError(
                "unsafe_artifact",
                f"run output contains an unresolvable directory: {exc}",
            ) from exc
        if not _is_relative_to(resolved_directory, resolved_output_dir):
            raise RunnerError(
                "unsafe_artifact",
                "run output contains a directory outside its root",
            )
        try:
            iterator = os.scandir(directory)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RunnerError(
                "artifact_scan_failed",
                f"run output cannot be inspected: {exc}",
            ) from exc
        with iterator:
            for entry in iterator:
                try:
                    # DirEntry.stat() returns cached, incomplete link metadata on
                    # Windows, so artifact safety uses a fresh no-follow path stat.
                    info = os.stat(entry.path, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise RunnerError(
                        "artifact_scan_failed",
                        f"run output entry cannot be inspected: {exc}",
                    ) from exc
                mode = info.st_mode
                if stat.S_ISLNK(mode) or _is_reparse_point(info):
                    raise RunnerError(
                        "unsafe_artifact",
                        "run output contains a symbolic link or reparse point",
                    )
                if stat.S_ISDIR(mode):
                    directory_count += 1
                    if directory_count > limits.max_artifact_directories:
                        raise RunnerError(
                            "too_many_artifact_directories",
                            (
                                "run output contains more than "
                                f"{limits.max_artifact_directories} directories"
                            ),
                        )
                    stack.append(Path(entry.path))
                    continue
                if (
                    not stat.S_ISREG(mode)
                    or getattr(info, "st_nlink", 0) != 1
                ):
                    raise RunnerError(
                        "unsafe_artifact",
                        "run output contains a special or multiply-linked file",
                    )

                file_count += 1
                if file_count > limits.max_artifacts:
                    raise RunnerError(
                        "too_many_artifacts",
                        f"run output contains more than {limits.max_artifacts} files",
                    )
                if info.st_size > limits.max_artifact_bytes:
                    raise RunnerError(
                        "artifact_too_large",
                        (f"an output file exceeds {limits.max_artifact_bytes} bytes"),
                    )
                total_size += info.st_size
                if total_size > limits.max_total_artifact_bytes:
                    raise RunnerError(
                        "artifact_total_too_large",
                        (
                            "run output exceeds "
                            f"{limits.max_total_artifact_bytes} bytes in total"
                        ),
                    )
                if include_records:
                    path = Path(entry.path)
                    files.append(
                        {
                            "path": str(path),
                            "relative_path": path.relative_to(output_dir).as_posix(),
                            "size_bytes": info.st_size,
                        }
                    )
    files.sort(key=lambda item: str(item["relative_path"]))
    return files, total_size


def _extract_marker(text: str, marker: str) -> dict[str, object] | None:
    for line in reversed(text.splitlines()):
        if not line.startswith(marker):
            continue
        raw_payload = line[len(marker) :]
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if isinstance(payload, dict):
            return {str(key): value for key, value in payload.items()}
    return None


def _base_result(
    *,
    script_rel: str,
    skill_root: Path,
    output_dir: Path,
    started_at: float,
    duration_seconds: float,
    stdout: _BoundedPipe,
    stderr: _BoundedPipe,
) -> dict[str, object]:
    return {
        "ok": False,
        "status": "failed",
        "script": script_rel,
        "cwd": str(skill_root),
        "output_dir": str(output_dir),
        "started_at": started_at,
        "duration_seconds": round(duration_seconds, 6),
        "exit_code": None,
        "stdout": stdout.text(),
        "stderr": stderr.text(),
        "stdout_bytes": stdout.total_bytes,
        "stderr_bytes": stderr.total_bytes,
        "stdout_truncated": stdout.truncated,
        "stderr_truncated": stderr.truncated,
        "artifacts": [],
        "artifact_count": 0,
        "artifact_bytes": 0,
    }


def _run_python_script_sync(
    *,
    skill_root: Path,
    script_rel: str,
    argv: list[str],
    output_root: Path,
    timeout_seconds: int,
    limits: RunnerLimits,
    cancel_event: threading.Event,
) -> dict[str, object]:
    limits.validate()
    normalized_argv = validate_argv(argv, limits)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
        or timeout_seconds > limits.max_timeout_seconds
    ):
        raise RunnerError(
            "invalid_timeout",
            (
                "timeout_seconds must be a positive integer no greater than "
                f"{limits.max_timeout_seconds}"
            ),
        )

    runtime = detect_python_runtime()
    if runtime.get("available") is not True:
        raise RunnerError(
            "python_unavailable",
            str(runtime.get("message") or "Python execution is unavailable."),
            details=runtime,
        )
    executable = Path(str(runtime["executable"]))
    lexical_root, resolved_root = _prepare_skill_root(Path(skill_root))
    normalized_script = _normalize_script_rel(script_rel)
    script = _prepare_script(
        lexical_root=lexical_root,
        resolved_root=resolved_root,
        script_rel=normalized_script,
        limits=limits,
    )
    prepared_output_root = _prepare_output_root(
        raw_output_root=Path(output_root),
        lexical_root=lexical_root,
        resolved_root=resolved_root,
    )
    output_dir = _create_run_output(prepared_output_root, resolved_root)
    sandbox_entry = _prepare_sandbox_entry(
        Path(__file__).resolve(strict=True).with_name("_sandbox_runner.py")
    )

    command = [
        str(executable),
        *_PYTHON_SANDBOX_FLAGS,
        str(sandbox_entry),
        "--skill-root",
        str(resolved_root),
        "--script",
        str(script),
        "--output-dir",
        str(output_dir),
        "--",
        *normalized_argv,
    ]
    environment = _minimal_environment(
        executable=executable,
        skill_root=resolved_root,
        output_dir=output_dir,
    )
    popen_kwargs: dict[str, Any] = {
        "args": command,
        "cwd": str(resolved_root),
        "env": environment,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "bufsize": 0,
        "close_fds": True,
        "shell": False,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = int(
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        ) | int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    else:
        popen_kwargs["start_new_session"] = True

    started_at = time.time()
    start_monotonic = time.monotonic()
    stdout_capture = _BoundedPipe(limits.max_stdout_bytes)
    stderr_capture = _BoundedPipe(limits.max_stderr_bytes)
    try:
        process = subprocess.Popen(**popen_kwargs)
    except (OSError, ValueError) as exc:
        duration = time.monotonic() - start_monotonic
        result = _base_result(
            script_rel=script_rel,
            skill_root=resolved_root,
            output_dir=output_dir,
            started_at=started_at,
            duration_seconds=duration,
            stdout=stdout_capture,
            stderr=stderr_capture,
        )
        result.update(
            {
                "status": "spawn_error",
                "summary": "The isolated Python process could not be started.",
                "diagnostic": {
                    "code": "spawn_error",
                    "message": str(exc),
                },
            }
        )
        return result

    if process.stdout is None or process.stderr is None:
        _terminate_process_tree(
            process,
            grace_seconds=limits.terminate_grace_seconds,
        )
        raise RunnerError(
            "pipe_setup_failed",
            "the isolated process did not provide bounded output pipes",
        )

    stdout_thread = threading.Thread(
        target=stdout_capture.drain,
        args=(process.stdout,),
        name="skill-runner-stdout",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=stderr_capture.drain,
        args=(process.stderr,),
        name="skill-runner-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    termination_status: str | None = None
    termination_error: RunnerError | None = None
    deadline = start_monotonic + timeout_seconds
    while process.poll() is None:
        if cancel_event.is_set():
            termination_status = "cancelled"
            break
        if time.monotonic() >= deadline:
            termination_status = "timed_out"
            break
        try:
            _scan_artifacts(
                output_dir,
                limits=limits,
                include_records=False,
            )
        except RunnerError as exc:
            termination_status = "output_rejected"
            termination_error = exc
            break
        time.sleep(limits.poll_interval_seconds)

    if termination_status is not None:
        _terminate_process_tree(
            process,
            grace_seconds=limits.terminate_grace_seconds,
        )
    else:
        try:
            process.wait(timeout=limits.terminate_grace_seconds)
        except subprocess.TimeoutExpired:
            termination_status = "timed_out"
            _terminate_process_tree(
                process,
                grace_seconds=limits.terminate_grace_seconds,
            )

    for thread, pipe in (
        (stdout_thread, process.stdout),
        (stderr_thread, process.stderr),
    ):
        thread.join(timeout=max(limits.terminate_grace_seconds, 0.1))
        if thread.is_alive():
            try:
                pipe.close()
            except OSError:
                pass
            thread.join(timeout=max(limits.terminate_grace_seconds, 0.1))

    duration = time.monotonic() - start_monotonic
    result = _base_result(
        script_rel=script_rel,
        skill_root=resolved_root,
        output_dir=output_dir,
        started_at=started_at,
        duration_seconds=duration,
        stdout=stdout_capture,
        stderr=stderr_capture,
    )
    result["exit_code"] = process.returncode

    artifacts: list[dict[str, object]] = []
    artifact_bytes = 0
    artifact_error: RunnerError | None = None
    try:
        artifacts, artifact_bytes = _scan_artifacts(
            output_dir,
            limits=limits,
            include_records=True,
        )
    except RunnerError as exc:
        artifact_error = exc
    result["artifacts"] = artifacts
    result["artifact_count"] = len(artifacts)
    result["artifact_bytes"] = artifact_bytes

    if termination_status == "cancelled":
        result.update(
            {
                "status": "cancelled",
                "summary": "The script run was cancelled and its process tree was stopped.",
                "diagnostic": {
                    "code": "cancelled",
                    "message": "The caller cancelled this skill script run.",
                },
            }
        )
        return result
    if termination_status == "timed_out":
        result.update(
            {
                "status": "timed_out",
                "summary": "The script exceeded its time limit and was stopped.",
                "diagnostic": {
                    "code": "script_timeout",
                    "message": (
                        f"The script did not finish within {timeout_seconds} seconds. "
                        "No permissions were bypassed and its process tree was stopped."
                    ),
                },
            }
        )
        return result
    if termination_status == "output_rejected":
        diagnostic = termination_error or artifact_error
        result.update(
            {
                "status": "output_rejected",
                "summary": "The script output violated the configured artifact limits.",
                "diagnostic": (
                    diagnostic.to_dict()
                    if diagnostic is not None
                    else {
                        "code": "output_rejected",
                        "message": "The run output was rejected.",
                    }
                ),
            }
        )
        return result
    if artifact_error is not None:
        result.update(
            {
                "status": "output_rejected",
                "summary": "The script finished, but its output was not safe to return.",
                "diagnostic": artifact_error.to_dict(),
            }
        )
        return result

    marker_text = stderr_capture.marker_text()
    if process.returncode == EXIT_MISSING_MODULE:
        marker = _extract_marker(marker_text, MISSING_MODULE_MARKER) or {}
        module_name = str(marker.get("module") or "").strip()
        message = str(marker.get("message") or "").strip()
        if not message:
            message = (
                "A required Python module is missing from the isolated runtime. "
                "Install dependencies in a dedicated environment; the skill loader "
                "will not modify the system Python installation."
            )
        result.update(
            {
                "status": "missing_dependency",
                "summary": "The script needs a Python module that is not available.",
                "diagnostic": {
                    "code": "missing_python_module",
                    "message": message,
                    "module": module_name,
                },
            }
        )
        return result
    if process.returncode == EXIT_SANDBOX_VIOLATION:
        marker = _extract_marker(marker_text, SANDBOX_VIOLATION_MARKER) or {}
        result.update(
            {
                "status": "sandbox_violation",
                "summary": "The script attempted an operation blocked by the sandbox.",
                "diagnostic": {
                    "code": "sandbox_violation",
                    "message": str(
                        marker.get("message")
                        or "The script attempted to cross the managed safety boundary."
                    ),
                    "operation": str(marker.get("operation") or "runtime"),
                },
            }
        )
        return result
    if process.returncode == 0:
        result.update(
            {
                "ok": True,
                "status": "succeeded",
                "summary": (
                    f"The script completed successfully and produced "
                    f"{len(artifacts)} artifact(s)."
                ),
            }
        )
        return result

    result.update(
        {
            "status": "failed",
            "summary": f"The script exited with code {process.returncode}.",
            "diagnostic": {
                "code": "script_failed",
                "message": (
                    "Review the bounded stderr output. The skill loader did not "
                    "install dependencies or relax permissions automatically."
                ),
            },
        }
    )
    return result


async def run_python_script(
    skill_root: Path,
    script_rel: str,
    argv: list[str],
    output_root: Path,
    timeout_seconds: int,
    limits: RunnerLimits = DEFAULT_RUNNER_LIMITS,
) -> dict[str, object]:
    """Run one managed ``scripts/*.py`` file in the bounded sandbox.

    ``output_root`` must be inside ``skill_root``.  A unique child directory is
    created for every call.  Validation and setup errors raise ``RunnerError``;
    script failures, timeouts, missing modules, and sandbox violations are
    returned as JSON-compatible result objects.
    """

    cancel_event = threading.Event()
    worker = asyncio.create_task(
        asyncio.to_thread(
            _run_python_script_sync,
            skill_root=Path(skill_root),
            script_rel=script_rel,
            argv=argv,
            output_root=Path(output_root),
            timeout_seconds=timeout_seconds,
            limits=limits,
            cancel_event=cancel_event,
        )
    )
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        cancel_event.set()
        try:
            await worker
        except Exception:
            pass
        raise


__all__ = [
    "DEFAULT_RUNNER_LIMITS",
    "RunnerError",
    "RunnerLimits",
    "detect_python_runtime",
    "run_python_script",
    "validate_argv",
]
