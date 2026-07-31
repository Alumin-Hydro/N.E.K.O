"""Isolated Python entrypoint used by the skill script runner.

This module is executed in a fresh isolated interpreter.  It validates the
managed paths again, installs a Python audit hook, and only then executes the
selected script.  The audit policy is intentionally narrow: skill files and
interpreter libraries are readable, while writes are limited to the dedicated
run output directory.

Python audit hooks are a defense-in-depth boundary, not a replacement for an
operating-system sandbox.  The parent runner still applies process, timeout,
output, and artifact limits.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import runpy
import stat
import sys
import sysconfig
import threading
import traceback
from collections.abc import Iterable
from pathlib import Path
from typing import NoReturn

EXIT_MISSING_MODULE = 86
EXIT_SANDBOX_VIOLATION = 87
MISSING_MODULE_MARKER = "__NEKO_SKILL_MISSING_MODULE__:"
SANDBOX_VIOLATION_MARKER = "__NEKO_SKILL_SANDBOX_VIOLATION__:"

_ORIGINAL_STAT = os.stat
_ORIGINAL_LSTAT = os.lstat
_NATIVE_OS = importlib.import_module("nt" if os.name == "nt" else "posix")
_RESOLUTION_STATE = threading.local()


class SandboxViolation(PermissionError):
    """Raised when a script attempts an operation outside its policy."""


def _emit_marker(marker: str, payload: dict[str, object]) -> None:
    line = marker + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    print(line, file=sys.stderr, flush=True)


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


def _resolve_path(path: Path, *, strict: bool) -> Path:
    _RESOLUTION_STATE.active = True
    try:
        return path.resolve(strict=strict)
    finally:
        _RESOLUTION_STATE.active = False


def _validate_directory(path: Path, *, label: str) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute.is_symlink():
        raise SandboxViolation(f"{label} must not be a symbolic link")
    resolved = _resolve_path(absolute, strict=True)
    info = _ORIGINAL_STAT(resolved)
    if not stat.S_ISDIR(info.st_mode):
        raise SandboxViolation(f"{label} must be a directory")
    return resolved


def _validate_script(skill_root: Path, raw_script: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(raw_script)))
    if not _is_relative_to(absolute, skill_root):
        raise SandboxViolation("script is outside the managed skill root")
    relative = absolute.relative_to(skill_root)
    if not relative.parts or relative.parts[0] != "scripts":
        raise SandboxViolation("script must be inside the scripts directory")
    if absolute.suffix.lower() != ".py":
        raise SandboxViolation("only .py scripts are supported")

    current = skill_root
    for part in relative.parts:
        current = current / part
        try:
            info = _ORIGINAL_LSTAT(current)
        except OSError as exc:
            raise SandboxViolation("script path is not readable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise SandboxViolation("script path must not contain symbolic links")

    resolved = _resolve_path(absolute, strict=True)
    if not _is_relative_to(resolved, skill_root):
        raise SandboxViolation("script resolves outside the managed skill root")
    info = _ORIGINAL_STAT(resolved)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SandboxViolation("script must be a regular non-linked file")
    return resolved


def _validate_output(skill_root: Path, raw_output: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(raw_output)))
    if absolute == skill_root or not _is_relative_to(absolute, skill_root):
        raise SandboxViolation("output directory must be below the managed skill root")
    relative = absolute.relative_to(skill_root)
    current = skill_root
    for part in relative.parts:
        current = current / part
        try:
            info = _ORIGINAL_LSTAT(current)
        except OSError as exc:
            raise SandboxViolation("output directory is not readable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise SandboxViolation("output path must not contain symbolic links")
    resolved = _resolve_path(absolute, strict=True)
    if not _is_relative_to(resolved, skill_root):
        raise SandboxViolation(
            "output directory resolves outside the managed skill root"
        )
    if not stat.S_ISDIR(_ORIGINAL_STAT(resolved).st_mode):
        raise SandboxViolation("output path must be a directory")
    return resolved


def _validate_trusted_launcher(raw_launcher: Path) -> Path:
    """Validate the exact canonical launcher before installing audit guards."""

    lexical = Path(os.path.abspath(os.fspath(raw_launcher)))
    try:
        initial_info = _ORIGINAL_LSTAT(lexical)
        resolved = _resolve_path(lexical, strict=True)
        final_info = _ORIGINAL_LSTAT(resolved)
    except (OSError, RuntimeError) as exc:
        raise SandboxViolation("sandbox launcher cannot be verified") from exc
    for info in (initial_info, final_info):
        if (
            stat.S_ISLNK(info.st_mode)
            or _is_reparse_point(info)
            or not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_nlink", 0) != 1
        ):
            raise SandboxViolation("sandbox launcher must be an ordinary unlinked file")
    if resolved != lexical or initial_info.st_size != final_info.st_size:
        raise SandboxViolation("sandbox launcher must remain canonical and stable")
    return resolved


def _collect_system_roots(skill_root: Path) -> tuple[Path, ...]:
    candidates: set[Path] = set()
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        raw = sysconfig.get_paths().get(key)
        if raw:
            try:
                candidates.add(_resolve_path(Path(raw), strict=True))
            except OSError:
                continue

    prefixes: list[Path] = []
    for raw_prefix in (
        sys.prefix,
        sys.base_prefix,
        sys.exec_prefix,
        sys.base_exec_prefix,
    ):
        if not raw_prefix:
            continue
        try:
            prefixes.append(_resolve_path(Path(raw_prefix), strict=True))
        except OSError:
            continue

    for raw_entry in sys.path:
        if not raw_entry:
            continue
        try:
            entry = _resolve_path(Path(raw_entry), strict=True)
        except OSError:
            continue
        if entry == skill_root or _is_relative_to(entry, skill_root):
            continue
        if any(
            entry == prefix or _is_relative_to(entry, prefix) for prefix in prefixes
        ):
            candidates.add(entry)
    return tuple(sorted(candidates, key=lambda item: (len(item.parts), str(item))))


class _AuditPolicy:
    """Path and operation policy installed through ``sys.addaudithook``."""

    def __init__(
        self,
        *,
        skill_root: Path,
        output_dir: Path,
        system_roots: Iterable[Path],
        trusted_stat_files: Iterable[Path] = (),
    ) -> None:
        self.skill_root = skill_root
        self.output_dir = output_dir
        self.system_roots = tuple(system_roots)
        self.trusted_stat_files = frozenset(trusted_stat_files)
        self.first_violation: str | None = None

    def _deny(self, message: str) -> NoReturn:
        if self.first_violation is None:
            self.first_violation = message
        raise SandboxViolation(message)

    def _path_from_value(self, value: object, *, operation: str) -> Path:
        if isinstance(value, int):
            if value in {0, 1, 2}:
                return Path(os.devnull)
            self._deny(f"{operation} rejected an untrusted file descriptor")
        try:
            raw = os.fsdecode(os.fspath(value))
        except (TypeError, ValueError):
            self._deny(f"{operation} received an invalid path")
        if "\x00" in raw:
            self._deny(f"{operation} rejected a NUL-containing path")
        absolute = Path(raw)
        if not absolute.is_absolute():
            absolute = self.skill_root / absolute
        return Path(os.path.abspath(os.fspath(absolute)))

    def _resolved(self, value: object, *, operation: str) -> tuple[Path, Path]:
        lexical = self._path_from_value(value, operation=operation)
        try:
            resolved = _resolve_path(lexical, strict=False)
        except (OSError, RuntimeError) as exc:
            self._deny(f"{operation} could not safely resolve its path: {exc}")
        return lexical, resolved

    def _check_skill_link_state(
        self,
        lexical: Path,
        resolved: Path,
        *,
        operation: str,
    ) -> None:
        if not _is_relative_to(lexical, self.skill_root):
            return
        current = self.skill_root
        for part in lexical.relative_to(self.skill_root).parts:
            current = current / part
            try:
                info = _ORIGINAL_LSTAT(current)
            except FileNotFoundError:
                break
            except OSError as exc:
                self._deny(f"{operation} could not inspect a managed path: {exc}")
            if stat.S_ISLNK(info.st_mode):
                self._deny(f"{operation} rejected a symbolic-link path")
        try:
            info = _ORIGINAL_LSTAT(resolved)
        except FileNotFoundError:
            return
        except OSError as exc:
            self._deny(f"{operation} could not inspect a managed file: {exc}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            self._deny(f"{operation} rejected a multiply-linked managed file")

    def _check_resolved_read(
        self,
        lexical: Path,
        resolved: Path,
        *,
        operation: str,
    ) -> Path:
        if _is_relative_to(resolved, self.skill_root):
            self._check_skill_link_state(lexical, resolved, operation=operation)
            return resolved
        for allowed in self.system_roots:
            if resolved == allowed or _is_relative_to(resolved, allowed):
                return resolved
        self._deny(f"{operation} denied read access outside approved roots: {resolved}")

    def check_read(self, value: object, *, operation: str) -> Path:
        if isinstance(value, int) and value in {0, 1, 2}:
            return Path(os.devnull)
        lexical, resolved = self._resolved(value, operation=operation)
        return self._check_resolved_read(
            lexical,
            resolved,
            operation=operation,
        )

    def check_stat(self, value: object) -> Path:
        """Allow metadata access to the exact verified launcher, nothing else."""

        if isinstance(value, int) and value in {0, 1, 2}:
            return Path(os.devnull)
        lexical, resolved = self._resolved(value, operation="os.stat")
        if lexical == resolved and resolved in self.trusted_stat_files:
            return resolved
        return self._check_resolved_read(
            lexical,
            resolved,
            operation="os.stat",
        )

    def check_write(self, value: object, *, operation: str) -> Path:
        if isinstance(value, int) and value in {1, 2}:
            return Path(os.devnull)
        lexical, resolved = self._resolved(value, operation=operation)
        if not _is_relative_to(resolved, self.output_dir):
            self._deny(
                f"{operation} denied write access outside the run output: {resolved}"
            )
        self._check_skill_link_state(lexical, resolved, operation=operation)
        return resolved

    @staticmethod
    def _open_is_write(mode: object, flags: object) -> bool:
        if isinstance(mode, str) and any(
            token in mode for token in ("w", "a", "x", "+")
        ):
            return True
        if isinstance(flags, int):
            write_flags = (
                os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
            )
            return bool(flags & write_flags)
        return False

    def audit(self, event: str, args: tuple[object, ...]) -> None:
        if event == "open" and args:
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else None
            if self._open_is_write(mode, flags):
                self.check_write(args[0], operation="open")
            else:
                self.check_read(args[0], operation="open")
            return

        if event == "os.stat" and args:
            self.check_stat(args[0])
            return

        if event in {"os.listdir", "os.scandir", "os.lstat", "os.readlink"} and args:
            self.check_read(args[0], operation=event)
            return

        if event == "sqlite3.connect" and args:
            database = args[0]
            if database != ":memory:":
                self.check_write(database, operation=event)
            return

        if (
            event
            in {
                "os.remove",
                "os.unlink",
                "os.rmdir",
                "os.mkdir",
                "os.chmod",
                "os.chown",
                "os.truncate",
                "os.utime",
            }
            and args
        ):
            self.check_write(args[0], operation=event)
            return

        if event in {"os.rename", "os.replace"} and len(args) >= 2:
            self.check_write(args[0], operation=event)
            self.check_write(args[1], operation=event)
            return

        if event in {"os.symlink", "os.link"}:
            self._deny(f"{event} is disabled for skill scripts")

        if event == "os.chdir" or event == "os.fchdir":
            self._deny("changing the managed working directory is disabled")

        if (
            event == "subprocess.Popen"
            or event
            in {
                "os.system",
                "os.fork",
                "os.forkpty",
                "os.posix_spawn",
                "os.posix_spawnp",
                "os.exec",
                "_posixsubprocess.fork_exec",
                "pty.spawn",
                "os.kill",
                "os.killpg",
            }
            or event.startswith("os.spawn")
            or event.startswith("os.exec")
        ):
            self._deny(f"{event} is disabled for skill scripts")

        if event.startswith("ctypes."):
            self._deny("ctypes is disabled for skill scripts")

        if event == "import" and args:
            module_name = str(args[0])
            if (
                module_name == "_ctypes"
                or module_name == "ctypes"
                or module_name.startswith("ctypes.")
            ):
                self._deny("ctypes is disabled for skill scripts")

        if event.startswith("socket."):
            self._deny("network sockets are disabled for skill scripts")

        if event in {
            "sys._current_exceptions",
            "sys._current_frames",
            "sys.setprofile",
            "sys.settrace",
        }:
            self._deny(f"{event} is disabled for skill scripts")


def _install_stat_guards(policy: _AuditPolicy) -> None:
    def guarded_stat(path: object, *args: object, **kwargs: object):
        if getattr(_RESOLUTION_STATE, "active", False):
            return _ORIGINAL_STAT(path, *args, **kwargs)
        if kwargs.get("dir_fd") is not None:
            policy._deny("os.stat with dir_fd is disabled for skill scripts")
        policy.check_stat(path)
        return _ORIGINAL_STAT(path, *args, **kwargs)

    def guarded_lstat(path: object, *args: object, **kwargs: object):
        if getattr(_RESOLUTION_STATE, "active", False):
            return _ORIGINAL_LSTAT(path, *args, **kwargs)
        if kwargs.get("dir_fd") is not None:
            policy._deny("os.lstat with dir_fd is disabled for skill scripts")
        policy.check_read(path, operation="os.lstat")
        return _ORIGINAL_LSTAT(path, *args, **kwargs)

    def blocked_exit(*_args: object, **_kwargs: object) -> NoReturn:
        policy._deny("os._exit is disabled for skill scripts")

    os.stat = guarded_stat  # type: ignore[assignment]
    os.lstat = guarded_lstat  # type: ignore[assignment]
    _NATIVE_OS.stat = guarded_stat
    _NATIVE_OS.lstat = guarded_lstat
    os._exit = blocked_exit  # type: ignore[assignment]
    _NATIVE_OS._exit = blocked_exit


def _minimal_environment(skill_root: Path, output_dir: Path) -> None:
    allowed_names = {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONIOENCODING",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONSAFEPATH",
        "PYTHONUTF8",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
    preserved = {
        key: value for key, value in os.environ.items() if key.upper() in allowed_names
    }
    preserved.update(
        {
            "HOME": str(output_dir),
            "NEKO_SKILL_OUTPUT_DIR": str(output_dir),
            "NEKO_SKILL_ROOT": str(skill_root),
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
    os.environ.clear()
    os.environ.update(preserved)


def _parse_args(raw_args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--skill-root", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("script_args", nargs=argparse.REMAINDER)
    parsed = parser.parse_args(raw_args)
    if parsed.script_args and parsed.script_args[0] == "--":
        parsed.script_args = parsed.script_args[1:]
    return parsed


def _main(raw_args: list[str]) -> int:
    try:
        args = _parse_args(raw_args)
        trusted_launcher = _validate_trusted_launcher(Path(__file__))
        skill_root = _validate_directory(Path(args.skill_root), label="skill root")
        script = _validate_script(skill_root, Path(args.script))
        output_dir = _validate_output(skill_root, Path(args.output_dir))
        if _resolve_path(Path.cwd(), strict=True) != skill_root:
            raise SandboxViolation("working directory is not the managed skill root")
    except SandboxViolation as exc:
        _emit_marker(
            SANDBOX_VIOLATION_MARKER,
            {"operation": "startup", "message": str(exc)},
        )
        return EXIT_SANDBOX_VIOLATION
    except (OSError, ValueError) as exc:
        _emit_marker(
            SANDBOX_VIOLATION_MARKER,
            {"operation": "startup", "message": f"invalid sandbox path: {exc}"},
        )
        return EXIT_SANDBOX_VIOLATION

    _minimal_environment(skill_root, output_dir)
    system_roots = _collect_system_roots(skill_root)
    policy = _AuditPolicy(
        skill_root=skill_root,
        output_dir=output_dir,
        system_roots=system_roots,
        trusted_stat_files=(trusted_launcher,),
    )

    sys.dont_write_bytecode = True
    for import_root in (skill_root, script.parent):
        root_text = str(import_root)
        if root_text not in sys.path:
            sys.path.insert(0, root_text)

    sys.addaudithook(policy.audit)
    _install_stat_guards(policy)
    sys.argv = [str(script), *args.script_args]

    exit_code = 0
    missing_module: ModuleNotFoundError | None = None
    uncaught_violation: SandboxViolation | None = None
    try:
        runpy.run_path(str(script), run_name="__main__")
    except ModuleNotFoundError as exc:
        missing_module = exc
        exit_code = EXIT_MISSING_MODULE
    except SandboxViolation as exc:
        uncaught_violation = exc
        exit_code = EXIT_SANDBOX_VIOLATION
    except SystemExit as exc:
        if exc.code is None:
            exit_code = 0
        elif isinstance(exc.code, int):
            exit_code = exc.code
        else:
            print(str(exc.code), file=sys.stderr, flush=True)
            exit_code = 1
    except BaseException:
        traceback.print_exc()
        exit_code = 1

    if policy.first_violation is not None:
        _emit_marker(
            SANDBOX_VIOLATION_MARKER,
            {
                "operation": "runtime",
                "message": policy.first_violation,
            },
        )
        return EXIT_SANDBOX_VIOLATION
    if uncaught_violation is not None:
        _emit_marker(
            SANDBOX_VIOLATION_MARKER,
            {"operation": "runtime", "message": str(uncaught_violation)},
        )
        return EXIT_SANDBOX_VIOLATION
    if missing_module is not None:
        _emit_marker(
            MISSING_MODULE_MARKER,
            {
                "module": missing_module.name or "",
                "message": (
                    f"Python module '{missing_module.name}' is unavailable in the "
                    "current isolated runtime. Install it in a dedicated environment "
                    "before retrying; the skill loader will not install packages."
                ),
            },
        )
        return EXIT_MISSING_MODULE
    return exit_code


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
