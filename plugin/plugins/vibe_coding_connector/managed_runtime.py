"""Managed, pinned HAPI runtime for the Vibe Coding connector."""

from __future__ import annotations

import hashlib
import heapq
import http.client
import json
import os
import platform
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence

try:
    import psutil
except ImportError:  # pragma: no cover - N.E.K.O ships psutil
    psutil = None  # type: ignore[assignment]


RUNTIME_VERSION = "0.25.1"
_MANIFEST_SCHEMA_VERSION = 1
_LOOPBACK_HOST = "127.0.0.1"
_MAX_HTTP_BODY_BYTES = 1_048_576
_MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
_OWNERSHIP_SCHEMA_VERSION = 2
_TOKEN_BYTES = 32
_TOKEN_MAX_CHARS = 256
_PROCESS_ROLES = ("runner", "hub")
_HEALTH_PROBE_INTERVAL_SECONDS = 1.0
_HEALTH_FAILURE_LIMIT = 3
_LIFECYCLE_LOCK_TIMEOUT_SECONDS = 5.0


class ManagedHapiError(RuntimeError):
    """Safe managed-runtime error carrying a stable public code."""

    def __init__(self, message: str, *, code: str = "runtime_error") -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    """One pinned release asset from the runtime manifest."""

    platform_key: str
    asset_name: str
    archive_path: str
    download_url: str
    archive_format: str
    executable: str
    size: int
    sha256: str
    executable_sha256: str = ""


@dataclass(frozen=True, slots=True)
class RuntimeCatalog:
    """Validated runtime manifest data."""

    version: str
    release_url: str
    source_url: str
    license: str
    bundles: Mapping[str, RuntimeBundle]

    @classmethod
    def load(cls, path: Path) -> RuntimeCatalog:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError) as exc:
            raise ManagedHapiError(
                "内置 HAPI runtime manifest 无法读取",
                code="runtime_manifest_invalid",
            ) from exc
        if not isinstance(raw, Mapping):
            raise ManagedHapiError(
                "内置 HAPI runtime manifest 格式无效",
                code="runtime_manifest_invalid",
            )
        if raw.get("schema_version") != _MANIFEST_SCHEMA_VERSION:
            raise ManagedHapiError(
                "内置 HAPI runtime manifest 版本不受支持",
                code="runtime_manifest_invalid",
            )
        version = _bounded_text(raw.get("version"), maximum=64)
        if version != RUNTIME_VERSION:
            raise ManagedHapiError(
                "内置 HAPI runtime 版本与插件锁版不一致",
                code="runtime_version_mismatch",
            )
        release_url = _validated_https_url(raw.get("release_url"))
        source_url = _validated_https_url(raw.get("source_url"))
        license_name = _bounded_text(raw.get("license"), maximum=64)
        if license_name != "AGPL-3.0-only":
            raise ManagedHapiError(
                "内置 HAPI runtime 许可证声明无效",
                code="runtime_manifest_invalid",
            )
        bundle_raw = raw.get("bundles")
        if not isinstance(bundle_raw, Mapping) or not bundle_raw:
            raise ManagedHapiError(
                "内置 HAPI runtime manifest 没有平台资产",
                code="runtime_manifest_invalid",
            )
        bundles: dict[str, RuntimeBundle] = {}
        for key, value in bundle_raw.items():
            platform_key = _bounded_text(key, maximum=64)
            if (
                not platform_key
                or not isinstance(value, Mapping)
                or platform_key in bundles
            ):
                raise ManagedHapiError(
                    "内置 HAPI runtime 平台资产格式无效",
                    code="runtime_manifest_invalid",
                )
            asset_name = _safe_filename(value.get("asset_name"))
            archive_path = _safe_relative_path(value.get("archive_path"))
            download_url = _validated_https_url(value.get("download_url"))
            archive_format = _bounded_text(
                value.get("archive_format"),
                maximum=16,
            )
            if archive_format not in {"zip", "tar.gz"}:
                raise ManagedHapiError(
                    "内置 HAPI runtime 压缩格式无效",
                    code="runtime_manifest_invalid",
                )
            executable = _safe_relative_path(value.get("executable"))
            size = value.get("size")
            if (
                isinstance(size, bool)
                or not isinstance(size, int)
                or not 1 <= size <= _MAX_DOWNLOAD_BYTES
            ):
                raise ManagedHapiError(
                    "内置 HAPI runtime 资产大小无效",
                    code="runtime_manifest_invalid",
                )
            sha256 = _sha256_text(value.get("sha256"))
            executable_sha256 = _optional_sha256_text(
                value.get("executable_sha256")
            )
            bundles[platform_key] = RuntimeBundle(
                platform_key=platform_key,
                asset_name=asset_name,
                archive_path=archive_path,
                download_url=download_url,
                archive_format=archive_format,
                executable=executable,
                size=size,
                sha256=sha256,
                executable_sha256=executable_sha256,
            )
        return cls(
            version=version,
            release_url=release_url,
            source_url=source_url,
            license=license_name,
            bundles=bundles,
        )


@dataclass(frozen=True, slots=True)
class ManagedHapiConfig:
    """Validated process-supervision settings."""

    preferred_port: int = 3006
    workspace_roots: tuple[str, ...] = ()
    allow_download: bool = False
    readiness_timeout: float = 45.0
    max_restarts: int = 3
    restart_backoff: tuple[float, ...] = (0.5, 1.0, 2.0)
    monitor_interval: float = 0.25
    max_log_bytes: int = 1_048_576
    log_backups: int = 2
    extra_env: Mapping[str, str] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.preferred_port, bool)
            or not isinstance(self.preferred_port, int)
            or not 1024 <= self.preferred_port <= 65_535
        ):
            raise ManagedHapiError(
                "HAPI 首选端口必须在 1024 到 65535 之间",
                code="invalid_runtime_config",
            )
        if (
            isinstance(self.allow_download, bool) is False
            or isinstance(self.max_restarts, bool)
            or not isinstance(self.max_restarts, int)
            or not 0 <= self.max_restarts <= 10
        ):
            raise ManagedHapiError(
                "HAPI runtime 配置无效",
                code="invalid_runtime_config",
            )
        for value, minimum, maximum in (
            (self.readiness_timeout, 1.0, 120.0),
            (self.monitor_interval, 0.05, 5.0),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not minimum <= float(value) <= maximum
            ):
                raise ManagedHapiError(
                    "HAPI runtime 时间配置无效",
                    code="invalid_runtime_config",
                )
        if not self.restart_backoff or len(self.restart_backoff) > 10:
            raise ManagedHapiError(
                "HAPI runtime 重启退避配置无效",
                code="invalid_runtime_config",
            )
        for delay in self.restart_backoff:
            if (
                isinstance(delay, bool)
                or not isinstance(delay, (int, float))
                or not 0 <= float(delay) <= 60
            ):
                raise ManagedHapiError(
                    "HAPI runtime 重启退避配置无效",
                    code="invalid_runtime_config",
                )
        if (
            isinstance(self.max_log_bytes, bool)
            or not isinstance(self.max_log_bytes, int)
            or not 16_384 <= self.max_log_bytes <= 16 * 1024 * 1024
            or isinstance(self.log_backups, bool)
            or not isinstance(self.log_backups, int)
            or not 1 <= self.log_backups <= 5
        ):
            raise ManagedHapiError(
                "HAPI runtime 日志配置无效",
                code="invalid_runtime_config",
            )
        roots = _validate_workspace_roots(self.workspace_roots)
        object.__setattr__(self, "workspace_roots", roots)
        environment: dict[str, str] = {}
        if not isinstance(self.extra_env, Mapping) or len(self.extra_env) > 32:
            raise ManagedHapiError(
                "HAPI runtime 环境配置无效",
                code="invalid_runtime_config",
            )
        protected = {
            "HAPI_HOME",
            "DB_PATH",
            "HAPI_API_URL",
            "HAPI_PUBLIC_URL",
            "HAPI_DISABLE_VERSION_HANDOFF",
            "CLI_API_TOKEN",
            "HAPI_LISTEN_HOST",
            "HAPI_LISTEN_PORT",
        }
        for key, value in self.extra_env.items():
            if (
                not isinstance(key, str)
                or not key
                or len(key) > 128
                or key in protected
                or not isinstance(value, str)
                or len(value) > 4096
                or "\x00" in key
                or "\x00" in value
            ):
                raise ManagedHapiError(
                    "HAPI runtime 环境配置无效",
                    code="invalid_runtime_config",
                )
            environment[key] = value
        object.__setattr__(self, "extra_env", environment)


@dataclass(slots=True)
class _OwnedProcess:
    role: str
    pid: int
    create_time: float
    started_at: float
    argv: tuple[str, ...]
    process: subprocess.Popen[bytes] | None = None
    pump: _LogPump | None = None
    job: _WindowsKillJob | None = None


class _WindowsKillJob:
    """Own a Windows Job Object configured to kill its process tree on close."""

    def __init__(self, handle: int) -> None:
        self._handle = handle

    @classmethod
    def assign(cls, process: subprocess.Popen[bytes]) -> _WindowsKillJob | None:
        if os.name != "nt":  # pragma: no cover - Windows-only boundary
            return None
        try:  # pragma: no cover - exercised on the Windows delivery host
            import ctypes
            from ctypes import wintypes

            class _IoCounters(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong),
                ]

            class _BasicLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class _ExtendedLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", _BasicLimitInformation),
                    ("IoInfo", _IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.AssignProcessToJobObject.argtypes = [
                wintypes.HANDLE,
                wintypes.HANDLE,
            ]
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return None
            information = _ExtendedLimitInformation()
            information.BasicLimitInformation.LimitFlags = 0x00002000
            if not kernel32.SetInformationJobObject(
                handle,
                9,
                ctypes.byref(information),
                ctypes.sizeof(information),
            ):
                kernel32.CloseHandle(handle)
                return None
            process_handle = wintypes.HANDLE(int(getattr(process, "_handle")))
            if not kernel32.AssignProcessToJobObject(handle, process_handle):
                kernel32.CloseHandle(handle)
                return None
            return cls(int(handle))
        except (AttributeError, OSError, TypeError, ValueError):
            return None

    def close(self) -> None:
        handle = self._handle
        self._handle = 0
        if not handle or os.name != "nt":
            return
        try:  # pragma: no cover - exercised on the Windows delivery host
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle(wintypes.HANDLE(handle))
        except (OSError, TypeError, ValueError):
            pass

    def __del__(self) -> None:  # pragma: no cover - interpreter safety net
        self.close()


class _LogPump(threading.Thread):
    def __init__(
        self,
        *,
        stream: BinaryIO,
        path: Path,
        maximum: int,
        backups: int,
        redactions: Sequence[bytes],
    ) -> None:
        super().__init__(name=f"hapi-log-{path.stem}", daemon=True)
        self._stream = stream
        self._path = path
        self._maximum = maximum
        self._backups = backups
        self._redactions = tuple(item for item in redactions if item)

    def run(self) -> None:  # pragma: no cover - exercised through runtime tests
        overlap = max((len(item) for item in self._redactions), default=0)
        overlap = max(0, overlap - 1)
        pending = b""
        try:
            while True:
                chunk = self._stream.read(8192)
                if not chunk:
                    break
                chunk = pending + chunk
                for secret in self._redactions:
                    chunk = chunk.replace(secret, b"[REDACTED]")
                if overlap and len(chunk) > overlap:
                    self._write(chunk[:-overlap])
                    pending = chunk[-overlap:]
                elif overlap:
                    pending = chunk
                else:
                    self._write(chunk)
                    pending = b""
            if pending:
                for secret in self._redactions:
                    pending = pending.replace(secret, b"[REDACTED]")
                self._write(pending)
        except (OSError, ValueError):
            pass
        finally:
            try:
                self._stream.close()
            except OSError:
                pass

    def _write(self, chunk: bytes) -> None:
        if (
            _is_link_or_junction(self._path.parent)
            or _is_link_or_junction(self._path)
        ):
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if len(chunk) > self._maximum:
            chunk = chunk[-self._maximum :]
        try:
            current_size = self._path.stat().st_size
        except OSError:
            current_size = 0
        if current_size + len(chunk) > self._maximum:
            for index in range(self._backups, 0, -1):
                source = self._path if index == 1 else _backup_path(
                    self._path,
                    index - 1,
                )
                target = _backup_path(self._path, index)
                if not source.exists():
                    continue
                try:
                    os.replace(source, target)
                except OSError:
                    pass
        try:
            with self._path.open("ab") as handle:
                handle.write(chunk)
            _chmod_private(self._path)
        except OSError:
            pass


class ManagedHapiRuntime:
    """Own, supervise, and expose one isolated HAPI hub and runner."""

    def __init__(
        self,
        *,
        bundle_root: Path,
        data_root: Path,
        config: ManagedHapiConfig,
        logger: Any = None,
        platform_key: str | None = None,
    ) -> None:
        self._bundle_root = Path(bundle_root).resolve()
        self._data_root = Path(os.path.abspath(data_root))
        self._config = config
        self._logger = logger
        self._platform_key = platform_key or detect_platform_key()
        self._catalog: RuntimeCatalog | None = None
        self._bundle: RuntimeBundle | None = None
        self._executable: Path | None = None
        self._runtime_dir: Path | None = None
        self._token: str | None = None
        self._processes: dict[str, _OwnedProcess] = {}
        self._actual_port = 0
        self._hub_ready = False
        self._runner_ready = False
        self._state = "stopped"
        self._last_error = ""
        self._restart_count = 0
        self._generation = 0
        self._bundled = False
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._next_log_maintenance = 0.0
        self._next_health_probe = 0.0
        self._health_failure_count = 0
        self._lifecycle_lock_file: BinaryIO | None = None

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    @property
    def base_url(self) -> str:
        with self._lock:
            if self._actual_port <= 0:
                return ""
            return f"http://{_LOOPBACK_HOST}:{self._actual_port}"

    @property
    def access_token(self) -> str | None:
        with self._lock:
            return self._token

    def status(self) -> dict[str, Any]:
        with self._lock:
            catalog = self._catalog
            bundle = self._bundle
            processes = {
                role: {
                    "pid": owned.pid,
                    "created_at": owned.create_time,
                }
                for role, owned in self._processes.items()
                if self._same_process(owned)
            }
            actual_port = self._actual_port
            state = self._state
            if state in {"ready", "degraded"} and not self._all_required_alive():
                state = "restarting" if self._monitor_alive() else "failed"
            return {
                "state": state,
                "version": catalog.version if catalog else RUNTIME_VERSION,
                "platform": self._platform_key,
                "bundled": self._bundled,
                "download_enabled": self._config.allow_download,
                "actual_port": actual_port or None,
                "base_url": (
                    f"http://{_LOOPBACK_HOST}:{actual_port}"
                    if actual_port
                    else ""
                ),
                "hub_ready": self._hub_ready,
                "runner_ready": self._runner_ready,
                "workspace_root_count": len(self._config.workspace_roots),
                "restart_count": self._restart_count,
                "max_restarts": self._config.max_restarts,
                "processes": processes,
                "runtime_dir": str(self._runtime_dir or ""),
                "log_dir": str(self._logs_dir),
                "native_log_dir": str(
                    self._data_root / "hapi-home" / "logs"
                ),
                "last_error": self._last_error,
                "source_url": catalog.source_url if catalog else "",
                "release_url": catalog.release_url if catalog else "",
                "archive_sha256": bundle.sha256 if bundle else "",
                "license": catalog.license if catalog else "AGPL-3.0-only",
                "provider_note": (
                    "HAPI 已内置；Claude、Codex、OpenCode 仍需分别安装并登录。"
                ),
            }

    def prepare(self) -> Path:
        with self._lock:
            already_leased = self._lifecycle_lock_file is not None
            self._ensure_data_root()
            self._acquire_lifecycle_lease_locked()
            try:
                return self._prepare_locked()
            finally:
                if not already_leased and not self._processes:
                    self._release_lifecycle_lease_locked()

    def start(self, *, reset_budget: bool = False) -> dict[str, Any]:
        with self._lock:
            if self._state in {"ready", "degraded"} and self._all_required_alive():
                return self.status()
            if self._state in {"starting", "restarting"} and self._monitor_alive():
                return self.status()
            if (
                self._state in {"failed", "shutdown_failed", "unsupported"}
                and not reset_budget
            ):
                return self.status()
            try:
                self._ensure_data_root()
                self._acquire_lifecycle_lease_locked()
                self._stop_event.clear()
                if reset_budget or self._state == "stopped":
                    self._restart_count = 0
                self._last_error = ""
                self._state = "preparing"
                self._prepare_locked()
                if self._adopt_owned_locked():
                    self._start_monitor_locked()
                    return self.status()
                self._start_with_budget_locked(prefer_existing_port=False)
                self._start_monitor_locked()
                return self.status()
            except ManagedHapiError as exc:
                self._last_error = exc.public_message
                self._state = (
                    "unsupported"
                    if exc.code in {"platform_unsupported", "runtime_not_bundled"}
                    else "busy"
                    if exc.code == "runtime_lifecycle_busy"
                    else "failed"
                )
                terminated = self._terminate_processes_locked()
                if terminated:
                    self._release_lifecycle_lease_locked()
                raise
            except Exception as exc:
                self._last_error = (
                    f"HAPI runtime 启动失败（{type(exc).__name__}）"
                )
                self._state = "failed"
                terminated = self._terminate_processes_locked()
                if terminated:
                    self._release_lifecycle_lease_locked()
                raise ManagedHapiError(
                    self._last_error,
                    code="runtime_start_failed",
                ) from exc

    def restart(self) -> dict[str, Any]:
        stopped = self.stop()
        if stopped.get("state") != "stopped":
            raise ManagedHapiError(
                str(stopped.get("last_error") or "HAPI runtime 无法安全停止"),
                code="runtime_shutdown_failed",
            )
        return self.start(reset_budget=True)

    def stop(self) -> dict[str, Any]:
        self._stop_event.set()
        monitor = self._monitor_thread
        if (
            monitor is not None
            and monitor is not threading.current_thread()
            and monitor.is_alive()
        ):
            monitor.join(timeout=max(2.0, self._config.readiness_timeout + 1.0))
        with self._lock:
            self._monitor_thread = None
            terminated = self._terminate_processes_locked()
            self._hub_ready = False
            self._runner_ready = False
            self._generation += 1
            if not terminated:
                self._state = "shutdown_failed"
                return self.status()
            self._actual_port = 0
            self._state = "stopped"
            self._last_error = ""
            self._release_lifecycle_lease_locked()
            return self.status()

    def _start_with_budget_locked(self, *, prefer_existing_port: bool) -> None:
        reuse_port = prefer_existing_port
        while True:
            try:
                self._start_once_locked(prefer_existing_port=reuse_port)
                return
            except ManagedHapiError as exc:
                if self._stop_event.is_set():
                    raise
                self._last_error = exc.public_message
                if self._restart_count >= self._config.max_restarts:
                    self._state = "failed"
                    self._hub_ready = False
                    self._runner_ready = False
                    self._terminate_processes_locked()
                    raise ManagedHapiError(
                        f"{exc.public_message}；已达到有限重启上限",
                        code="runtime_restart_limit",
                    ) from exc
                self._restart_count += 1
                restart_number = self._restart_count
                self._state = "restarting"
                if not self._terminate_processes_locked(keep_port=True):
                    raise ManagedHapiError(
                        self._last_error,
                        code="runtime_shutdown_failed",
                    ) from exc
                delay = self._config.restart_backoff[
                    min(
                        restart_number - 1,
                        len(self._config.restart_backoff) - 1,
                    )
                ]
                if self._stop_event.wait(delay):
                    raise ManagedHapiError(
                        "HAPI runtime 启动已取消",
                        code="runtime_start_cancelled",
                    ) from exc
                reuse_port = True

    def _prepare_locked(self) -> Path:
        self._ensure_data_root()
        catalog = RuntimeCatalog.load(self._bundle_root / "manifest.json")
        bundle = catalog.bundles.get(self._platform_key)
        if bundle is None:
            self._catalog = catalog
            raise ManagedHapiError(
                f"HAPI v{catalog.version} 不支持当前平台 {self._platform_key}",
                code="platform_unsupported",
            )
        archive_path = _contained_path(
            self._bundle_root,
            bundle.archive_path,
            kind="runtime archive",
        )
        self._bundled = archive_path.is_file()
        if not archive_path.is_file():
            if not self._config.allow_download:
                self._catalog = catalog
                self._bundle = bundle
                raise ManagedHapiError(
                    (
                        f"安装包未内置 {self._platform_key} HAPI runtime；"
                        "可在高级设置启用校验下载，或改用外部 HAPI"
                    ),
                    code="runtime_not_bundled",
                )
            archive_path = self._download_bundle_locked(bundle)
        _verify_file(
            archive_path,
            expected_size=bundle.size,
            expected_sha256=bundle.sha256,
        )
        expected_executable_sha = (
            bundle.executable_sha256
            or _archive_executable_sha256(archive_path, bundle)
        )
        versions_dir = self._data_root / "versions"
        version_dir = versions_dir / catalog.version
        _ensure_owned_directory(versions_dir, self._data_root)
        _ensure_owned_directory(version_dir, self._data_root)
        runtime_dir = version_dir / bundle.platform_key
        if _is_link_or_junction(runtime_dir):
            raise ManagedHapiError(
                "HAPI runtime 解包目录不安全",
                code="runtime_path_invalid",
            )
        if runtime_dir.exists():
            _assert_within(runtime_dir, self._data_root)
        executable = runtime_dir / Path(bundle.executable)
        marker_path = runtime_dir / ".bundle.json"
        _assert_within(executable, self._data_root)
        _assert_within(marker_path, self._data_root)
        if not self._extracted_bundle_valid(
            marker_path=marker_path,
            executable=executable,
            bundle=bundle,
            expected_executable_sha=expected_executable_sha,
        ):
            self._extract_bundle_atomic(
                archive_path=archive_path,
                runtime_dir=runtime_dir,
                bundle=bundle,
                expected_executable_sha=expected_executable_sha,
            )
        if not executable.is_file() or _is_link_or_junction(executable):
            raise ManagedHapiError(
                "解包后的 HAPI 可执行文件缺失或不安全",
                code="runtime_extract_failed",
            )
        if os.name != "nt":
            try:
                executable.chmod(executable.stat().st_mode | 0o700)
            except OSError as exc:
                raise ManagedHapiError(
                    "无法设置 HAPI 可执行权限",
                    code="runtime_extract_failed",
                ) from exc
        _verify_file(
            executable,
            expected_size=None,
            expected_sha256=expected_executable_sha,
        )
        self._catalog = catalog
        self._bundle = bundle
        self._runtime_dir = runtime_dir.resolve()
        self._executable = executable.resolve()
        self._token = self._load_or_create_token()
        return self._executable

    def _ensure_data_root(self) -> None:
        if _is_link_or_junction(self._data_root):
            raise ManagedHapiError(
                "HAPI runtime 数据目录不安全",
                code="runtime_path_invalid",
            )
        self._data_root.mkdir(parents=True, exist_ok=True)
        if (
            _is_link_or_junction(self._data_root)
            or not self._data_root.is_dir()
        ):
            raise ManagedHapiError(
                "HAPI runtime 数据目录不安全",
                code="runtime_path_invalid",
            )
        _assert_within(self._data_root, self._data_root)
        _chmod_private_directory(self._data_root)

    def _acquire_lifecycle_lease_locked(self) -> None:
        if self._lifecycle_lock_file is not None:
            return
        lock_path = self._data_root / "lifecycle.lock"
        if _is_link_or_junction(lock_path):
            raise ManagedHapiError(
                "HAPI runtime 生命周期锁路径不安全",
                code="runtime_path_invalid",
            )
        handle: BinaryIO | None = None
        try:
            handle = lock_path.open("a+b")
            _chmod_private(lock_path)
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            deadline = time.monotonic() + _LIFECYCLE_LOCK_TIMEOUT_SECONDS
            while not _try_lock_file(handle):
                if time.monotonic() >= deadline:
                    raise ManagedHapiError(
                        "另一插件实例正在管理此 HAPI runtime，请稍后重试",
                        code="runtime_lifecycle_busy",
                    )
                time.sleep(0.05)
        except ManagedHapiError:
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
            raise
        except OSError as exc:
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
            raise ManagedHapiError(
                "HAPI runtime 生命周期锁无法创建",
                code="runtime_path_invalid",
            ) from exc
        if handle is None:  # pragma: no cover - defensive type boundary
            raise ManagedHapiError(
                "HAPI runtime 生命周期锁无法创建",
                code="runtime_path_invalid",
            )
        self._lifecycle_lock_file = handle

    def _release_lifecycle_lease_locked(self) -> None:
        handle = self._lifecycle_lock_file
        self._lifecycle_lock_file = None
        if handle is None:
            return
        try:
            _unlock_file(handle)
        finally:
            try:
                handle.close()
            except OSError:
                pass

    def _download_bundle_locked(self, bundle: RuntimeBundle) -> Path:
        download_dir = self._data_root / "downloads"
        _ensure_owned_directory(download_dir, self._data_root)
        target = download_dir / bundle.asset_name
        if target.is_file():
            try:
                _verify_file(
                    target,
                    expected_size=bundle.size,
                    expected_sha256=bundle.sha256,
                )
                return target
            except ManagedHapiError:
                target.unlink(missing_ok=True)
        temporary = download_dir / f".{bundle.asset_name}.{secrets.token_hex(8)}.part"
        request = urllib.request.Request(
            bundle.download_url,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "NEKO-vibe-coding-connector/0.2.0",
            },
            method="GET",
        )
        digest = hashlib.sha256()
        total = 0
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                header = response.headers.get("Content-Length")
                if header:
                    try:
                        announced = int(header)
                    except ValueError:
                        announced = 0
                    if announced > _MAX_DOWNLOAD_BYTES:
                        raise ManagedHapiError(
                            "HAPI runtime 下载大小超过安全上限",
                            code="runtime_download_failed",
                        )
                with temporary.open("xb") as handle:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > _MAX_DOWNLOAD_BYTES or total > bundle.size:
                            raise ManagedHapiError(
                                "HAPI runtime 下载大小与锁版记录不符",
                                code="runtime_download_failed",
                            )
                        digest.update(chunk)
                        handle.write(chunk)
            if total != bundle.size or digest.hexdigest() != bundle.sha256:
                raise ManagedHapiError(
                    "HAPI runtime 下载校验失败",
                    code="checksum_mismatch",
                )
            os.replace(temporary, target)
            _chmod_private(target)
            return target
        except ManagedHapiError:
            temporary.unlink(missing_ok=True)
            raise
        except (OSError, urllib.error.URLError) as exc:
            temporary.unlink(missing_ok=True)
            raise ManagedHapiError(
                f"HAPI runtime 下载失败（{type(exc).__name__}）",
                code="runtime_download_failed",
            ) from exc

    def _extracted_bundle_valid(
        self,
        *,
        marker_path: Path,
        executable: Path,
        bundle: RuntimeBundle,
        expected_executable_sha: str,
    ) -> bool:
        if (
            not marker_path.is_file()
            or _is_link_or_junction(marker_path)
            or not executable.is_file()
            or _is_link_or_junction(executable)
        ):
            return False
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            return False
        if not isinstance(marker, Mapping):
            return False
        if (
            marker.get("version") != RUNTIME_VERSION
            or marker.get("platform") != bundle.platform_key
            or marker.get("archive_sha256") != bundle.sha256
            or marker.get("executable") != bundle.executable
        ):
            return False
        if marker.get("executable_sha256") != expected_executable_sha:
            return False
        try:
            return _sha256_file(executable) == expected_executable_sha
        except OSError:
            return False

    def _extract_bundle_atomic(
        self,
        *,
        archive_path: Path,
        runtime_dir: Path,
        bundle: RuntimeBundle,
        expected_executable_sha: str,
    ) -> None:
        parent = runtime_dir.parent
        versions = self._data_root / "versions"
        _ensure_owned_directory(versions, self._data_root)
        _ensure_owned_directory(parent, self._data_root)
        temporary = Path(
            tempfile.mkdtemp(
                prefix=f".{bundle.platform_key}-",
                dir=str(parent),
            )
        )
        try:
            if bundle.archive_format == "zip":
                self._extract_zip(archive_path, temporary)
            else:
                self._extract_tar(archive_path, temporary)
            executable = temporary / Path(bundle.executable)
            if not executable.is_file() or _is_link_or_junction(executable):
                raise ManagedHapiError(
                    "官方 HAPI 资产没有预期的可执行文件",
                    code="runtime_extract_failed",
                )
            executable_sha = _sha256_file(executable)
            if executable_sha != expected_executable_sha:
                raise ManagedHapiError(
                    "HAPI 可执行文件校验失败",
                    code="checksum_mismatch",
                )
            marker = {
                "version": RUNTIME_VERSION,
                "platform": bundle.platform_key,
                "archive_sha256": bundle.sha256,
                "executable": bundle.executable,
                "executable_sha256": executable_sha,
            }
            _atomic_json_write(temporary / ".bundle.json", marker)
            if runtime_dir.exists():
                _assert_within(runtime_dir, self._data_root)
                shutil.rmtree(runtime_dir)
            os.replace(temporary, runtime_dir)
        except ManagedHapiError:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
            shutil.rmtree(temporary, ignore_errors=True)
            raise ManagedHapiError(
                f"HAPI runtime 解包失败（{type(exc).__name__}）",
                code="runtime_extract_failed",
            ) from exc

    @staticmethod
    def _extract_zip(archive_path: Path, destination: Path) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                relative = _archive_member_path(info.filename)
                if relative is None:
                    continue
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ManagedHapiError(
                        "HAPI runtime 压缩包包含符号链接",
                        code="runtime_extract_failed",
                    )
                target = destination.joinpath(*relative.parts)
                _assert_within(target, destination)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)

    @staticmethod
    def _extract_tar(archive_path: Path, destination: Path) -> None:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                relative = _archive_member_path(member.name)
                if relative is None:
                    continue
                if member.issym() or member.islnk() or member.isdev():
                    raise ManagedHapiError(
                        "HAPI runtime 压缩包包含不安全链接或设备",
                        code="runtime_extract_failed",
                    )
                target = destination.joinpath(*relative.parts)
                _assert_within(target, destination)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ManagedHapiError(
                        "HAPI runtime 压缩包包含不支持的成员",
                        code="runtime_extract_failed",
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise ManagedHapiError(
                        "HAPI runtime 压缩包成员无法读取",
                        code="runtime_extract_failed",
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)

    def _load_or_create_token(self) -> str:
        token_path = self._data_root / "access-token"
        if _is_link_or_junction(token_path) or (
            token_path.exists() and not token_path.is_file()
        ):
            raise ManagedHapiError(
                "HAPI runtime token 路径不安全",
                code="runtime_path_invalid",
            )
        try:
            token = token_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            token = ""
        if (
            32 <= len(token) <= _TOKEN_MAX_CHARS
            and all(character.isalnum() or character in "_-" for character in token)
        ):
            _chmod_private(token_path)
            return token
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        _atomic_text_write(token_path, token, encoding="ascii")
        _chmod_private(token_path)
        return token

    def _adopt_owned_locked(self) -> bool:
        marker_path = self._ownership_path
        if _is_link_or_junction(marker_path):
            marker_path.unlink(missing_ok=True)
            return False
        try:
            raw = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            return False
        if not isinstance(raw, Mapping):
            marker_path.unlink(missing_ok=True)
            return False
        if (
            raw.get("schema_version") != _OWNERSHIP_SCHEMA_VERSION
            or raw.get("version") != RUNTIME_VERSION
            or raw.get("platform") != self._platform_key
            or raw.get("runtime_dir") != str(self._runtime_dir)
            or raw.get("config_fingerprint") != self._config_fingerprint()
        ):
            if not self._terminate_marker_processes_if_owned(raw):
                raise ManagedHapiError(
                    "旧 HAPI 进程无法安全终止；已保留 ownership 记录",
                    code="runtime_shutdown_failed",
                )
            marker_path.unlink(missing_ok=True)
            return False
        port, marker_roots = self._marker_process_context(raw)
        process_values = raw.get("processes")
        if (
            port is None
            or marker_roots is None
            or marker_roots != self._config.workspace_roots
            or not isinstance(process_values, list)
        ):
            if not self._terminate_marker_processes_if_owned(raw):
                raise ManagedHapiError(
                    "旧 HAPI 进程无法安全终止；已保留 ownership 记录",
                    code="runtime_shutdown_failed",
                )
            marker_path.unlink(missing_ok=True)
            return False
        adopted: dict[str, _OwnedProcess] = {}
        invalid = False
        for value in process_values:
            owned = self._owned_from_marker(
                value,
                port=port,
                workspace_roots=marker_roots,
            )
            if (
                owned is None
                or owned.role in adopted
                or not self._same_process(owned)
            ):
                invalid = True
                continue
            adopted[owned.role] = owned
        required = {"hub"}
        if self._config.workspace_roots:
            required.add("runner")
        if invalid or set(adopted) != required:
            if not self._terminate_marker_processes_if_owned(raw):
                raise ManagedHapiError(
                    "部分旧 HAPI 进程无法安全终止；已保留 ownership 记录",
                    code="runtime_shutdown_failed",
                )
            marker_path.unlink(missing_ok=True)
            return False
        self._processes = adopted
        self._actual_port = port
        ready, runner_ready, _ = self._probe_hapi(
            port=port,
            require_runner=bool(self._config.workspace_roots),
        )
        if not ready or (self._config.workspace_roots and not runner_ready):
            self._terminate_processes_locked()
            return False
        self._hub_ready = True
        self._runner_ready = runner_ready
        self._health_failure_count = 0
        self._next_health_probe = (
            time.monotonic() + _HEALTH_PROBE_INTERVAL_SECONDS
        )
        self._state = "ready" if runner_ready else "degraded"
        self._last_error = (
            ""
            if runner_ready
            else "尚未配置工作区；HAPI hub 已启动，runner 保持禁用"
        )
        self._generation += 1
        self._log("info", "Reused owned HAPI runtime on port {}", port)
        return True

    def _start_once_locked(self, *, prefer_existing_port: bool) -> None:
        if self._executable is None or self._runtime_dir is None or not self._token:
            raise ManagedHapiError(
                "HAPI runtime 尚未准备完成",
                code="runtime_not_prepared",
            )
        previous_port = self._actual_port
        self._terminate_processes_locked()
        self._state = "starting"
        port = 0
        if (
            prefer_existing_port
            and 1024 <= previous_port <= 65_535
            and _port_available(previous_port)
        ):
            port = previous_port
        if port <= 0:
            port = _choose_port(self._config.preferred_port)
        self._actual_port = port
        environment = self._process_environment(port)
        hub_argv = self._expected_argv(
            "hub",
            port=port,
            workspace_roots=self._config.workspace_roots,
        )
        self._spawn_owned("hub", hub_argv, environment)
        if self._config.workspace_roots:
            runner_argv = self._expected_argv(
                "runner",
                port=port,
                workspace_roots=self._config.workspace_roots,
            )
            self._spawn_owned("runner", runner_argv, environment)
        self._write_ownership_marker()
        deadline = time.monotonic() + self._config.readiness_timeout
        last_detail = "等待 HAPI 健康检查"
        while time.monotonic() < deadline:
            if self._stop_event.is_set():
                raise ManagedHapiError(
                    "HAPI runtime 启动已取消",
                    code="runtime_start_cancelled",
                )
            crashed = self._crashed_roles()
            if crashed:
                raise ManagedHapiError(
                    self._process_exit_diagnostic(crashed),
                    code="runtime_process_exited",
                )
            hub_ready, runner_ready, detail = self._probe_hapi(
                port=port,
                require_runner=bool(self._config.workspace_roots),
            )
            last_detail = detail
            if hub_ready and (
                runner_ready or not self._config.workspace_roots
            ):
                self._hub_ready = True
                self._runner_ready = runner_ready
                self._health_failure_count = 0
                self._next_health_probe = (
                    time.monotonic() + _HEALTH_PROBE_INTERVAL_SECONDS
                )
                self._state = "ready" if runner_ready else "degraded"
                self._last_error = (
                    ""
                    if runner_ready
                    else "尚未配置工作区；HAPI hub 已启动，runner 保持禁用"
                )
                self._generation += 1
                self._write_ownership_marker()
                self._log(
                    "info",
                    "Managed HAPI v{} ready on port {} (runner={})",
                    RUNTIME_VERSION,
                    port,
                    runner_ready,
                )
                return
            self._stop_event.wait(0.1)
        raise ManagedHapiError(
            (
                f"HAPI readiness 超时：{last_detail}；"
                f"诊断日志：{self._logs_dir}"
            ),
            code="runtime_readiness_timeout",
        )

    def _expected_argv(
        self,
        role: str,
        *,
        port: int,
        workspace_roots: tuple[str, ...],
    ) -> tuple[str, ...]:
        if self._executable is None:
            raise ManagedHapiError(
                "HAPI runtime 尚未准备完成",
                code="runtime_not_prepared",
            )
        executable = str(self._executable)
        if role == "hub":
            return (
                executable,
                "hub",
                "--host",
                _LOOPBACK_HOST,
                "--port",
                str(port),
                "--no-relay",
            )
        if role != "runner" or not workspace_roots:
            raise ManagedHapiError(
                "HAPI runtime 进程角色无效",
                code="runtime_start_failed",
            )
        argv: list[str] = [executable, "runner", "start-sync"]
        for root in workspace_roots:
            argv.extend(("--workspace-root", root))
        return tuple(argv)

    def _process_environment(self, port: int) -> dict[str, str]:
        hapi_home = self._data_root / "hapi-home"
        _ensure_owned_directory(hapi_home, self._data_root)
        environment = dict(os.environ)
        environment.update(self._config.extra_env)
        environment.update(
            {
                "HAPI_HOME": str(hapi_home),
                "DB_PATH": str(hapi_home / "hapi.db"),
                "HAPI_API_URL": f"http://{_LOOPBACK_HOST}:{port}",
                "HAPI_PUBLIC_URL": f"http://{_LOOPBACK_HOST}:{port}",
                "HAPI_DISABLE_VERSION_HANDOFF": "1",
                "CLI_API_TOKEN": self._token or "",
                "HAPI_LISTEN_HOST": _LOOPBACK_HOST,
                "HAPI_LISTEN_PORT": str(port),
                "NO_COLOR": "1",
            }
        )
        return environment

    def _spawn_owned(
        self,
        role: str,
        argv: tuple[str, ...],
        environment: Mapping[str, str],
    ) -> None:
        if role not in {"hub", "runner"}:
            raise ManagedHapiError(
                "HAPI runtime 进程角色无效",
                code="runtime_start_failed",
            )
        popen_kwargs: dict[str, Any] = {
            "cwd": str(self._runtime_dir),
            "env": dict(environment),
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "shell": False,
            "bufsize": 0,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = int(
                getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
            )
        else:
            popen_kwargs["start_new_session"] = True
        process: subprocess.Popen[bytes] | None = None
        job: _WindowsKillJob | None = None
        try:
            process = subprocess.Popen(list(argv), **popen_kwargs)
            job = _WindowsKillJob.assign(process)
            if os.name == "nt" and job is None:
                raise ManagedHapiError(
                    "Windows 无法建立 HAPI kill-on-close Job Object",
                    code="runtime_start_failed",
                )
            create_time = _process_create_time(process.pid)
            if os.name == "nt":
                _resume_windows_process(process)
        except ManagedHapiError:
            if job is not None:
                job.close()
            if process is not None:
                _terminate_unregistered_process(process)
            raise
        except (OSError, ValueError) as exc:
            if job is not None:
                job.close()
            if process is not None:
                _terminate_unregistered_process(process)
            raise ManagedHapiError(
                f"HAPI {role} 无法启动（{type(exc).__name__}）",
                code="runtime_start_failed",
            ) from exc
        owned = _OwnedProcess(
            role=role,
            pid=process.pid,
            create_time=create_time,
            started_at=time.time(),
            argv=argv,
            process=process,
            job=job,
        )
        self._processes[role] = owned
        stream = process.stdout
        pump: _LogPump | None = None
        if stream is not None:
            _ensure_owned_directory(self._logs_dir, self._data_root)
            pump = _LogPump(
                stream=stream,
                path=self._logs_dir / f"{role}.log",
                maximum=self._config.max_log_bytes,
                backups=self._config.log_backups,
                redactions=((self._token or "").encode("utf-8"),),
            )
            pump.start()
            owned.pump = pump

    def _probe_hapi(
        self,
        *,
        port: int,
        require_runner: bool,
    ) -> tuple[bool, bool, str]:
        connection: http.client.HTTPConnection | None = None
        try:
            connection = http.client.HTTPConnection(
                _LOOPBACK_HOST,
                port,
                timeout=0.5,
            )
            connection.request(
                "GET",
                "/health",
                headers={"Accept": "application/json", "Connection": "close"},
            )
            response = connection.getresponse()
            payload = _read_json_response(response)
            if response.status != 200:
                return False, False, f"/health 返回 HTTP {response.status}"
            source = payload.get("data") if isinstance(payload.get("data"), Mapping) else payload
            health_status = str(source.get("status") or "").lower()
            if health_status != "ok":
                return False, False, f"/health 状态为 {health_status or 'unknown'}"
            if source.get("protocolVersion") != 1:
                return False, False, "/health protocolVersion 与锁版 HAPI 不匹配"
        except (OSError, ValueError, http.client.HTTPException) as exc:
            return False, False, f"/health 尚不可用（{type(exc).__name__}）"
        finally:
            if connection is not None:
                connection.close()
        if not require_runner:
            return True, False, "hub ready; runner disabled until workspace is set"

        bearer = ""
        try:
            auth_body = json.dumps(
                {"accessToken": self._token or ""},
                separators=(",", ":"),
            ).encode("utf-8")
            connection = http.client.HTTPConnection(
                _LOOPBACK_HOST,
                port,
                timeout=0.75,
            )
            connection.request(
                "POST",
                "/api/auth",
                body=auth_body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(auth_body)),
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            auth_payload = _read_json_response(response)
            if response.status != 200:
                return True, False, f"/api/auth 返回 HTTP {response.status}"
            auth_data = (
                auth_payload.get("data")
                if isinstance(auth_payload.get("data"), Mapping)
                else {}
            )
            for key in ("token", "bearerToken", "jwt"):
                value = auth_payload.get(key) or auth_data.get(key)
                if isinstance(value, str) and value:
                    bearer = value
                    break
        except (OSError, ValueError, http.client.HTTPException) as exc:
            return True, False, f"/api/auth 尚不可用（{type(exc).__name__}）"
        finally:
            if connection is not None:
                connection.close()
        if not bearer:
            return True, False, "/api/auth 未返回 bearer token"

        try:
            connection = http.client.HTTPConnection(
                _LOOPBACK_HOST,
                port,
                timeout=0.75,
            )
            connection.request(
                "GET",
                "/api/machines",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {bearer}",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            machine_payload = _read_json_response(response)
            if response.status != 200:
                return True, False, f"/api/machines 返回 HTTP {response.status}"
            raw_machines = machine_payload.get("machines")
            if raw_machines is None and isinstance(
                machine_payload.get("data"),
                Mapping,
            ):
                raw_machines = machine_payload["data"].get("machines")
            if not isinstance(raw_machines, list):
                return True, False, "/api/machines 响应格式无效"
            matching = any(
                self._machine_matches_runtime(item)
                for item in raw_machines[:100]
                if isinstance(item, Mapping)
            )
            if not matching:
                return True, False, "runner 尚未以锁版、隔离目录和受限 roots 在线"
            return True, True, "hub and runner ready"
        except (OSError, ValueError, http.client.HTTPException) as exc:
            return True, False, f"/api/machines 尚不可用（{type(exc).__name__}）"
        finally:
            if connection is not None:
                connection.close()

    def _machine_matches_runtime(self, machine: Mapping[str, Any]) -> bool:
        online = (
            machine.get("active") is True
            or machine.get("isOnline") is True
            or machine.get("online") is True
            or str(machine.get("status") or "").lower() == "online"
        )
        machine_id = machine.get("id") or machine.get("machineId")
        metadata = machine.get("metadata")
        runner_state = machine.get("runnerState") or machine.get("runner_state")
        owned_runner = self._processes.get("runner")
        runner_pid = (
            runner_state.get("pid")
            if isinstance(runner_state, Mapping)
            else None
        )
        if (
            not online
            or not isinstance(machine_id, str)
            or not machine_id
            or not isinstance(metadata, Mapping)
            or metadata.get("happyCliVersion") != RUNTIME_VERSION
            or not isinstance(runner_state, Mapping)
            or str(runner_state.get("status") or "").lower() != "running"
            or owned_runner is None
            or isinstance(runner_pid, bool)
            or not isinstance(runner_pid, int)
            or runner_pid != owned_runner.pid
        ):
            return False
        home = metadata.get("happyHomeDir")
        roots = metadata.get("workspaceRoots")
        if (
            not isinstance(home, str)
            or not Path(home).is_absolute()
            or not isinstance(roots, list)
            or len(roots) != len(self._config.workspace_roots)
        ):
            return False
        expected_home = _normalized_path(self._data_root / "hapi-home")
        if _normalized_path(Path(home)) != expected_home:
            return False
        expected_roots = tuple(
            _normalized_path(Path(root))
            for root in self._config.workspace_roots
        )
        actual_roots: list[str] = []
        for root in roots:
            if not isinstance(root, str) or not Path(root).is_absolute():
                return False
            actual_roots.append(_normalized_path(Path(root)))
        return tuple(actual_roots) == expected_roots

    def _start_monitor_locked(self) -> None:
        if self._monitor_alive():
            return
        monitor = threading.Thread(
            target=self._monitor_main,
            name="vibe-coding-hapi-supervisor",
            daemon=True,
        )
        self._monitor_thread = monitor
        monitor.start()

    def _monitor_main(self) -> None:
        while not self._stop_event.wait(self._config.monitor_interval):
            with self._lock:
                self._bound_native_logs()
                crashed = self._crashed_roles()
                failure = self._process_exit_diagnostic(crashed) if crashed else ""
                now = time.monotonic()
                if (
                    not failure
                    and self._state in {"ready", "degraded"}
                    and now >= self._next_health_probe
                ):
                    self._next_health_probe = (
                        now + _HEALTH_PROBE_INTERVAL_SECONDS
                    )
                    hub_ready, runner_ready, detail = self._probe_hapi(
                        port=self._actual_port,
                        require_runner=bool(self._config.workspace_roots),
                    )
                    healthy = hub_ready and (
                        runner_ready or not self._config.workspace_roots
                    )
                    if healthy:
                        self._health_failure_count = 0
                        self._hub_ready = True
                        self._runner_ready = runner_ready
                    else:
                        self._health_failure_count += 1
                        if self._health_failure_count >= _HEALTH_FAILURE_LIMIT:
                            failure = f"HAPI readiness 已丢失：{detail}"
                if not failure:
                    continue
                if self._restart_count >= self._config.max_restarts:
                    self._last_error = failure + "；已达到有限重启上限"
                    self._state = "failed"
                    self._hub_ready = False
                    self._runner_ready = False
                    terminated = self._terminate_processes_locked()
                    if terminated:
                        self._release_lifecycle_lease_locked()
                    self._generation += 1
                    return
                self._restart_count += 1
                restart_number = self._restart_count
                self._state = "restarting"
                self._last_error = failure
                self._hub_ready = False
                self._runner_ready = False
                if not self._terminate_processes_locked(keep_port=True):
                    self._generation += 1
                    return
                self._generation += 1
            delay = self._config.restart_backoff[
                min(restart_number - 1, len(self._config.restart_backoff) - 1)
            ]
            if self._stop_event.wait(delay):
                return
            with self._lock:
                if self._stop_event.is_set():
                    return
                try:
                    self._start_once_locked(prefer_existing_port=True)
                except ManagedHapiError as exc:
                    self._last_error = exc.public_message
                    self._state = "restarting"
                    if not self._terminate_processes_locked(keep_port=True):
                        return
                    continue
                except Exception as exc:
                    self._last_error = (
                        "HAPI runtime 监督重启失败"
                        f"（{type(exc).__name__}）"
                    )
                    self._state = "restarting"
                    if not self._terminate_processes_locked(keep_port=True):
                        return
                    continue

    def _bound_native_logs(self) -> None:
        """Best-effort cap HAPI's own append-only log files."""

        now = time.monotonic()
        if now < self._next_log_maintenance:
            return
        self._next_log_maintenance = now + 5.0
        log_root = self._data_root / "hapi-home" / "logs"
        if not log_root.is_dir() or _is_link_or_junction(log_root):
            return
        keep_count = max(2, self._config.log_backups * len(_PROCESS_ROLES))
        newest: list[tuple[float, str, Path]] = []
        try:
            for path in log_root.rglob("*.log"):
                if not path.is_file() or _is_link_or_junction(path):
                    continue
                _assert_within(path, log_root)
                item = (path.stat().st_mtime, str(path), path)
                if len(newest) < keep_count:
                    heapq.heappush(newest, item)
                    continue
                if item > newest[0]:
                    stale = heapq.heapreplace(newest, item)[2]
                else:
                    stale = path
                try:
                    stale.unlink()
                except OSError:
                    pass
        except (ManagedHapiError, OSError):
            return
        candidates = [
            item[2]
            for item in sorted(newest, reverse=True)
        ]
        for current in candidates:
            try:
                _assert_within(current, log_root)
                size = current.stat().st_size
                with current.open("r+b") as handle:
                    if size > self._config.max_log_bytes:
                        handle.seek(-self._config.max_log_bytes, os.SEEK_END)
                    else:
                        handle.seek(0)
                    tail = handle.read(self._config.max_log_bytes)
                    redacted = tail
                    if self._token:
                        redacted = tail.replace(
                            self._token.encode("utf-8"),
                            b"[REDACTED]",
                        )
                    if (
                        size <= self._config.max_log_bytes
                        and redacted == tail
                    ):
                        continue
                    handle.seek(0)
                    handle.write(redacted)
                    handle.truncate()
            except (ManagedHapiError, OSError, ValueError):
                pass

    def _crashed_roles(self) -> list[str]:
        required = {"hub"}
        if self._config.workspace_roots:
            required.add("runner")
        crashed: list[str] = []
        for role in sorted(required):
            owned = self._processes.get(role)
            if owned is None or not self._same_process(owned):
                crashed.append(role)
        return crashed

    def _all_required_alive(self) -> bool:
        return not self._crashed_roles()

    def _same_process(self, owned: _OwnedProcess) -> bool:
        if owned.pid <= 0:
            return False
        if owned.process is not None and owned.process.poll() is not None:
            return False
        if psutil is None:
            return owned.process is not None and owned.process.poll() is None
        try:
            process = psutil.Process(owned.pid)
            if not process.is_running():
                return False
            if abs(process.create_time() - owned.create_time) > 0.25:
                return False
            executable = self._executable
            if executable is None or not owned.argv:
                return False
            expected = _normalized_path(executable)
            try:
                process_executable = _normalized_path(Path(process.exe()))
                actual_argv = tuple(process.cmdline())
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                return False
            if process_executable != expected and os.name == "nt":
                return False
            if actual_argv == owned.argv:
                return True
            if os.name == "nt":
                return bool(
                    len(actual_argv) == len(owned.argv)
                    and actual_argv
                    and _normalized_path(Path(actual_argv[0])) == expected
                    and actual_argv[1:] == owned.argv[1:]
                )
            for index, candidate in enumerate(actual_argv[:3]):
                if (
                    _normalized_path(Path(candidate)) == expected
                    and actual_argv[index:] == owned.argv
                ):
                    return True
            return False
        except (psutil.Error, OSError, ValueError):
            return False

    def _terminate_processes_locked(self, *, keep_port: bool = False) -> bool:
        survivors: dict[str, _OwnedProcess] = {}
        for role in _PROCESS_ROLES:
            owned = self._processes.get(role)
            if owned is not None and not self._terminate_owned_tree(owned):
                survivors[role] = owned
        self._processes = survivors
        if survivors:
            roles = "、".join(sorted(survivors))
            self._hub_ready = False
            self._runner_ready = False
            self._state = "shutdown_failed"
            self._last_error = (
                f"HAPI {roles} 进程树无法确认已终止；"
                "已保留 ownership 记录，未启动替代进程"
            )
            if self._lifecycle_lock_file is not None:
                self._write_ownership_marker()
            return False
        if self._lifecycle_lock_file is not None:
            self._ownership_path.unlink(missing_ok=True)
        if not keep_port:
            self._actual_port = 0
        return True

    def _terminate_owned_tree(self, owned: _OwnedProcess) -> bool:
        if not self._same_process(owned):
            if owned.job is not None:
                owned.job.close()
                owned.job = None
            return not self._process_still_matches_creation(owned)
        if owned.job is not None:
            owned.job.close()
            owned.job = None
        if psutil is not None:
            try:
                parent = psutil.Process(owned.pid)
                if abs(parent.create_time() - owned.create_time) > 0.25:
                    return True
                children = parent.children(recursive=True)
                targets = [*reversed(children), parent]
                for process in targets:
                    try:
                        process.terminate()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                _, alive = psutil.wait_procs(targets, timeout=3.0)
                for process in alive:
                    try:
                        process.kill()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                _, alive = psutil.wait_procs(alive, timeout=2.0)
                if alive:
                    return False
            except (psutil.Error, OSError, ValueError):
                if self._same_process(owned):
                    return False
        elif owned.process is not None:  # pragma: no cover
            try:
                owned.process.terminate()
                owned.process.wait(timeout=3.0)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    owned.process.kill()
                    owned.process.wait(timeout=2.0)
                except (OSError, subprocess.TimeoutExpired):
                    if owned.process.poll() is None:
                        return False
        if owned.pump is not None and owned.pump is not threading.current_thread():
            owned.pump.join(timeout=1.0)
        elif owned.process is not None and owned.process.stdout is not None:
            try:
                owned.process.stdout.close()
            except OSError:
                pass
        return not self._process_still_matches_creation(owned)

    @staticmethod
    def _process_still_matches_creation(owned: _OwnedProcess) -> bool:
        if owned.process is not None and owned.process.poll() is not None:
            return False
        if psutil is None:
            return bool(
                owned.process is not None and owned.process.poll() is None
            )
        try:
            process = psutil.Process(owned.pid)
            return bool(
                process.is_running()
                and abs(process.create_time() - owned.create_time) <= 0.25
            )
        except (psutil.NoSuchProcess, ProcessLookupError):
            return False
        except (psutil.AccessDenied, OSError, ValueError):
            return True

    def _write_ownership_marker(self) -> None:
        payload = {
            "schema_version": _OWNERSHIP_SCHEMA_VERSION,
            "version": RUNTIME_VERSION,
            "platform": self._platform_key,
            "runtime_dir": str(self._runtime_dir),
            "actual_port": self._actual_port,
            "preferred_port": self._config.preferred_port,
            "workspace_roots": list(self._config.workspace_roots),
            "config_fingerprint": self._config_fingerprint(),
            "processes": [
                {
                    "role": owned.role,
                    "pid": owned.pid,
                    "create_time": owned.create_time,
                    "started_at": owned.started_at,
                    "argv": list(owned.argv),
                    "argv_sha256": hashlib.sha256(
                        "\0".join(owned.argv).encode("utf-8")
                    ).hexdigest(),
                }
                for owned in self._processes.values()
            ],
        }
        _atomic_json_write(self._ownership_path, payload)
        _chmod_private(self._ownership_path)

    def _owned_from_marker(
        self,
        value: Any,
        *,
        port: int,
        workspace_roots: tuple[str, ...],
    ) -> _OwnedProcess | None:
        if not isinstance(value, Mapping):
            return None
        role = value.get("role")
        pid = value.get("pid")
        create_time = value.get("create_time")
        started_at = value.get("started_at")
        argv_value = value.get("argv")
        argv_sha256 = value.get("argv_sha256")
        if (
            role not in {"hub", "runner"}
            or isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
            or isinstance(create_time, bool)
            or not isinstance(create_time, (int, float))
            or create_time <= 0
            or isinstance(started_at, bool)
            or not isinstance(started_at, (int, float))
            or not isinstance(argv_value, list)
            or len(argv_value) > 72
            or not all(
                isinstance(item, str)
                and item
                and "\x00" not in item
                and len(item) <= 4096
                for item in argv_value
            )
        ):
            return None
        argv = tuple(argv_value)
        expected = self._expected_argv(
            role,
            port=port,
            workspace_roots=workspace_roots,
        )
        expected_hash = hashlib.sha256(
            "\0".join(expected).encode("utf-8")
        ).hexdigest()
        if (
            argv != expected
            or argv_sha256 != expected_hash
        ):
            return None
        return _OwnedProcess(
            role=role,
            pid=pid,
            create_time=float(create_time),
            started_at=float(started_at),
            argv=argv,
        )

    @staticmethod
    def _marker_process_context(
        marker: Mapping[str, Any],
    ) -> tuple[int | None, tuple[str, ...] | None]:
        port = marker.get("actual_port")
        roots_value = marker.get("workspace_roots")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1024 <= port <= 65_535
            or not isinstance(roots_value, list)
            or len(roots_value) > 32
        ):
            return None, None
        roots: list[str] = []
        for value in roots_value:
            if (
                not isinstance(value, str)
                or not value
                or value != value.strip()
                or "\x00" in value
                or len(value) > 4096
                or not Path(value).is_absolute()
            ):
                return None, None
            roots.append(value)
        return port, tuple(roots)

    def _terminate_marker_processes_if_owned(
        self,
        marker: Mapping[str, Any],
    ) -> bool:
        if (
            marker.get("schema_version") != _OWNERSHIP_SCHEMA_VERSION
            or marker.get("version") != RUNTIME_VERSION
            or marker.get("platform") != self._platform_key
            or marker.get("runtime_dir") != str(self._runtime_dir)
        ):
            return True
        port, workspace_roots = self._marker_process_context(marker)
        values = marker.get("processes")
        if port is None or workspace_roots is None or not isinstance(values, list):
            return True
        seen: set[str] = set()
        terminated = True
        for value in values:
            owned = self._owned_from_marker(
                value,
                port=port,
                workspace_roots=workspace_roots,
            )
            if (
                owned is not None
                and owned.role not in seen
            ):
                seen.add(owned.role)
                if self._same_process(owned):
                    terminated = self._terminate_owned_tree(owned) and terminated
                elif self._process_still_matches_creation(owned):
                    terminated = False
        return terminated

    def _process_exit_diagnostic(self, roles: Sequence[str]) -> str:
        details: list[str] = []
        for role in roles:
            owned = self._processes.get(role)
            code: Any = None
            if owned is not None and owned.process is not None:
                code = owned.process.poll()
            details.append(
                f"{role} 已退出"
                + (f"（exit {code}）" if code is not None else "")
            )
        logs = "、".join(
            str(self._logs_dir / f"{role}.log")
            for role in roles
        )
        return f"HAPI {'、'.join(details)}；诊断日志：{logs}"

    def _config_fingerprint(self) -> str:
        payload = {
            "version": RUNTIME_VERSION,
            "platform": self._platform_key,
            "preferred_port": self._config.preferred_port,
            "workspace_roots": list(self._config.workspace_roots),
        }
        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    def _monitor_alive(self) -> bool:
        return bool(
            self._monitor_thread is not None
            and self._monitor_thread.is_alive()
        )

    @property
    def _ownership_path(self) -> Path:
        return self._data_root / "ownership.json"

    @property
    def _logs_dir(self) -> Path:
        return self._data_root / "logs"

    def _log(self, level: str, message: str, *args: Any) -> None:
        method = getattr(self._logger, level, None)
        if callable(method):
            try:
                method(message, *args)
            except Exception:
                pass


def detect_platform_key() -> str:
    """Return the release asset key for the current OS and architecture."""

    machine = platform.machine().strip().lower()
    if machine in {"amd64", "x86_64", "x64"}:
        architecture = "x64"
    elif machine in {"arm64", "aarch64"}:
        architecture = "arm64"
    else:
        architecture = machine or "unknown"
    if sys.platform == "win32":
        system = "win32"
    elif sys.platform == "darwin":
        system = "darwin"
    elif sys.platform.startswith("linux"):
        system = "linux"
    else:
        system = sys.platform.replace("/", "-")
    suffix = "-baseline" if system == "linux" and architecture == "x64" else ""
    return f"{system}-{architecture}{suffix}"


def _validate_workspace_roots(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or len(values) > 32:
        raise ManagedHapiError(
            "HAPI runner 工作区根目录配置无效",
            code="invalid_workspace",
        )
    roots: list[str] = []
    seen: set[str] = set()
    for value in values:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or "\x00" in value
            or len(value) > 4096
        ):
            raise ManagedHapiError(
                "HAPI runner 工作区根目录无效",
                code="invalid_workspace",
            )
        path = Path(value)
        if not path.is_absolute():
            raise ManagedHapiError(
                "HAPI runner 工作区根目录必须是绝对路径",
                code="invalid_workspace",
            )
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ManagedHapiError(
                "HAPI runner 工作区根目录不存在或无法访问",
                code="invalid_workspace",
            ) from exc
        if not resolved.is_dir() or str(resolved) != value:
            raise ManagedHapiError(
                "HAPI runner 只接受已规范化的工作区根目录",
                code="invalid_workspace",
            )
        try:
            home = Path.home().resolve(strict=True)
        except (OSError, RuntimeError):
            home = Path.home().resolve()
        normalized_system = (
            str(resolved).replace("\\", "/").rstrip("/").casefold()
        )
        if (
            resolved == home
            or resolved in home.parents
            or resolved == Path(resolved.anchor)
            or normalized_system
            in {
                "/applications",
                "/bin",
                "/etc",
                "/library",
                "/private",
                "/sbin",
                "/system",
                "/usr",
                "/var",
                "c:/program files",
                "c:/program files (x86)",
                "c:/programdata",
                "c:/windows",
            }
        ):
            raise ManagedHapiError(
                "HAPI runner 拒绝文件系统根目录、用户主目录或系统目录",
                code="invalid_workspace",
            )
        normalized = str(resolved)
        if normalized not in seen:
            seen.add(normalized)
            roots.append(normalized)
    return tuple(roots)


def _choose_port(preferred: int) -> int:
    if _port_available(preferred):
        return preferred
    for offset in range(1, 128):
        candidate = preferred + offset
        if candidate > 65_535:
            candidate = 1024 + (candidate - 65_536)
        if _port_available(candidate):
            return candidate
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((_LOOPBACK_HOST, 0))
        port = int(sock.getsockname()[1])
    if not 1024 <= port <= 65_535:
        raise ManagedHapiError(
            "无法为 HAPI 找到安全的本机端口",
            code="port_unavailable",
        )
    return port


def _port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_EXCLUSIVEADDRUSE,
                    1,
                )
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            sock.bind((_LOOPBACK_HOST, port))
            return True
        except OSError:
            return False


def _read_json_response(response: http.client.HTTPResponse) -> dict[str, Any]:
    header = response.getheader("Content-Length")
    if header:
        try:
            if int(header) > _MAX_HTTP_BODY_BYTES:
                raise ValueError("response too large")
        except ValueError:
            if header.isdigit():
                raise
    body = response.read(_MAX_HTTP_BODY_BYTES + 1)
    if len(body) > _MAX_HTTP_BODY_BYTES:
        raise ValueError("response too large")
    if not body:
        return {}
    payload = json.loads(body.decode("utf-8"))
    return dict(payload) if isinstance(payload, Mapping) else {}


def _verify_file(
    path: Path,
    *,
    expected_size: int | None,
    expected_sha256: str,
) -> None:
    try:
        if not path.is_file() or path.is_symlink():
            raise OSError("not a regular file")
        if expected_size is not None and path.stat().st_size != expected_size:
            raise ManagedHapiError(
                f"HAPI runtime 资产大小校验失败：{path.name}",
                code="checksum_mismatch",
            )
        actual = _sha256_file(path)
    except ManagedHapiError:
        raise
    except OSError as exc:
        raise ManagedHapiError(
            f"HAPI runtime 资产无法读取：{path.name}",
            code="runtime_asset_missing",
        ) from exc
    if actual != expected_sha256:
        raise ManagedHapiError(
            f"HAPI runtime SHA256 校验失败：{path.name}",
            code="checksum_mismatch",
        )


def _archive_executable_sha256(
    archive_path: Path,
    bundle: RuntimeBundle,
) -> str:
    expected_name = bundle.executable.replace("\\", "/")
    try:
        if bundle.archive_format == "zip":
            with zipfile.ZipFile(archive_path) as archive:
                matches = [
                    info
                    for info in archive.infolist()
                    if info.filename.replace("\\", "/") == expected_name
                    and not info.is_dir()
                ]
                if len(matches) != 1:
                    raise ManagedHapiError(
                        "官方 HAPI 资产没有唯一的预期可执行文件",
                        code="runtime_extract_failed",
                    )
                with archive.open(matches[0]) as source:
                    return _sha256_stream(source)
        with tarfile.open(archive_path, mode="r:gz") as archive:
            matches = [
                member
                for member in archive.getmembers()
                if member.name.replace("\\", "/") == expected_name
                and member.isfile()
            ]
            if len(matches) != 1:
                raise ManagedHapiError(
                    "官方 HAPI 资产没有唯一的预期可执行文件",
                    code="runtime_extract_failed",
                )
            source = archive.extractfile(matches[0])
            if source is None:
                raise ManagedHapiError(
                    "官方 HAPI 可执行文件无法读取",
                    code="runtime_extract_failed",
                )
            with source:
                return _sha256_stream(source)
    except ManagedHapiError:
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise ManagedHapiError(
            "官方 HAPI 资产无法验证",
            code="runtime_extract_failed",
        ) from exc


def _sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return _sha256_stream(handle)


def _sha256_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _bounded_text(value: Any, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ManagedHapiError(
            "HAPI runtime manifest 字符串字段无效",
            code="runtime_manifest_invalid",
        )
    result = value.strip()
    if (
        not result
        or result != value
        or len(result) > maximum
        or any(ord(character) < 32 for character in result)
    ):
        raise ManagedHapiError(
            "HAPI runtime manifest 字符串字段无效",
            code="runtime_manifest_invalid",
        )
    return result


def _sha256_text(value: Any) -> str:
    result = _bounded_text(value, maximum=64).lower()
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise ManagedHapiError(
            "HAPI runtime manifest SHA256 字段无效",
            code="runtime_manifest_invalid",
        )
    return result


def _optional_sha256_text(value: Any) -> str:
    if value in {None, ""}:
        return ""
    return _sha256_text(value)


def _safe_filename(value: Any) -> str:
    result = _bounded_text(value, maximum=255)
    if Path(result).name != result or result in {".", ".."}:
        raise ManagedHapiError(
            "HAPI runtime manifest 文件名无效",
            code="runtime_manifest_invalid",
        )
    return result


def _safe_relative_path(value: Any) -> str:
    result = _bounded_text(value, maximum=1024).replace("\\", "/")
    path = Path(result)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ManagedHapiError(
            "HAPI runtime manifest 路径无效",
            code="runtime_manifest_invalid",
        )
    return path.as_posix()


def _validated_https_url(value: Any) -> str:
    result = _bounded_text(value, maximum=2048)
    if not result.startswith("https://github.com/tiann/hapi/"):
        raise ManagedHapiError(
            "HAPI runtime manifest 来源 URL 无效",
            code="runtime_manifest_invalid",
        )
    return result


def _contained_path(root: Path, relative: str, *, kind: str) -> Path:
    candidate = root.joinpath(*Path(relative).parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ManagedHapiError(
            f"{kind} 路径越界",
            code="runtime_path_invalid",
        ) from exc
    return candidate


def _assert_within(candidate: Path, root: Path) -> None:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ManagedHapiError(
            "HAPI runtime 文件路径越界",
            code="runtime_path_invalid",
        ) from exc


def _ensure_owned_directory(path: Path, root: Path) -> None:
    if _is_link_or_junction(path):
        raise ManagedHapiError(
            "HAPI runtime 子目录不安全",
            code="runtime_path_invalid",
        )
    try:
        path.mkdir(exist_ok=True)
    except OSError as exc:
        raise ManagedHapiError(
            "HAPI runtime 子目录无法创建",
            code="runtime_path_invalid",
        ) from exc
    if _is_link_or_junction(path) or not path.is_dir():
        raise ManagedHapiError(
            "HAPI runtime 子目录不安全",
            code="runtime_path_invalid",
        )
    _assert_within(path, root)
    _chmod_private_directory(path)


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if not callable(is_junction):
        return False
    try:
        return bool(is_junction())
    except OSError:
        return True


def _archive_member_path(value: str) -> Path | None:
    normalized = value.replace("\\", "/")
    if not normalized or normalized.endswith("/") and normalized.strip("/") == "":
        return None
    path = Path(normalized)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or (path.parts and ":" in path.parts[0])
    ):
        raise ManagedHapiError(
            "HAPI runtime 压缩包包含越界路径",
            code="runtime_extract_failed",
        )
    return path


def _process_create_time(pid: int) -> float:
    if psutil is None:  # pragma: no cover
        return time.time()
    try:
        return float(psutil.Process(pid).create_time())
    except (psutil.Error, OSError, ValueError) as exc:
        raise ManagedHapiError(
            "无法记录 HAPI 进程创建时间",
            code="runtime_start_failed",
        ) from exc


def _terminate_unregistered_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.terminate()
        process.wait(timeout=3.0)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=2.0)
        except (OSError, subprocess.TimeoutExpired):
            pass
    stream = process.stdout
    if stream is not None:
        try:
            stream.close()
        except OSError:
            pass


def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
    if os.name != "nt":  # pragma: no cover - Windows-only boundary
        return
    if psutil is None:  # pragma: no cover - host dependency contract
        raise ManagedHapiError(
            "Windows 无法安全恢复已隔离的 HAPI 进程",
            code="runtime_start_failed",
        )
    try:  # pragma: no cover - exercised on the Windows delivery host
        import ctypes
        from ctypes import wintypes

        thread_id = 0
        deadline = time.monotonic() + 1.0
        while not thread_id and time.monotonic() < deadline:
            threads = psutil.Process(process.pid).threads()
            if threads:
                thread_id = int(threads[0].id)
                break
            time.sleep(0.01)
        if not thread_id:
            raise OSError("suspended process thread unavailable")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenThread.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.OpenThread.restype = wintypes.HANDLE
        kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel32.ResumeThread.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        thread_handle = kernel32.OpenThread(0x0002, False, thread_id)
        if not thread_handle:
            raise OSError("suspended process thread cannot be opened")
        try:
            previous_count = int(kernel32.ResumeThread(thread_handle))
            if previous_count == 0xFFFFFFFF:
                raise OSError("suspended process thread cannot be resumed")
        finally:
            kernel32.CloseHandle(thread_handle)
    except (AttributeError, OSError, TypeError, ValueError, psutil.Error) as exc:
        raise ManagedHapiError(
            "Windows 无法安全恢复已隔离的 HAPI 进程",
            code="runtime_start_failed",
        ) from exc


def _try_lock_file(handle: BinaryIO) -> bool:
    try:
        if os.name == "nt":  # pragma: no cover - Windows delivery boundary
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (BlockingIOError, OSError):
        return False


def _unlock_file(handle: BinaryIO) -> None:
    try:
        if os.name == "nt":  # pragma: no cover - Windows delivery boundary
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


def _normalized_path(path: Path) -> str:
    try:
        value = str(path.resolve())
    except OSError:
        value = str(path.absolute())
    return os.path.normcase(value)


def _atomic_json_write(path: Path, value: Mapping[str, Any]) -> None:
    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    _atomic_text_write(path, text, encoding="utf-8")


def _atomic_text_write(path: Path, value: str, *, encoding: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        temporary.write_text(value, encoding=encoding)
        _chmod_private(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _chmod_private(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _chmod_private_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _backup_path(path: Path, index: int) -> Path:
    return path.with_name(f"{path.name}.{index}")
