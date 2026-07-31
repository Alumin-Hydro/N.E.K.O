"""Process-supervision tests for the pinned managed HAPI runtime."""

from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import psutil
import pytest

import plugin.plugins.vibe_coding_connector.managed_runtime as managed_runtime_module
from plugin.plugins.vibe_coding_connector.managed_runtime import (
    ManagedHapiConfig,
    ManagedHapiError,
    ManagedHapiRuntime,
)


pytestmark = pytest.mark.plugin_unit

PLUGIN_DIR = Path(__file__).resolve().parents[3] / "plugins" / "vibe_coding_connector"


def _direct_python_executable() -> Path:
    """Return the base interpreter, never a Windows venv redirector."""

    candidate = getattr(sys, "_base_executable", sys.executable)
    if not isinstance(candidate, str) or not candidate:
        raise AssertionError("Python base executable is unavailable")
    executable = Path(candidate).resolve()
    if not executable.is_absolute() or not executable.is_file():
        raise AssertionError("Python base executable is not an absolute file")
    return executable


_FAKE_HAPI = r"""#!/usr/bin/env python3
import http.server
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

args = sys.argv[1:]
role = args[0] if args else ""
if role not in {"hub", "runner"}:
    raise SystemExit(2)
argv_log = Path(os.environ["FAKE_ARGV_LOG_DIR"]) / f"{role}.jsonl"
with argv_log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "sys_executable": sys.executable,
        "base_executable": getattr(sys, "_base_executable", ""),
        "args": args,
        "env": {
            key: os.environ.get(key)
            for key in (
                "HAPI_HOME",
                "HAPI_API_URL",
                "HAPI_PUBLIC_URL",
                "HAPI_DISABLE_VERSION_HANDOFF",
                "CLI_API_TOKEN",
                "HAPI_LISTEN_HOST",
                "HAPI_LISTEN_PORT",
            )
        },
    }) + "\n")
print(json.dumps({
    "event": "fake-started",
    "role": role,
    "pid": os.getpid(),
    "ppid": os.getppid(),
    "sys_executable": sys.executable,
    "base_executable": getattr(sys, "_base_executable", ""),
}), flush=True)

stop = threading.Event()
def on_stop(*_):
    stop.set()
signal.signal(signal.SIGTERM, on_stop)
signal.signal(signal.SIGINT, on_stop)

ready_file = Path(os.environ["FAKE_RUNNER_READY"])
health_failures_file = Path(os.environ["FAKE_HEALTH_FAILURES"])
if role == "runner":
    roots = [
        args[index + 1]
        for index, value in enumerate(args[:-1])
        if value == "--workspace-root"
    ]
    child_executable = getattr(sys, "_base_executable", "") or sys.executable
    child = subprocess.Popen(
        [child_executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=(os.name != "nt"),
    )
    with Path(os.environ["FAKE_CHILD_PIDS"]).open("a", encoding="ascii") as handle:
        handle.write(str(child.pid) + "\n")
    ready_file.write_text(json.dumps({
        "pid": os.getpid(),
        "roots": roots,
    }), encoding="utf-8")
    while not stop.wait(0.05):
        pass
    try:
        state = json.loads(ready_file.read_text(encoding="utf-8"))
        if state.get("pid") == os.getpid():
            ready_file.unlink()
    except (OSError, ValueError):
        pass
    raise SystemExit(0)

if role != "hub":
    raise SystemExit(2)
port = int(args[args.index("--port") + 1])
counter_path = Path(os.environ["FAKE_CRASH_COUNTER"])
try:
    count = int(counter_path.read_text(encoding="ascii")) + 1
except (OSError, ValueError):
    count = 1
counter_path.write_text(str(count), encoding="ascii")

class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == "/health":
            try:
                failures = int(
                    health_failures_file.read_text(encoding="ascii")
                )
            except (OSError, ValueError):
                failures = 0
            if failures > 0:
                health_failures_file.write_text(
                    str(failures - 1),
                    encoding="ascii",
                )
                self._send(503, {"status": "unhealthy"})
                return
            self._send(200, {"status": "ok", "protocolVersion": 1})
        elif self.path == "/api/machines":
            try:
                state = json.loads(ready_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                state = {}
            machines = [{
                "id": "fake-machine",
                "active": True,
                "metadata": {
                    "happyCliVersion": "0.25.1",
                    "happyHomeDir": os.environ["HAPI_HOME"],
                    "workspaceRoots": state.get("roots", []),
                },
                "runnerState": {
                    "status": "running",
                    "pid": state.get("pid"),
                },
            }] if state else []
            self._send(200, {"machines": machines})
        else:
            self._send(404, {"error": "not found"})
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        if self.path == "/api/auth":
            self._send(200, {"token": "fake-bearer"})
        else:
            self._send(404, {"error": "not found"})
    def log_message(self, *_):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
server.timeout = 0.05
crash_until = int(os.environ.get("FAKE_CRASH_UNTIL", "0"))
if count <= crash_until:
    def crash():
        time.sleep(float(os.environ.get("FAKE_CRASH_AFTER", "0.35")))
        os._exit(42)
    threading.Thread(target=crash, daemon=True).start()
while not stop.is_set():
    server.handle_request()
server.server_close()
"""


class _WindowsPythonFakeHapiRuntime(ManagedHapiRuntime):
    """Adapt only the fake script to an explicit interpreter on Windows.

    CreateProcess cannot execute a shebang-only file. Keeping Python as the
    tracked executable lets the production spawn, Job Object, identity, and
    ownership-marker paths run unchanged.
    """

    _fake_hapi_script: Path | None = None

    def _prepare_locked(self) -> Path:
        fake_hapi_script = super()._prepare_locked()
        self._fake_hapi_script = fake_hapi_script
        self._executable = _direct_python_executable()
        return self._executable

    def _expected_argv(
        self,
        role: str,
        *,
        port: int,
        workspace_roots: tuple[str, ...],
    ) -> tuple[str, ...]:
        fake_hapi_script = self._fake_hapi_script
        if fake_hapi_script is None:
            raise AssertionError("fake HAPI must be prepared before argv construction")
        base = super()._expected_argv(
            role,
            port=port,
            workspace_roots=workspace_roots,
        )
        return (base[0], str(fake_hapi_script), *base[1:])

    def _probe_hapi(
        self,
        *,
        port: int,
        require_runner: bool,
    ) -> tuple[bool, bool, str]:
        hub_ready, runner_ready, detail = super()._probe_hapi(
            port=port,
            require_runner=require_runner,
        )
        if hub_ready and (runner_ready or not require_runner):
            return hub_ready, runner_ready, detail
        try:
            diagnostics = self._fake_diagnostics()
        except Exception as exc:  # pragma: no cover - diagnostic safety net
            diagnostics = f"unavailable:{type(exc).__name__}"
        return (
            hub_ready,
            runner_ready,
            f"{detail}; fake diagnostics: {diagnostics}",
        )

    def _fake_diagnostics(self) -> str:
        details: list[str] = []
        for role in ("hub", "runner"):
            owned = self._processes.get(role)
            if owned is None:
                details.append(f"{role}=missing")
                continue
            exit_code = (
                owned.process.poll() if owned.process is not None else "untracked"
            )
            details.append(f"{role}=pid:{owned.pid},exit:{exit_code}")

        ready_value = self._config.extra_env.get("FAKE_RUNNER_READY")
        if ready_value:
            try:
                ready = Path(ready_value).read_text(encoding="utf-8")[-512:]
                details.append(f"ready={ready}")
            except FileNotFoundError:
                details.append("ready=missing")
            except (OSError, UnicodeError) as exc:
                details.append(f"ready={type(exc).__name__}")

        for role in ("hub", "runner"):
            try:
                tail = (self._logs_dir / f"{role}.log").read_text(
                    encoding="utf-8",
                    errors="replace",
                )[-512:]
            except OSError:
                continue
            tail = "\\n".join(
                line.strip() for line in tail.splitlines() if line.strip()
            )
            if tail:
                details.append(f"{role}_log={tail}")
        return " | ".join(details)[:2048]


class _Fixture:
    def __init__(self, root: Path, *, corrupt_checksum: bool = False) -> None:
        self.bundle_root = root / "bundle"
        self.data_root = root / "data"
        self.workspace = root / "workspace"
        self.argv_log_dir = root / "argv"
        self.runner_ready = root / "runner.ready"
        self.health_failures = root / "health-failures"
        self.crash_counter = root / "crash-counter"
        self.child_pids = root / "child-pids"
        self.workspace.mkdir(parents=True)
        self.argv_log_dir.mkdir()
        bundles = self.bundle_root / "bundles"
        bundles.mkdir(parents=True)
        executable_bytes = _FAKE_HAPI.encode("utf-8")
        archive_path = bundles / "fake-hapi.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("hapi")
            info.external_attr = 0o100755 << 16
            archive.writestr(info, executable_bytes)
        archive_sha = _sha256(archive_path)
        manifest = {
            "schema_version": 1,
            "version": "0.25.1",
            "release_url": "https://github.com/tiann/hapi/releases/tag/v0.25.1",
            "source_url": "https://github.com/tiann/hapi/tree/v0.25.1",
            "license": "AGPL-3.0-only",
            "bundles": {
                "fake-test": {
                    "asset_name": "fake-hapi.zip",
                    "archive_path": "bundles/fake-hapi.zip",
                    "download_url": (
                        "https://github.com/tiann/hapi/releases/download/"
                        "v0.25.1/fake-hapi.zip"
                    ),
                    "archive_format": "zip",
                    "executable": "hapi",
                    "size": archive_path.stat().st_size,
                    "sha256": "0" * 64 if corrupt_checksum else archive_sha,
                    "executable_sha256": hashlib.sha256(
                        executable_bytes
                    ).hexdigest(),
                }
            },
        }
        (self.bundle_root / "manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

    def runtime(
        self,
        *,
        preferred_port: int,
        max_restarts: int = 2,
        crash_until: int = 0,
        workspace_roots: tuple[str, ...] | None = None,
        runtime_class: type[ManagedHapiRuntime] | None = None,
    ) -> ManagedHapiRuntime:
        roots = workspace_roots
        if roots is None:
            roots = (str(self.workspace.resolve()),)
        if runtime_class is None:
            runtime_class = (
                _WindowsPythonFakeHapiRuntime
                if os.name == "nt"
                else ManagedHapiRuntime
            )
        return runtime_class(
            bundle_root=self.bundle_root,
            data_root=self.data_root,
            config=ManagedHapiConfig(
                preferred_port=preferred_port,
                workspace_roots=roots,
                readiness_timeout=4.0,
                max_restarts=max_restarts,
                restart_backoff=(0.05, 0.1, 0.15),
                monitor_interval=0.05,
                max_log_bytes=16_384,
                log_backups=1,
                extra_env={
                    "FAKE_ARGV_LOG_DIR": str(self.argv_log_dir),
                    "FAKE_RUNNER_READY": str(self.runner_ready),
                    "FAKE_HEALTH_FAILURES": str(self.health_failures),
                    "FAKE_CRASH_COUNTER": str(self.crash_counter),
                    "FAKE_CHILD_PIDS": str(self.child_pids),
                    "FAKE_CRASH_UNTIL": str(crash_until),
                    "FAKE_CRASH_AFTER": "0.7",
                },
            ),
            platform_key="fake-test",
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for(predicate, *, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("condition did not become true before timeout")


def _argv_records(directory: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for role in ("hub", "runner"):
        path = directory / f"{role}.jsonl"
        if not path.exists():
            continue
        role_records = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert all(record["args"][0] == role for record in role_records)
        records.extend(role_records)
    return records


def _kill_process_tree(pid: int, create_time: float) -> None:
    """Best-effort cleanup for fake processes deliberately orphaned by tests."""

    try:
        parent = psutil.Process(pid)
        if abs(parent.create_time() - create_time) > 0.25:
            return
        targets = [*reversed(parent.children(recursive=True)), parent]
    except (psutil.Error, OSError, ValueError):
        return
    for process in targets:
        try:
            process.kill()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    psutil.wait_procs(targets, timeout=3.0)


def test_direct_fake_interpreter_keeps_popen_process_identity() -> None:
    executable = _direct_python_executable()
    process = subprocess.Popen(
        [
            str(executable),
            "-I",
            "-c",
            "import os; print(os.getpid(), flush=True)",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        text=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise

    assert process.returncode == 0, stderr
    assert int(stdout.strip()) == process.pid


def test_runtime_starts_with_exact_argv_and_preferred_port(tmp_path: Path) -> None:
    fixture = _Fixture(tmp_path)
    port = _free_port()
    runtime = fixture.runtime(preferred_port=port)
    try:
        status = runtime.start()
        assert status["state"] == "ready"
        assert status["actual_port"] == port
        assert status["hub_ready"] is True
        assert status["runner_ready"] is True
        assert all(
            (fixture.argv_log_dir / f"{role}.jsonl").is_file()
            for role in ("hub", "runner")
        )
        records = _argv_records(fixture.argv_log_dir)
        assert [record["args"][0] for record in records] == ["hub", "runner"]
        hub, runner = records
        processes = status["processes"]
        assert hub["pid"] == processes["hub"]["pid"]
        assert runner["pid"] == processes["runner"]["pid"]
        ready = json.loads(fixture.runner_ready.read_text(encoding="utf-8"))
        assert ready["pid"] == processes["runner"]["pid"]
        assert hub["args"] == [
            "hub",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-relay",
        ]
        assert runner["args"] == [
            "runner",
            "start-sync",
            "--workspace-root",
            str(fixture.workspace.resolve()),
        ]
        for record in (hub, runner):
            environment = record["env"]
            assert environment["HAPI_HOME"] == str(
                fixture.data_root / "hapi-home"
            )
            assert environment["HAPI_API_URL"] == (
                f"http://127.0.0.1:{port}"
            )
            assert environment["HAPI_PUBLIC_URL"] == (
                f"http://127.0.0.1:{port}"
            )
            assert environment["HAPI_DISABLE_VERSION_HANDOFF"] == "1"
            assert environment["HAPI_LISTEN_HOST"] == "127.0.0.1"
            assert environment["HAPI_LISTEN_PORT"] == str(port)
            assert isinstance(environment["CLI_API_TOKEN"], str)
            assert len(environment["CLI_API_TOKEN"]) >= 32
    finally:
        runtime.stop()


def test_fake_readiness_diagnostics_expose_identity_without_token(
    tmp_path: Path,
) -> None:
    fixture = _Fixture(tmp_path)
    runtime = fixture.runtime(
        preferred_port=_free_port(),
        runtime_class=_WindowsPythonFakeHapiRuntime,
    )
    try:
        started = runtime.start()
        ready = json.loads(fixture.runner_ready.read_text(encoding="utf-8"))
        ready["pid"] = int(ready["pid"]) + 1
        fixture.runner_ready.write_text(json.dumps(ready), encoding="utf-8")
        _wait_for(
            lambda: all(
                (runtime._logs_dir / f"{role}.log").is_file()
                and (runtime._logs_dir / f"{role}.log").stat().st_size > 0
                for role in ("hub", "runner")
            )
        )

        hub_ready, runner_ready, detail = runtime._probe_hapi(
            port=int(started["actual_port"]),
            require_runner=True,
        )

        assert hub_ready is True
        assert runner_ready is False
        for role in ("hub", "runner"):
            pid = started["processes"][role]["pid"]
            assert f"{role}=pid:{pid},exit:None" in detail
            assert f"{role}_log=" in detail
        assert "fake-started" in detail
        assert f'"pid": {ready["pid"]}' in detail
        token = runtime.access_token
        assert token
        assert token not in detail
    finally:
        runtime.stop()


def test_port_conflict_falls_back_and_never_kills_occupant(tmp_path: Path) -> None:
    fixture = _Fixture(tmp_path)
    occupant = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupant.bind(("127.0.0.1", 0))
    occupant.listen()
    preferred = int(occupant.getsockname()[1])
    runtime = fixture.runtime(preferred_port=preferred)
    try:
        status = runtime.start()
        assert status["actual_port"] != preferred
        assert occupant.fileno() >= 0
        with socket.create_connection(("127.0.0.1", preferred), timeout=0.5):
            pass
        runtime_pids = {
            value["pid"]
            for value in status["processes"].values()
        }
        child_pids = {
            int(value)
            for value in fixture.child_pids.read_text(
                encoding="ascii"
            ).splitlines()
        }
        stopped = runtime.stop()
        assert stopped["state"] == "stopped"
        _wait_for(
            lambda: all(
                not psutil.pid_exists(pid)
                for pid in runtime_pids | child_pids
            )
        )
        assert occupant.fileno() >= 0
    finally:
        runtime.stop()
        occupant.close()


def test_runtime_restarts_crashes_with_backoff_then_recovers(tmp_path: Path) -> None:
    fixture = _Fixture(tmp_path)
    runtime = fixture.runtime(
        preferred_port=_free_port(),
        max_restarts=3,
        crash_until=2,
    )
    try:
        runtime.start()
        _wait_for(
            lambda: runtime.status()["state"] == "ready"
            and runtime.status()["restart_count"] == 2,
        )
        status = runtime.status()
        assert status["hub_ready"] is True
        assert status["runner_ready"] is True
        assert int(fixture.crash_counter.read_text(encoding="ascii")) == 3
    finally:
        runtime.stop()


def test_live_hub_readiness_failure_triggers_one_restart_then_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _Fixture(tmp_path)
    runtime = fixture.runtime(
        preferred_port=_free_port(),
        max_restarts=2,
    )
    monkeypatch.setattr(
        managed_runtime_module,
        "_HEALTH_PROBE_INTERVAL_SECONDS",
        0.1,
    )
    try:
        started = runtime.start()
        original_hub_pid = int(started["processes"]["hub"]["pid"])
        fixture.health_failures.write_text("3", encoding="ascii")

        _wait_for(
            lambda: (
                runtime.status()["state"] == "ready"
                and runtime.status()["restart_count"] == 1
                and int(runtime.status()["processes"]["hub"]["pid"])
                != original_hub_pid
            ),
            timeout=6.0,
        )

        recovered = runtime.status()
        assert recovered["hub_ready"] is True
        assert recovered["runner_ready"] is True
        assert int(fixture.health_failures.read_text(encoding="ascii")) == 0
        assert int(fixture.crash_counter.read_text(encoding="ascii")) == 2
    finally:
        runtime.stop()


def test_runtime_stops_after_finite_restart_budget(tmp_path: Path) -> None:
    fixture = _Fixture(tmp_path)
    runtime = fixture.runtime(
        preferred_port=_free_port(),
        max_restarts=2,
        crash_until=3,
    )
    try:
        runtime.start()
        _wait_for(lambda: runtime.status()["state"] == "failed")
        status = runtime.status()
        assert status["restart_count"] == 2
        assert status["processes"] == {}
        assert "重启上限" in status["last_error"]
        stable_counter = int(
            fixture.crash_counter.read_text(encoding="ascii")
        )
        stable_argv = _argv_records(fixture.argv_log_dir)
        assert stable_counter == 3
        assert runtime.start()["state"] == "failed"
        assert runtime.start()["state"] == "failed"
        time.sleep(0.4)
        assert int(fixture.crash_counter.read_text(encoding="ascii")) == stable_counter
        assert _argv_records(fixture.argv_log_dir) == stable_argv

        reset_status = runtime.start(reset_budget=True)
        assert reset_status["state"] == "ready"
        assert reset_status["restart_count"] == 0
        assert int(fixture.crash_counter.read_text(encoding="ascii")) == 4
    finally:
        runtime.stop()


def test_partial_marker_cleanup_kills_surviving_hub_before_new_start(
    tmp_path: Path,
) -> None:
    fixture = _Fixture(tmp_path)
    port = _free_port()
    original = fixture.runtime(preferred_port=port)
    replacement = fixture.runtime(preferred_port=port)
    original_status: dict[str, object] | None = None
    abandoned: list[tuple[int, float]] = []
    try:
        original_status = original.start()
        old_processes = original_status["processes"]
        assert isinstance(old_processes, dict)
        old_hub = old_processes["hub"]
        old_runner = old_processes["runner"]
        old_hub_pid = int(old_hub["pid"])
        old_runner_pid = int(old_runner["pid"])
        abandoned = [
            (old_hub_pid, float(old_hub["created_at"])),
            (old_runner_pid, float(old_runner["created_at"])),
        ]
        old_child_pids = {
            int(value)
            for value in fixture.child_pids.read_text(
                encoding="ascii"
            ).splitlines()
        }

        original._stop_event.set()
        monitor = original._monitor_thread
        if monitor is not None:
            monitor.join(timeout=2.0)
        with original._lock:
            original._monitor_thread = None
            original._release_lifecycle_lease_locked()

        _kill_process_tree(old_runner_pid, float(old_runner["created_at"]))
        old_runner_handle = original._processes["runner"].process
        if old_runner_handle is not None:
            old_runner_handle.wait(timeout=2.0)
        assert not psutil.pid_exists(old_runner_pid)
        assert all(not psutil.pid_exists(pid) for pid in old_child_pids)
        assert psutil.pid_exists(old_hub_pid)

        replacement_status = replacement.start()
        assert replacement_status["state"] == "ready"
        new_pids = {
            int(value["pid"])
            for value in replacement_status["processes"].values()
        }
        assert old_hub_pid not in new_pids
        old_hub_handle = original._processes["hub"].process
        if old_hub_handle is not None:
            old_hub_handle.poll()
        _wait_for(lambda: not psutil.pid_exists(old_hub_pid))
        assert len(_argv_records(fixture.argv_log_dir)) == 4
    finally:
        replacement.stop()
        original.stop()
        for pid, created_at in abandoned:
            _kill_process_tree(pid, created_at)


def test_second_instance_lifecycle_lock_never_spawns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _Fixture(tmp_path)
    owner = fixture.runtime(preferred_port=_free_port())
    contender = fixture.runtime(preferred_port=owner._config.preferred_port)
    monkeypatch.setattr(
        managed_runtime_module,
        "_LIFECYCLE_LOCK_TIMEOUT_SECONDS",
        0.15,
    )
    try:
        owner_status = owner.start()
        records_before = _argv_records(fixture.argv_log_dir)
        with pytest.raises(ManagedHapiError) as caught:
            contender.start()
        assert caught.value.code == "runtime_lifecycle_busy"
        assert _argv_records(fixture.argv_log_dir) == records_before
        assert owner.status()["processes"] == owner_status["processes"]
        assert owner.status()["state"] == "ready"
        assert (fixture.data_root / "ownership.json").is_file()
    finally:
        contender.stop()
        owner.stop()


def test_runtime_rejects_broad_workspace_root(tmp_path: Path) -> None:
    fixture = _Fixture(tmp_path)
    with pytest.raises(ManagedHapiError) as caught:
        fixture.runtime(
            preferred_port=_free_port(),
            workspace_roots=(str(Path(Path.cwd().anchor)),),
        )
    assert caught.value.code == "invalid_workspace"


def test_runtime_rejects_checksum_mismatch_before_execution(tmp_path: Path) -> None:
    fixture = _Fixture(tmp_path, corrupt_checksum=True)
    runtime = fixture.runtime(preferred_port=_free_port())
    with pytest.raises(ManagedHapiError) as caught:
        runtime.start()
    assert caught.value.code == "checksum_mismatch"
    assert _argv_records(fixture.argv_log_dir) == []


def test_bundled_windows_runtime_uses_absolute_hapi_exe_and_exact_argv(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runtime = ManagedHapiRuntime(
        bundle_root=PLUGIN_DIR / "runtime",
        data_root=tmp_path / "data",
        config=ManagedHapiConfig(
            preferred_port=3006,
            workspace_roots=(str(workspace.resolve()),),
        ),
        platform_key="win32-x64",
    )

    executable = runtime.prepare()

    assert executable.is_absolute()
    assert executable.name == "hapi.exe"
    assert executable == (
        tmp_path
        / "data"
        / "versions"
        / "0.25.1"
        / "win32-x64"
        / "hapi.exe"
    ).resolve()
    assert runtime._expected_argv(
        "hub",
        port=3006,
        workspace_roots=runtime._config.workspace_roots,
    ) == (
        str(executable),
        "hub",
        "--host",
        "127.0.0.1",
        "--port",
        "3006",
        "--no-relay",
    )
    assert runtime._expected_argv(
        "runner",
        port=3006,
        workspace_roots=runtime._config.workspace_roots,
    ) == (
        str(executable),
        "runner",
        "start-sync",
        "--workspace-root",
        str(workspace.resolve()),
    )


def test_runtime_without_workspace_starts_hub_but_not_runner(tmp_path: Path) -> None:
    fixture = _Fixture(tmp_path)
    runtime = fixture.runtime(
        preferred_port=_free_port(),
        workspace_roots=(),
    )
    try:
        status = runtime.start()
        assert status["state"] == "degraded"
        assert status["hub_ready"] is True
        assert status["runner_ready"] is False
        records = _argv_records(fixture.argv_log_dir)
        assert [record["args"][0] for record in records] == ["hub"]
    finally:
        runtime.stop()


def test_log_pump_redacts_token_split_across_read_boundary(
    tmp_path: Path,
) -> None:
    secret = b"fresh-boundary-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    split = 19
    payload = (
        b"x" * (8192 - split)
        + secret[:split]
        + secret[split:]
        + b"\n"
    )
    log_path = tmp_path / "boundary.log"
    pump = managed_runtime_module._LogPump(
        stream=io.BytesIO(payload),
        path=log_path,
        maximum=32_768,
        backups=1,
        redactions=(secret,),
    )

    pump.run()

    logged = log_path.read_bytes()
    assert b"[REDACTED]" in logged
    assert secret not in logged
    assert secret[:split] not in logged
    assert secret[split:] not in logged


def test_native_hapi_logs_are_bounded_without_following_symlinks(
    tmp_path: Path,
) -> None:
    fixture = _Fixture(tmp_path)
    runtime = fixture.runtime(
        preferred_port=_free_port(),
        workspace_roots=(),
    )
    native_logs = fixture.data_root / "hapi-home" / "logs"
    native_logs.mkdir(parents=True)
    runtime._token = "s" * 32
    paths = [native_logs / f"native-{index}.log" for index in range(300)]
    for index, path in enumerate(paths):
        content = bytes([65 + (index % 26)]) * 128
        if index == len(paths) - 1:
            content = (
                b"N" * 20_000
                + runtime._token.encode()
                + b"T" * 20_000
            )
        path.write_bytes(content)
        os.utime(path, (index + 1, index + 1))
    outside = tmp_path / "outside.log"
    outside.write_bytes(b"outside" * 10_000)
    symlink = native_logs / "linked.log"
    try:
        symlink.symlink_to(outside)
    except OSError:
        symlink = None

    runtime._bound_native_logs()

    remaining = [path for path in paths if path.exists()]
    assert remaining == paths[-2:]
    assert all(path.stat().st_size <= 16_384 for path in remaining)
    assert all(
        runtime._token.encode() not in path.read_bytes()
        for path in remaining
    )
    assert outside.stat().st_size == len(b"outside") * 10_000
    if symlink is not None:
        assert symlink.is_symlink()


@pytest.mark.parametrize("tamper", ["argv", "hash"])
def test_tampered_marker_is_not_adopted_or_used_to_kill_unknown_process(
    tmp_path: Path,
    tamper: str,
) -> None:
    fixture = _Fixture(tmp_path)
    runtime = fixture.runtime(
        preferred_port=_free_port(),
        workspace_roots=(),
    )
    unknown = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        runtime.prepare()
        forged_port = runtime._config.preferred_port
        expected_argv = runtime._expected_argv(
            "hub",
            port=forged_port,
            workspace_roots=(),
        )
        marker_argv = (
            (*expected_argv, "--tampered")
            if tamper == "argv"
            else expected_argv
        )
        marker_hash = hashlib.sha256(
            "\0".join(marker_argv).encode("utf-8")
        ).hexdigest()
        if tamper == "hash":
            marker_hash = "0" * 64
        unknown_created_at = psutil.Process(unknown.pid).create_time()
        marker = {
            "schema_version": 2,
            "version": "0.25.1",
            "platform": "fake-test",
            "runtime_dir": str(runtime._runtime_dir),
            "actual_port": forged_port,
            "preferred_port": forged_port,
            "workspace_roots": [],
            "config_fingerprint": runtime._config_fingerprint(),
            "processes": [
                {
                    "role": "hub",
                    "pid": unknown.pid,
                    "create_time": unknown_created_at,
                    "started_at": time.time(),
                    "argv": list(marker_argv),
                    "argv_sha256": marker_hash,
                }
            ],
        }
        (fixture.data_root / "ownership.json").write_text(
            json.dumps(marker),
            encoding="utf-8",
        )

        status = runtime.start()

        assert status["state"] == "degraded"
        assert unknown.poll() is None
        assert status["processes"]["hub"]["pid"] != unknown.pid
        current_marker = json.loads(
            (fixture.data_root / "ownership.json").read_text(encoding="utf-8")
        )
        assert {
            int(process["pid"])
            for process in current_marker["processes"]
        } == {int(status["processes"]["hub"]["pid"])}
        runtime.stop()
        assert unknown.poll() is None
    finally:
        runtime.stop()
        if unknown.poll() is None:
            unknown.terminate()
            try:
                unknown.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                unknown.kill()
                unknown.wait(timeout=2.0)


def test_stop_failure_preserves_owned_processes_and_marker_until_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _Fixture(tmp_path)
    runtime = fixture.runtime(preferred_port=_free_port())
    original_terminate = runtime._terminate_owned_tree
    owned: list[tuple[int, float]] = []
    try:
        started = runtime.start()
        owned = [
            (int(value["pid"]), float(value["created_at"]))
            for value in started["processes"].values()
        ]
        marker_path = fixture.data_root / "ownership.json"
        assert marker_path.is_file()
        monkeypatch.setattr(
            runtime,
            "_terminate_owned_tree",
            lambda _owned: False,
        )

        failed = runtime.stop()

        assert failed["state"] == "shutdown_failed"
        assert failed["state"] != "stopped"
        assert failed["processes"] == started["processes"]
        assert failed["actual_port"] == started["actual_port"]
        assert "ownership" in failed["last_error"]
        assert marker_path.is_file()
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert {
            int(process["pid"])
            for process in marker["processes"]
        } == {pid for pid, _ in owned}
        assert all(psutil.pid_exists(pid) for pid, _ in owned)
    finally:
        monkeypatch.setattr(
            runtime,
            "_terminate_owned_tree",
            original_terminate,
        )
        cleaned = runtime.stop()
        assert cleaned["state"] == "stopped"
        for pid, created_at in owned:
            _kill_process_tree(pid, created_at)
