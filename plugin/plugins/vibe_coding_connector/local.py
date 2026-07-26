"""Local CLI backend for vibe_coding_connector.

Runs claude / codex / opencode directly on this machine via asyncio
subprocesses. No shell joining, no dangerous flags, workspace is confined to
panel-configured canonical roots, output is bounded and redacted upstream.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import Any, Mapping, Sequence

from .security import (
    SUPPORTED_PROVIDERS,
    PolicyError,
    canonical_workspace,
)

#: Candidate executable names probed on PATH per provider.
_PROVIDER_BINARIES: dict[str, tuple[str, ...]] = {
    "claude": ("claude",),
    "codex": ("codex",),
    "opencode": ("opencode",),
}

_MAX_PROMPT_CHARS = 8000


def detect_local_providers(overrides: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    """Probe PATH (plus panel overrides) for each supported provider CLI."""

    result: dict[str, dict[str, Any]] = {}
    for provider in sorted(SUPPORTED_PROVIDERS):
        override = overrides.get(provider) if overrides else None
        path: str | None = None
        if isinstance(override, str) and override:
            candidate = Path(override)
            path = str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else None
        if path is None:
            for binary in _PROVIDER_BINARIES.get(provider, (provider,)):
                found = shutil.which(binary)
                if found:
                    path = found
                    break
        result[provider] = {
            "available": path is not None,
            "path": path or "",
        }
    return result


def build_local_command(
    *,
    provider: str,
    executable: str,
    prompt: str,
) -> list[str]:
    """Build an argv list. Never joins a shell string, never adds skip flags."""

    if provider not in SUPPORTED_PROVIDERS:
        raise PolicyError("不支持的提供商", code="provider_not_allowed")
    if not isinstance(prompt, str) or not prompt.strip():
        raise PolicyError("指令不能为空", code="invalid_instruction")
    prompt_clean = prompt.strip()[:_MAX_PROMPT_CHARS]
    if not executable or not isinstance(executable, str):
        raise PolicyError("CLI 可执行文件不可用", code="cli_unavailable")

    if provider == "claude":
        return [executable, "-p", prompt_clean]
    if provider == "codex":
        return [executable, "exec", "--skip-git-repo-check", prompt_clean]
    # opencode
    return [executable, "run", prompt_clean]


async def _run_subprocess_bounded(
    *argv: str,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    limit: int = 65_536,
) -> tuple[int, str, str]:
    """Spawn argv without a shell; kill on timeout via caller; bound output."""

    process = await asyncio.create_subprocess_exec(
        *argv,
        cwd=cwd,
        env=dict(env) if env else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    out = stdout[:limit].decode("utf-8", errors="replace")
    err = stderr[:limit].decode("utf-8", errors="replace")
    return process.returncode or 0, out, err


async def run_local_prompt(
    *,
    provider: str,
    prompt: str,
    workspace: str,
    allowed_roots: Sequence[str],
    overrides: Mapping[str, str],
    timeout_seconds: float,
    max_output_chars: int,
) -> dict[str, Any]:
    """Validate policy, build argv, execute, and return a bounded result."""

    if provider not in SUPPORTED_PROVIDERS:
        raise PolicyError("不支持的提供商", code="provider_not_allowed")
    safe_workspace = canonical_workspace(workspace, allowed_roots)

    detected = detect_local_providers(overrides)
    info = detected.get(provider) or {}
    if not info.get("available"):
        raise PolicyError(f"未检测到 {provider} CLI；请在面板高级设置中配置路径", code="cli_unavailable")

    argv = build_local_command(provider=provider, executable=str(info["path"]), prompt=prompt)

    env = dict(os.environ)
    env.setdefault("CI", "true")
    env.setdefault("NO_COLOR", "1")

    try:
        exit_code, stdout, stderr = await asyncio.wait_for(
            _run_subprocess_bounded(*argv, cwd=safe_workspace, env=env),
            timeout=max(1.0, float(timeout_seconds)) * 10,
        )
    except TimeoutError as exc:
        raise PolicyError("本地 CLI 执行超时", code="cli_timeout") from exc

    output = stdout.strip()
    if not output and stderr.strip():
        output = stderr.strip()
    output = output[:max_output_chars]

    return {
        "provider": provider,
        "workspace": safe_workspace,
        "command": [Path(argv[0]).name, *argv[1:-1], "<prompt>"],
        "exit_code": exit_code,
        "output": output,
        "truncated": len(stdout) + len(stderr) > max_output_chars,
        "ok": exit_code == 0,
    }
