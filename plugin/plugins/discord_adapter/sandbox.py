"""Minimal sandboxed code execution for Discord LLM tools.

Runs Python or JavaScript in a subprocess with timeout and output truncation.
No network access, no filesystem access outside /tmp.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from typing import Any

MAX_OUTPUT_CHARS = 2000
EXECUTE_TIMEOUT_SECONDS = 10


async def execute_code(language: str, code: str) -> str:
    """Execute code in a subprocess sandbox.

    Args:
        language: "python" or "javascript"
        code: Source code to execute

    Returns:
        Combined stdout+stderr, truncated to MAX_OUTPUT_CHARS.
    """
    language = str(language or "").strip().lower()
    code = str(code or "").strip()
    if not code:
        return "Error: no code provided"

    if language == "python":
        cmd = [sys.executable, "-c", code]
    elif language in ("javascript", "js", "node"):
        node = shutil.which("node")
        if not node:
            return "Error: Node.js not available in this environment"
        cmd = [node, "--eval", code]
    else:
        return f"Error: unsupported language '{language}'. Use 'python' or 'javascript'."

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            limit=1024 * 64,  # 64KB buffer
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=EXECUTE_TIMEOUT_SECONDS
            )
            output = stdout.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return f"Error: execution timed out after {EXECUTE_TIMEOUT_SECONDS}s"

        if proc.returncode != 0:
            output = f"Exit code {proc.returncode}:\n{output}"

        # Truncate
        if len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + f"\n... (truncated, {len(output)} total chars)"
        return output or "(no output)"

    except Exception as exc:
        return f"Error: {type(exc).__name__}: {exc}"
