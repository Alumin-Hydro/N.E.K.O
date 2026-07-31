"""v0.2 local_cli backend tests for vibe_coding_connector."""

from __future__ import annotations

from pathlib import Path

import pytest

from plugin.plugins.vibe_coding_connector.security import (
    ConnectorSettings,
    PolicyError,
    migrate_legacy_settings,
)


def test_backend_mode_defaults_to_managed_hapi_and_accepts_canonical_modes() -> None:
    settings = ConnectorSettings.from_mapping({})
    assert settings.backend_mode == "managed_hapi"

    external = ConnectorSettings.from_mapping({"backend_mode": "hapi_external"})
    assert external.backend_mode == "hapi_external"

    local = ConnectorSettings.from_mapping({"backend_mode": "local_cli"})
    assert local.backend_mode == "local_cli"

    with pytest.raises(PolicyError):
        ConnectorSettings.from_mapping({"backend_mode": "yolo"})


def test_backend_mode_migrates_legacy_settings_without_mutating_input() -> None:
    legacy = {"base_url": "http://127.0.0.1:4555"}
    migrated = migrate_legacy_settings(legacy)

    assert migrated["backend_mode"] == "hapi_external"
    assert "backend_mode" not in legacy
    assert ConnectorSettings.from_mapping(legacy).backend_mode == "hapi_external"
    assert (
        ConnectorSettings.from_mapping({"backend_mode": "hapi_remote"}).backend_mode
        == "hapi_external"
    )
    assert migrate_legacy_settings({}) == {}
    assert migrate_legacy_settings(None) == {}


def test_managed_runtime_settings_are_strict_and_bounded() -> None:
    defaults = ConnectorSettings.from_mapping({})
    assert defaults.preferred_port == 3006
    assert defaults.allow_runtime_download is False

    for port in (1024, 65535):
        settings = ConnectorSettings.from_mapping(
            {
                "backend_mode": "managed_hapi",
                "preferred_port": port,
                "allow_runtime_download": True,
            }
        )
        assert settings.preferred_port == port
        assert settings.allow_runtime_download is True

    for invalid_port in (1023, 65536, True, "3006"):
        with pytest.raises(PolicyError):
            ConnectorSettings.from_mapping(
                {
                    "backend_mode": "managed_hapi",
                    "preferred_port": invalid_port,
                }
            )

    with pytest.raises(PolicyError):
        ConnectorSettings.from_mapping(
            {
                "backend_mode": "managed_hapi",
                "allow_runtime_download": "true",
            }
        )

    with pytest.raises(PolicyError):
        ConnectorSettings.from_mapping(
            {
                "backend_mode": "managed_hapi",
                "unknown_runtime_field": True,
            }
        )


def test_workspace_roots_reject_filesystem_root_and_user_home() -> None:
    for dangerous in (Path(Path.cwd().anchor), Path.home().resolve()):
        with pytest.raises(PolicyError, match="(?i)(root|主目录|系统目录|工作区)"):
            ConnectorSettings.from_mapping(
                {"allowed_workspace_roots": [str(dangerous)]}
            )


def test_local_cli_command_overrides_are_validated() -> None:
    settings = ConnectorSettings.from_mapping(
        {"cli_command_overrides": {"codex": "/usr/local/bin/codex"}}
    )
    assert settings.cli_command_overrides["codex"] == "/usr/local/bin/codex"

    with pytest.raises(PolicyError):
        ConnectorSettings.from_mapping(
            {"cli_command_overrides": {"codex": "codex && echo pwned"}}
        )
    with pytest.raises(PolicyError):
        ConnectorSettings.from_mapping(
            {"cli_command_overrides": {"evil_tool": "/bin/true"}}
        )


def test_detect_local_providers_reports_availability(monkeypatch, tmp_path: Path) -> None:
    from plugin.plugins.vibe_coding_connector import local

    fake = tmp_path / "bin"
    fake.mkdir()
    for name in ("claude", "codex"):
        exe = fake / name
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake))

    detected = local.detect_local_providers({})
    assert detected["claude"]["available"] is True
    assert detected["codex"]["available"] is True
    assert detected["opencode"]["available"] is False


def test_build_local_command_never_shell_joins_and_has_no_dangerous_flags() -> None:
    from plugin.plugins.vibe_coding_connector import local

    argv = local.build_local_command(
        provider="codex",
        executable="/usr/local/bin/codex",
        prompt="read README; echo hi && summarize",
    )
    assert argv[0] == "/usr/local/bin/codex"
    joined = " ".join(argv).lower()
    for dangerous in ("--dangerously-skip-permissions", "--yolo", "--full-auto", "dangerously"):
        assert dangerous not in joined
    assert any("README" in part for part in argv)


@pytest.mark.asyncio
async def test_run_local_prompt_executes_bounded_and_denies_unlisted_workspace(
    monkeypatch, tmp_path: Path
) -> None:
    from plugin.plugins.vibe_coding_connector import local

    workspace = tmp_path / "proj"
    workspace.mkdir()

    async def fake_exec(*argv, cwd=None, env=None, limit=None):
        return 0, "hello output", ""

    monkeypatch.setattr(local, "_run_subprocess_bounded", fake_exec)
    monkeypatch.setattr(
        local,
        "detect_local_providers",
        lambda overrides: {
            "codex": {"available": True, "path": "/usr/local/bin/codex"},
        },
    )

    result = await local.run_local_prompt(
        provider="codex",
        prompt="say hi",
        workspace=str(workspace),
        allowed_roots=(str(workspace),),
        overrides={},
        timeout_seconds=5,
        max_output_chars=4000,
    )
    assert result["exit_code"] == 0
    assert "hello output" in result["output"]

    with pytest.raises(PolicyError):
        await local.run_local_prompt(
            provider="codex",
            prompt="say hi",
            workspace="/",
            allowed_roots=(str(workspace),),
            overrides={},
            timeout_seconds=5,
            max_output_chars=4000,
        )
