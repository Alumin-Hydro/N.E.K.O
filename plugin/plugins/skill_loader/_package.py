"""Safe Agent Skill package discovery and managed-copy helpers.

The module treats a skill directory as untrusted input. Discovery produces a
bounded, immutable byte snapshot; installation writes only that snapshot into
a fresh managed generation. No code is executed and no dependency is installed
while building a package.
"""

from __future__ import annotations

import ast
import copy
import datetime as dt
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
import re
import shutil
import stat
import sys
import unicodedata
import urllib.parse
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

try:
    from packaging.requirements import InvalidRequirement, Requirement
except ImportError:  # pragma: no cover - packaging is present in normal installs.
    InvalidRequirement = ValueError  # type: ignore[assignment,misc]
    Requirement = None  # type: ignore[assignment,misc]


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_MARKDOWN_INLINE_LINK_RE = re.compile(
    r"!?\[[^\]\r\n]*\]\(\s*(?:<([^>\r\n]+)>|([^\s)\r\n]+))"
)
_MARKDOWN_REFERENCE_RE = re.compile(
    r"(?m)^[ \t]{0,3}\[[^\]\r\n]+\]:[ \t]*(?:<([^>\r\n]+)>|(\S+))"
)
_MARKDOWN_CODE_PATH_RE = re.compile(
    r"`((?:references|templates|assets|scripts)/[^`\r\n]+)`",
    re.IGNORECASE,
)
_MARKDOWN_PLAIN_PATH_RE = re.compile(
    r"(?<![\w./-])((?:references|templates|assets|scripts)/"
    r"[A-Za-z0-9_@+.%{}-]+(?:/[A-Za-z0-9_@+.%{}-]+)*)"
)
_HEADING_RE = re.compile(r"(?m)^#[ \t]+(.+?)[ \t]*$")
_REQUIREMENTS_NAME_RE = re.compile(r"(?i)^requirements(?:[-_.][^/]*)?\.txt$")

_TEXT_EXTENSIONS = frozenset(
    {
        ".bash",
        ".cfg",
        ".conf",
        ".css",
        ".csv",
        ".graphql",
        ".htm",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".md",
        ".mjs",
        ".py",
        ".ps1",
        ".rst",
        ".scss",
        ".sh",
        ".sql",
        ".sty",
        ".svg",
        ".tex",
        ".toml",
        ".ts",
        ".tsx",
        ".tsv",
        ".txt",
        ".xml",
        ".xsd",
        ".yaml",
        ".yml",
        ".zsh",
    }
)
_TEXT_FILENAMES = frozenset(
    {
        "license",
        "notice",
        "readme",
        "requirements.txt",
        "skill.md",
    }
)
_UNSUPPORTED_SCRIPT_EXTENSIONS = frozenset(
    {
        ".bat",
        ".bash",
        ".cmd",
        ".cjs",
        ".exe",
        ".js",
        ".mjs",
        ".ps1",
        ".pyc",
        ".sh",
        ".zsh",
    }
)
_SENSITIVE_EXACT_NAMES = frozenset(
    {
        ".env",
        ".git",
        ".git-credentials",
        ".hg",
        ".npmrc",
        ".pypirc",
        ".ssh",
        ".svn",
        "__pycache__",
        "api_keys.json",
        "credentials.json",
        "id_dsa",
        "id_ed25519",
        "id_rsa",
        "node_modules",
        "secrets.json",
        "venv",
    }
)
_SENSITIVE_SUFFIXES = (
    ".key",
    ".p12",
    ".pfx",
    ".pem",
)
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "aux",
        "clock$",
        "com1",
        "com2",
        "com3",
        "com4",
        "com5",
        "com6",
        "com7",
        "com8",
        "com9",
        "con",
        "lpt1",
        "lpt2",
        "lpt3",
        "lpt4",
        "lpt5",
        "lpt6",
        "lpt7",
        "lpt8",
        "lpt9",
        "nul",
        "prn",
    }
)
_MAX_JSON_DEPTH = 24
_MAX_JSON_ITEMS = 2_048
_HARD_MAX_READ_BYTES = 8 * 1024 * 1024


class PackageError(ValueError):
    """A safe, structured error raised for invalid skill packages."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "invalid_skill_package",
        path: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.path = path

    def as_dict(self) -> dict[str, str]:
        """Return a JSON-compatible public error payload."""

        payload = {"code": self.code, "message": str(self)}
        if self.path is not None:
            payload["path"] = self.path
        return payload


@dataclass(frozen=True, slots=True)
class PackageLimits:
    """Resource limits applied while scanning and reading skill packages."""

    max_files: int = 256
    max_directories: int = 256
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    max_skill_md_bytes: int = 1024 * 1024
    max_frontmatter_bytes: int = 64 * 1024
    max_path_bytes: int = 512
    max_depth: int = 16
    max_markdown_links: int = 512
    max_dependency_scan_bytes: int = 512 * 1024
    max_read_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        values = {field: getattr(self, field) for field in self.__dataclass_fields__}
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in values.values()
        ):
            raise ValueError("package limits must be positive integers")
        if self.max_skill_md_bytes > self.max_file_bytes:
            raise ValueError("SKILL.md limit cannot exceed the per-file limit")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("per-file limit cannot exceed the total-size limit")
        if self.max_read_bytes > self.max_file_bytes:
            raise ValueError("read limit cannot exceed the per-file limit")
        if self.max_read_bytes > _HARD_MAX_READ_BYTES:
            raise ValueError("read limit exceeds the hard safety limit")


DEFAULT_LIMITS = PackageLimits()


@dataclass(frozen=True, slots=True)
class PackageFile:
    """An immutable file snapshot captured during package discovery."""

    path: str
    data: bytes
    kind: str
    readable: bool
    executable: bool
    sha256: str

    @property
    def size(self) -> int:
        """Return the snapshot size in bytes."""

        return len(self.data)


@dataclass(frozen=True, slots=True)
class SkillPackage:
    """A bounded package snapshot and its JSON-compatible manifest."""

    files: tuple[PackageFile, ...]
    directories: tuple[str, ...]
    manifest: dict[str, Any]

    @property
    def data_sha256(self) -> str:
        """Return the package content hash."""

        return str(self.manifest["data_sha256"])

    @property
    def manifest_sha256(self) -> str:
        """Return the manifest hash."""

        return str(self.manifest["manifest_sha256"])

    def manifest_copy(self) -> dict[str, Any]:
        """Return a defensive copy suitable for persistence."""

        return copy.deepcopy(self.manifest)


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects aliases and duplicate mapping keys."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.constructor.ConstructorError(
                None,
                None,
                "YAML aliases are not allowed",
                getattr(event, "start_mark", None),
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, yaml.MappingNode):
            return super().construct_mapping(node, deep=deep)
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=False)
            try:
                duplicate = key in seen
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "mapping keys must be scalar",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate key: {key!r}",
                    key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def normalize_relative_path(value: str | os.PathLike[str]) -> str:
    """Normalize a safe package-relative path to POSIX form.

    Absolute paths, traversal, backslashes, control characters, and components
    that are unsafe on common target platforms are rejected.
    """

    raw = os.fspath(value)
    if not isinstance(raw, str):
        raise PackageError("path must be text", code="invalid_path")
    if not raw or raw in {".", "./"}:
        raise PackageError("path must name a package entry", code="invalid_path")
    if "\x00" in raw or "\\" in raw:
        raise PackageError("path contains a forbidden character", code="invalid_path")
    if raw.startswith(("/", "//")) or _WINDOWS_DRIVE_RE.match(raw):
        raise PackageError("absolute paths are not allowed", code="absolute_path")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise PackageError("path contains control characters", code="invalid_path")

    parts: list[str] = []
    for part in raw.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise PackageError("parent traversal is not allowed", code="path_traversal")
        _validate_component(part)
        parts.append(part)
    if not parts:
        raise PackageError("path must name a package entry", code="invalid_path")
    return PurePosixPath(*parts).as_posix()


def scan_skill_package(
    source_root: str | os.PathLike[str],
    limits: PackageLimits = DEFAULT_LIMITS,
) -> SkillPackage:
    """Scan an untrusted skill directory into an immutable package snapshot."""

    root = Path(source_root).expanduser()
    try:
        root_lstat = root.lstat()
    except OSError as exc:
        raise PackageError(
            "skill source does not exist or cannot be inspected",
            code="source_unavailable",
        ) from exc
    if stat.S_ISLNK(root_lstat.st_mode) or _is_reparse_point(root_lstat):
        raise PackageError(
            "skill source cannot be a symbolic link", code="symlink_rejected"
        )
    if stat.S_ISREG(root_lstat.st_mode):
        if root.name != "SKILL.md":
            raise PackageError(
                "a file source must be named SKILL.md",
                code="missing_skill_md",
            )
        root = root.parent
        root_lstat = root.lstat()
        if stat.S_ISLNK(root_lstat.st_mode) or _is_reparse_point(root_lstat):
            raise PackageError(
                "skill source cannot be a symbolic link",
                code="symlink_rejected",
            )
    if not stat.S_ISDIR(root_lstat.st_mode):
        raise PackageError(
            "skill source must be a directory", code="invalid_source_type"
        )
    if root.is_symlink():
        raise PackageError(
            "skill source cannot be a symbolic link", code="symlink_rejected"
        )

    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise PackageError(
            "skill source cannot be resolved",
            code="source_unavailable",
        ) from exc

    def discover() -> tuple[tuple[PackageFile, ...], tuple[str, ...]]:
        directories: list[str] = []
        files: list[PackageFile] = []
        total_bytes = 0
        portable_names: dict[str, str] = {}

        def visit(directory: Path, relative_directory: str, depth: int) -> None:
            nonlocal total_bytes
            if depth > limits.max_depth:
                raise PackageError(
                    "package directory nesting exceeds the configured limit",
                    code="too_deep",
                    path=relative_directory or None,
                )
            try:
                directory_stat = os.stat(directory, follow_symlinks=False)
            except OSError as exc:
                raise PackageError(
                    "package directory cannot be inspected",
                    code="source_unavailable",
                    path=relative_directory or None,
                ) from exc
            if (
                stat.S_ISLNK(directory_stat.st_mode)
                or _is_reparse_point(directory_stat)
            ):
                raise PackageError(
                    "filesystem links are not allowed in skill packages",
                    code="symlink_rejected",
                    path=relative_directory or None,
                )
            if not stat.S_ISDIR(directory_stat.st_mode):
                raise PackageError(
                    "package entry changed type during discovery",
                    code="source_changed",
                    path=relative_directory or None,
                )
            _assert_resolves_within(directory, resolved_root)
            try:
                with os.scandir(directory) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name)
            except OSError as exc:
                raise PackageError(
                    "package directory cannot be read",
                    code="source_unavailable",
                    path=relative_directory or None,
                ) from exc
            for entry in entries:
                _validate_source_name(entry.name)
                relative = (
                    f"{relative_directory}/{entry.name}"
                    if relative_directory
                    else entry.name
                )
                normalized = normalize_relative_path(relative)
                encoded_path = normalized.encode("utf-8")
                if len(encoded_path) > limits.max_path_bytes:
                    raise PackageError(
                        "package path exceeds the configured limit",
                        code="path_too_long",
                        path=normalized,
                    )
                if len(PurePosixPath(normalized).parts) > limits.max_depth:
                    raise PackageError(
                        "package path nesting exceeds the configured limit",
                        code="too_deep",
                        path=normalized,
                    )
                _record_portable_name(normalized, portable_names)
                entry_path = Path(entry.path)
                try:
                    # DirEntry.stat() caches results and reports zero identity/link
                    # fields on Windows; security checks require a fresh path stat.
                    entry_stat = os.stat(entry_path, follow_symlinks=False)
                except FileNotFoundError as exc:
                    raise PackageError(
                        "package entry changed during discovery",
                        code="source_changed",
                        path=normalized,
                    ) from exc
                except OSError as exc:
                    raise PackageError(
                        "package entry cannot be inspected",
                        code="source_unavailable",
                        path=normalized,
                    ) from exc
                if stat.S_ISLNK(entry_stat.st_mode) or _is_reparse_point(entry_stat):
                    raise PackageError(
                        "filesystem links are not allowed in skill packages",
                        code="symlink_rejected",
                        path=normalized,
                    )
                if stat.S_ISDIR(entry_stat.st_mode):
                    directories.append(normalized)
                    if len(directories) > limits.max_directories:
                        raise PackageError(
                            "package contains too many directories",
                            code="too_many_directories",
                        )
                    visit(entry_path, normalized, depth + 1)
                    continue
                if not stat.S_ISREG(entry_stat.st_mode):
                    raise PackageError(
                        "only ordinary files and directories are allowed",
                        code="special_file_rejected",
                        path=normalized,
                    )
                if getattr(entry_stat, "st_nlink", 0) != 1:
                    raise PackageError(
                        "hard-linked files are not allowed",
                        code="hardlink_rejected",
                        path=normalized,
                    )
                if len(files) >= limits.max_files:
                    raise PackageError(
                        "package contains too many files",
                        code="too_many_files",
                    )
                per_file_limit = (
                    min(limits.max_file_bytes, limits.max_skill_md_bytes)
                    if normalized == "SKILL.md"
                    else limits.max_file_bytes
                )
                data = _read_source_file(
                    entry_path,
                    entry_stat,
                    resolved_root,
                    per_file_limit,
                    normalized,
                )
                total_bytes += len(data)
                if total_bytes > limits.max_total_bytes:
                    raise PackageError(
                        "package exceeds the configured total-size limit",
                        code="package_too_large",
                    )
                kind, readable, executable = _classify_file(
                    normalized,
                    data,
                    entry_stat.st_mode,
                )
                files.append(
                    PackageFile(
                        path=normalized,
                        data=data,
                        kind=kind,
                        readable=readable,
                        executable=executable,
                        sha256=_sha256(data),
                    )
                )

        visit(root, "", 0)
        return tuple(files), tuple(directories)

    files, directories = discover()
    verification_files, verification_directories = discover()
    _require_stable_source_snapshot(
        files,
        directories,
        verification_files,
        verification_directories,
    )
    return _build_package(files, directories, limits)


def build_inline_package(
    content: str | bytes,
    *,
    name: str | None = None,
    description: str | None = None,
    limits: PackageLimits = DEFAULT_LIMITS,
) -> SkillPackage:
    """Build a managed package containing a single inline SKILL.md file."""

    if isinstance(content, str):
        data = content.encode("utf-8")
    elif isinstance(content, bytes):
        data = bytes(content)
    else:
        raise PackageError(
            "inline content must be text or bytes", code="invalid_content"
        )
    if len(data) > limits.max_skill_md_bytes:
        raise PackageError(
            "SKILL.md exceeds the configured size limit",
            code="file_too_large",
            path="SKILL.md",
        )
    _decode_utf8(data, "SKILL.md")
    package_file = PackageFile(
        path="SKILL.md",
        data=data,
        kind="skill",
        readable=True,
        executable=False,
        sha256=_sha256(data),
    )
    return _build_package(
        (package_file,),
        (),
        limits,
        name_override=name,
        description_override=description,
    )


def install_package(
    package: SkillPackage,
    skill_root: str | os.PathLike[str],
    skill_id: str,
) -> tuple[Path, dict[str, Any]]:
    """Install a snapshot into a fresh managed generation.

    The caller owns retention of older generations. This function never
    replaces or mutates an existing generation.
    """

    if not isinstance(package, SkillPackage):
        raise PackageError(
            "package snapshot has an invalid type", code="invalid_snapshot"
        )
    if not isinstance(skill_id, str) or not _ID_RE.fullmatch(skill_id):
        raise PackageError("skill ID is invalid", code="invalid_skill_id")
    _verify_package_snapshot(package)

    managed_root = Path(skill_root)
    try:
        managed_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise PackageError(
            "managed skill root cannot be created",
            code="managed_root_unavailable",
        ) from exc
    _require_real_directory(managed_root, "managed skill root")

    skill_directory = managed_root / skill_id
    try:
        skill_directory.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise PackageError(
            "managed skill directory cannot be created",
            code="managed_root_unavailable",
        ) from exc
    _require_real_directory(skill_directory, "managed skill directory")

    nonce = uuid.uuid4().hex
    staging = skill_directory / f".staging-{nonce}"
    generation = skill_directory / f"gen-{package.data_sha256[:16]}-{nonce[:12]}"
    try:
        staging.mkdir(mode=0o700)
        for relative in sorted(package.directories, key=_directory_sort_key):
            destination = _managed_destination(staging, relative)
            destination.mkdir(mode=0o700, exist_ok=False)
        for item in package.files:
            destination = _managed_destination(staging, item.path)
            try:
                with destination.open("xb") as handle:
                    handle.write(item.data)
            except OSError as exc:
                raise PackageError(
                    "managed package file cannot be written",
                    code="managed_write_failed",
                    path=item.path,
                ) from exc
            try:
                destination.chmod(0o600)
            except OSError as exc:
                raise PackageError(
                    "managed package permissions cannot be secured",
                    code="managed_write_failed",
                    path=item.path,
                ) from exc
        staging.rename(generation)
    except Exception:
        if staging.exists() and not staging.is_symlink():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    return generation, package.manifest_copy()


def read_manifest_file(
    generation_root: str | os.PathLike[str],
    manifest: Mapping[str, Any],
    relative_path: str | os.PathLike[str],
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Read one manifest-listed file without following links outside the root."""

    normalized = normalize_relative_path(relative_path)
    _verify_manifest(manifest)
    configured_limit = DEFAULT_LIMITS.max_read_bytes if max_bytes is None else max_bytes
    if (
        not isinstance(configured_limit, int)
        or isinstance(configured_limit, bool)
        or configured_limit <= 0
        or configured_limit > _HARD_MAX_READ_BYTES
    ):
        raise PackageError("read limit is invalid", code="invalid_read_limit")
    metadata = _manifest_file_entry(manifest, normalized)
    declared_size = metadata.get("size")
    if (
        not isinstance(declared_size, int)
        or isinstance(declared_size, bool)
        or declared_size < 0
    ):
        raise PackageError("manifest file size is invalid", code="invalid_manifest")
    if declared_size > configured_limit:
        raise PackageError(
            "file exceeds the requested read limit",
            code="read_limit_exceeded",
            path=normalized,
        )

    root = Path(generation_root)
    _require_real_directory(root, "managed generation")
    target = _managed_destination(root, normalized)
    _require_no_symlink_components(root, target)
    try:
        target_stat = target.lstat()
    except OSError as exc:
        raise PackageError(
            "managed package file is missing",
            code="managed_file_missing",
            path=normalized,
        ) from exc
    if (
        not stat.S_ISREG(target_stat.st_mode)
        or stat.S_ISLNK(target_stat.st_mode)
        or _is_reparse_point(target_stat)
        or getattr(target_stat, "st_nlink", 0) != 1
    ):
        raise PackageError(
            "managed package entry is not an ordinary file",
            code="managed_file_invalid",
            path=normalized,
        )
    if target_stat.st_size != declared_size:
        raise PackageError(
            "managed package file size does not match its manifest",
            code="managed_file_changed",
            path=normalized,
        )
    data = _read_managed_file(target, configured_limit, normalized)
    declared_hash = metadata.get("sha256")
    if not isinstance(declared_hash, str) or _sha256(data) != declared_hash:
        raise PackageError(
            "managed package file hash does not match its manifest",
            code="managed_file_changed",
            path=normalized,
        )

    result = copy.deepcopy(metadata)
    result["content"] = None
    result["encoding"] = "binary"
    if bool(metadata.get("readable")):
        result["content"] = _decode_utf8(data, normalized)
        result["encoding"] = "utf-8"
    return result


def _build_package(
    files: tuple[PackageFile, ...],
    directories: tuple[str, ...],
    limits: PackageLimits,
    *,
    name_override: str | None = None,
    description_override: str | None = None,
) -> SkillPackage:
    files = tuple(sorted(files, key=lambda item: item.path))
    directories = tuple(sorted(directories))
    by_path = {item.path: item for item in files}
    skill_file = by_path.get("SKILL.md")
    if skill_file is None:
        raise PackageError(
            "skill package must contain a root-level SKILL.md",
            code="missing_skill_md",
        )
    if len(by_path) != len(files):
        raise PackageError(
            "package contains duplicate file paths", code="duplicate_path"
        )
    if len(set(directories)) != len(directories):
        raise PackageError(
            "package contains duplicate directory paths", code="duplicate_path"
        )
    if len(files) > limits.max_files or len(directories) > limits.max_directories:
        raise PackageError(
            "package snapshot exceeds entry limits", code="too_many_entries"
        )
    total_bytes = sum(item.size for item in files)
    if total_bytes > limits.max_total_bytes:
        raise PackageError(
            "package exceeds the total-size limit", code="package_too_large"
        )

    skill_text = _decode_utf8(skill_file.data, "SKILL.md")
    frontmatter, body = _parse_frontmatter(skill_text, limits)
    name = _display_text(name_override, 160) or _frontmatter_text(
        frontmatter, "name", 160
    )
    description = _display_text(description_override, 1_000) or _frontmatter_text(
        frontmatter,
        "description",
        1_000,
    )
    if not name:
        heading = _HEADING_RE.search(body)
        if heading:
            name = _display_text(heading.group(1), 160)
    if not name:
        name = "Unnamed Skill"

    manifest_files = [_manifest_metadata(item) for item in files]
    linked_paths = _discover_linked_paths(files, directories, limits)
    dependencies = _diagnose_dependencies(files, directories, limits)
    scripts = _script_capabilities(files, dependencies)
    counts = _kind_counts(files)
    data_sha256 = _data_hash(files, directories)
    dependency_summary = _dependency_summary(dependencies)
    capabilities = {
        "complete_directory": True,
        "read_skill_markdown": True,
        "read_linked_files": True,
        "preserves_empty_directories": True,
        "has_references": counts.get("reference", 0) > 0
        or _has_directory(directories, "references"),
        "has_templates": counts.get("template", 0) > 0
        or _has_directory(directories, "templates"),
        "has_assets": counts.get("asset", 0) > 0
        or _has_directory(directories, "assets"),
        "has_scripts": bool(scripts),
        "script_count": len(scripts),
        "supported_script_count": sum(bool(item["supported"]) for item in scripts),
        "unsupported_script_count": sum(
            not bool(item["supported"]) for item in scripts
        ),
        "script_execution_requires_authorization": True,
        "supported_interpreters": ["python"],
    }
    linked_copy = copy.deepcopy(linked_paths)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "format": "agent-skill-directory",
        "name": name,
        "description": description,
        "frontmatter": frontmatter,
        "skill": {
            "path": "SKILL.md",
            "size": skill_file.size,
            "sha256": skill_file.sha256,
            "body_sha256": _sha256(body.encode("utf-8")),
        },
        "files": manifest_files,
        "directories": list(directories),
        "linked_paths": linked_paths,
        "linked_files": linked_copy,
        "scripts": scripts,
        "capabilities": capabilities,
        "dependencies": dependencies,
        "dependency_summary": dependency_summary,
        "totals": {
            "files": len(files),
            "directories": len(directories),
            "bytes": total_bytes,
            "kinds": counts,
        },
        "data_sha256": data_sha256,
    }
    manifest["manifest_sha256"] = _manifest_hash(manifest)
    _json_bytes(manifest)
    return SkillPackage(
        files=tuple(sorted(files, key=lambda item: item.path)),
        directories=tuple(sorted(directories)),
        manifest=manifest,
    )


def _parse_frontmatter(
    skill_text: str,
    limits: PackageLimits,
) -> tuple[dict[str, Any], str]:
    text = skill_text.removeprefix("\ufeff")
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return {}, text
    closing_index: int | None = None
    frontmatter_size = 0
    for index in range(1, len(lines)):
        frontmatter_size += len(lines[index].encode("utf-8"))
        if frontmatter_size > limits.max_frontmatter_bytes:
            raise PackageError(
                "SKILL.md frontmatter exceeds the configured limit",
                code="frontmatter_too_large",
                path="SKILL.md",
            )
        if lines[index].rstrip("\r\n") == "---":
            closing_index = index
            break
    if closing_index is None:
        raise PackageError(
            "SKILL.md frontmatter is not terminated",
            code="invalid_frontmatter",
            path="SKILL.md",
        )
    yaml_text = "".join(lines[1:closing_index])
    try:
        loaded = yaml.load(yaml_text, Loader=_NoAliasSafeLoader)
        loaded = {} if loaded is None else loaded
        if not isinstance(loaded, Mapping):
            raise PackageError(
                "SKILL.md frontmatter must be a mapping",
                code="invalid_frontmatter",
                path="SKILL.md",
            )
        frontmatter = _json_value(loaded)
    except PackageError:
        raise
    except (RecursionError, yaml.YAMLError) as exc:
        raise PackageError(
            "SKILL.md frontmatter is invalid or uses unsupported YAML",
            code="invalid_frontmatter",
            path="SKILL.md",
        ) from exc
    if not isinstance(frontmatter, dict):
        raise PackageError(
            "SKILL.md frontmatter must use string keys",
            code="invalid_frontmatter",
            path="SKILL.md",
        )
    body = "".join(lines[closing_index + 1 :])
    return frontmatter, body


def _json_value(value: Any, *, depth: int = 0, counter: list[int] | None = None) -> Any:
    if depth > _MAX_JSON_DEPTH:
        raise PackageError(
            "frontmatter is nested too deeply", code="invalid_frontmatter"
        )
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > _MAX_JSON_ITEMS:
        raise PackageError(
            "frontmatter contains too many values", code="invalid_frontmatter"
        )
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PackageError(
                "frontmatter contains a non-finite number", code="invalid_frontmatter"
            )
        return value
    if isinstance(value, (dt.date, dt.datetime, dt.time)):
        return value.isoformat()
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise PackageError(
                    "frontmatter mapping keys must be strings",
                    code="invalid_frontmatter",
                )
            result[key] = _json_value(item, depth=depth + 1, counter=counter)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item, depth=depth + 1, counter=counter) for item in value]
    raise PackageError(
        "frontmatter contains an unsupported YAML value",
        code="invalid_frontmatter",
    )


def _discover_linked_paths(
    files: tuple[PackageFile, ...],
    directories: tuple[str, ...],
    limits: PackageLimits,
) -> list[dict[str, Any]]:
    file_map = {item.path: item for item in files}
    directory_set = set(directories)
    links: dict[str, dict[str, Any]] = {}
    observed = 0
    for source in files:
        if not source.readable or PurePosixPath(source.path).suffix.lower() != ".md":
            continue
        text = source.data.decode("utf-8")
        for target in _markdown_targets(text):
            local = _normalize_markdown_target(target, source.path)
            if local is None:
                continue
            observed += 1
            if observed > limits.max_markdown_links:
                raise PackageError(
                    "package contains too many local Markdown links",
                    code="too_many_links",
                )
            entry = links.setdefault(
                local,
                {
                    "path": local,
                    "exists": local in file_map or local in directory_set,
                    "entry_type": (
                        "file"
                        if local in file_map
                        else "directory"
                        if local in directory_set
                        else "missing"
                    ),
                    "kind": file_map[local].kind
                    if local in file_map
                    else "directory"
                    if local in directory_set
                    else "missing",
                    "readable": file_map[local].readable
                    if local in file_map
                    else False,
                    "referenced_by": [],
                },
            )
            if source.path not in entry["referenced_by"]:
                entry["referenced_by"].append(source.path)
    return [links[path] for path in sorted(links)]


def _markdown_targets(text: str) -> list[str]:
    targets: list[str] = []
    for pattern in (_MARKDOWN_INLINE_LINK_RE, _MARKDOWN_REFERENCE_RE):
        for match in pattern.finditer(text):
            target = match.group(1) or match.group(2)
            if target:
                targets.append(target)
    targets.extend(
        match.group(1).strip() for match in _MARKDOWN_CODE_PATH_RE.finditer(text)
    )
    targets.extend(
        match.group(1).strip() for match in _MARKDOWN_PLAIN_PATH_RE.finditer(text)
    )
    return targets


def _normalize_markdown_target(target: str, source_path: str) -> str | None:
    cleaned = target.strip().strip("<>")
    if not cleaned or cleaned.startswith("#"):
        return None
    parsed = urllib.parse.urlsplit(cleaned)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme.lower() in {"http", "https", "mailto", "data"}:
            return None
        raise PackageError(
            "Markdown links cannot use local or unsupported URI schemes",
            code="unsafe_link",
            path=source_path,
        )
    decoded = urllib.parse.unquote(parsed.path)
    if not decoded:
        return None
    source_parent = PurePosixPath(source_path).parent
    candidate = (source_parent / decoded).as_posix()
    try:
        return normalize_relative_path(candidate)
    except PackageError as exc:
        raise PackageError(
            "Markdown link escapes the skill package",
            code="unsafe_link",
            path=source_path,
        ) from exc


def _diagnose_dependencies(
    files: tuple[PackageFile, ...],
    directories: tuple[str, ...],
    limits: PackageLimits,
) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    for item in files:
        if _REQUIREMENTS_NAME_RE.fullmatch(PurePosixPath(item.path).name):
            diagnostics.extend(_requirements_diagnostics(item, limits))

    local_modules = _local_python_modules(files)
    import_uses: dict[str, set[str]] = {}
    for item in files:
        if item.kind != "script" or PurePosixPath(item.path).suffix.lower() != ".py":
            continue
        if item.size > limits.max_dependency_scan_bytes:
            diagnostics.append(
                {
                    "kind": "script_parse",
                    "name": item.path,
                    "status": "not_scanned",
                    "required_by": [item.path],
                    "message": "Script is too large for dependency analysis.",
                }
            )
            continue
        try:
            source = item.data.decode("utf-8")
        except UnicodeDecodeError:
            diagnostics.append(
                {
                    "kind": "script_parse",
                    "name": item.path,
                    "status": "unsupported_encoding",
                    "required_by": [item.path],
                    "message": "Python scripts must use UTF-8 to be supported.",
                }
            )
            continue
        try:
            tree = ast.parse(source, filename=item.path)
        except (SyntaxError, ValueError):
            diagnostics.append(
                {
                    "kind": "script_parse",
                    "name": item.path,
                    "status": "syntax_error",
                    "required_by": [item.path],
                    "message": "Python syntax could not be analyzed.",
                }
            )
            continue
        for module in _top_level_imports(tree):
            import_uses.setdefault(module, set()).add(item.path)

    for module in sorted(import_uses):
        required_by = sorted(import_uses[module])
        if module in local_modules:
            status = "bundled"
            message = "Module is bundled in the managed skill package."
        elif module in sys.builtin_module_names or module in getattr(
            sys, "stdlib_module_names", set()
        ):
            status = "available"
            message = "Module is provided by the Python standard library."
        else:
            try:
                available = importlib.util.find_spec(module) is not None
            except (ImportError, AttributeError, ValueError):
                available = False
            status = "available" if available else "missing"
            message = (
                "Module is available in the plugin Python environment."
                if available
                else "Module is not available; use an isolated compatible environment."
            )
        diagnostics.append(
            {
                "kind": "python_import",
                "name": module,
                "status": status,
                "required_by": required_by,
                "message": message,
            }
        )

    for item in files:
        if item.kind != "script":
            continue
        suffix = PurePosixPath(item.path).suffix.lower()
        if suffix == ".py" and item.readable:
            continue
        diagnostics.append(
            {
                "kind": "interpreter",
                "name": suffix.lstrip(".") or "unknown",
                "status": "unsupported",
                "required_by": [item.path],
                "message": (
                    "This script type is preserved but has no supported interpreter."
                ),
            }
        )

    for link in _discover_linked_paths(files, directories, limits):
        if not link["exists"]:
            diagnostics.append(
                {
                    "kind": "linked_file",
                    "name": link["path"],
                    "status": "missing",
                    "required_by": link["referenced_by"],
                    "message": "A referenced package file is missing.",
                }
            )
    return _deduplicate_diagnostics(diagnostics)


def _requirements_diagnostics(
    item: PackageFile,
    limits: PackageLimits,
) -> list[dict[str, Any]]:
    if item.size > limits.max_dependency_scan_bytes:
        return [
            {
                "kind": "requirement_file",
                "name": item.path,
                "status": "not_scanned",
                "required_by": [item.path],
                "message": "Requirements file is too large for dependency analysis.",
            }
        ]
    try:
        text = item.data.decode("utf-8")
    except UnicodeDecodeError:
        return [
            {
                "kind": "requirement_file",
                "name": item.path,
                "status": "unsupported_encoding",
                "required_by": [item.path],
                "message": "Requirements files must use UTF-8.",
            }
        ]
    diagnostics: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if (
            line.startswith(("-", "."))
            or "://" in line
            or line.startswith(("git+", "hg+", "svn+", "bzr+"))
        ):
            diagnostics.append(
                {
                    "kind": "python_requirement",
                    "name": f"{item.path}:{line_number}",
                    "status": "unsupported",
                    "required_by": [item.path],
                    "message": "Requirement options, URLs, and local paths are not installed automatically.",
                }
            )
            continue
        requirement_text = _strip_requirement_comment(line)
        if not requirement_text:
            continue
        if Requirement is None:
            diagnostics.append(
                {
                    "kind": "python_requirement",
                    "name": requirement_text[:128],
                    "status": "not_scanned",
                    "required_by": [item.path],
                    "message": "Requirement metadata support is unavailable.",
                }
            )
            continue
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement:
            diagnostics.append(
                {
                    "kind": "python_requirement",
                    "name": f"{item.path}:{line_number}",
                    "status": "invalid",
                    "required_by": [item.path],
                    "message": "Requirement syntax is invalid.",
                }
            )
            continue
        if requirement.url:
            status = "unsupported"
            version = None
            message = "Direct URL requirements are not installed automatically."
        elif requirement.marker is not None and not requirement.marker.evaluate():
            status = "not_applicable"
            version = None
            message = "Requirement does not apply to this runtime."
        else:
            try:
                version = importlib.metadata.version(requirement.name)
            except importlib.metadata.PackageNotFoundError:
                version = None
            if version is None:
                status = "missing"
                message = "Package is not available in the plugin Python environment."
            elif requirement.specifier and not requirement.specifier.contains(
                version,
                prereleases=True,
            ):
                status = "version_mismatch"
                message = "Installed package version does not satisfy the requirement."
            else:
                status = "available"
                message = "Package is available in the plugin Python environment."
        diagnostic: dict[str, Any] = {
            "kind": "python_requirement",
            "name": requirement.name,
            "specifier": str(requirement.specifier),
            "status": status,
            "required_by": [item.path],
            "message": message,
        }
        if version is not None:
            diagnostic["installed_version"] = version
        diagnostics.append(diagnostic)
    return diagnostics


def _script_capabilities(
    files: tuple[PackageFile, ...],
    dependencies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    package_requirements = [
        diagnostic
        for diagnostic in dependencies
        if diagnostic.get("kind") == "python_requirement"
    ]
    for item in files:
        if item.kind != "script":
            continue
        suffix = PurePosixPath(item.path).suffix.lower()
        supported = suffix == ".py" and item.readable
        relevant = [
            diagnostic
            for diagnostic in dependencies
            if item.path in diagnostic.get("required_by", [])
            and diagnostic.get("kind") in {"python_import", "python_requirement"}
        ]
        if suffix == ".py":
            relevant.extend(package_requirements)
        relevant_dependencies = sorted(
            {str(diagnostic["name"]) for diagnostic in relevant}
        )
        blocking = sorted(
            {
                str(diagnostic["name"])
                for diagnostic in relevant
                if diagnostic.get("status")
                in {
                    "invalid",
                    "missing",
                    "syntax_error",
                    "unsupported",
                    "unsupported_encoding",
                    "version_mismatch",
                }
            }
        )
        scripts.append(
            {
                "path": item.path,
                "sha256": item.sha256,
                "size": item.size,
                "interpreter": "python" if supported else None,
                "supported": supported,
                "dependencies": relevant_dependencies,
                "blocking_dependencies": blocking,
            }
        )
    return sorted(scripts, key=lambda script: str(script["path"]))


def _top_level_imports(tree: ast.AST) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.partition(".")[0])
    return {module for module in modules if module.isidentifier()}


def _local_python_modules(files: tuple[PackageFile, ...]) -> set[str]:
    modules: set[str] = set()
    for item in files:
        path = PurePosixPath(item.path)
        if path.suffix.lower() != ".py":
            continue
        if path.stem != "__init__":
            modules.add(path.stem)
        modules.update(part for part in path.parts[:-1] if part.isidentifier())
    return modules


def _deduplicate_diagnostics(
    diagnostics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for diagnostic in diagnostics:
        key = (
            str(diagnostic.get("kind", "")),
            str(diagnostic.get("name", "")),
            str(diagnostic.get("status", "")),
        )
        if key not in merged:
            merged[key] = copy.deepcopy(diagnostic)
            continue
        existing = merged[key]
        required_by = set(existing.get("required_by", []))
        required_by.update(diagnostic.get("required_by", []))
        existing["required_by"] = sorted(required_by)
    return [merged[key] for key in sorted(merged)]


def _dependency_summary(dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    blocking_statuses = {
        "invalid",
        "missing",
        "syntax_error",
        "unsupported",
        "unsupported_encoding",
        "version_mismatch",
    }
    for item in dependencies:
        status = str(item.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "status": (
            "attention_required"
            if any(status_counts.get(status, 0) for status in blocking_statuses)
            else "ready"
        ),
        "counts": status_counts,
        "automatic_install": False,
    }


def _classify_file(path: str, data: bytes, mode: int) -> tuple[str, bool, bool]:
    pure_path = PurePosixPath(path)
    suffix = pure_path.suffix.lower()
    first = pure_path.parts[0].lower()
    executable_bit = bool(mode & 0o111)
    if path == "SKILL.md":
        kind = "skill"
    elif first == "references":
        kind = "reference"
    elif first == "templates":
        kind = "template"
    elif first == "assets":
        kind = "asset"
    elif first == "scripts":
        if (
            suffix == ".py"
            or suffix in _UNSUPPORTED_SCRIPT_EXTENSIONS
            or executable_bit
        ):
            kind = "script"
        else:
            kind = "script_resource"
    else:
        kind = "support"
    text_candidate = (
        suffix in _TEXT_EXTENSIONS or pure_path.name.casefold() in _TEXT_FILENAMES
    )
    readable = text_candidate and b"\x00" not in data and _is_utf8(data)
    if path == "SKILL.md" and not readable:
        raise PackageError(
            "SKILL.md must be strict UTF-8 text",
            code="invalid_utf8",
            path=path,
        )
    return kind, readable, executable_bit


def _kind_counts(files: tuple[PackageFile, ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in files:
        counts[item.kind] = counts.get(item.kind, 0) + 1
    return dict(sorted(counts.items()))


def _has_directory(directories: tuple[str, ...], top_level: str) -> bool:
    return any(
        PurePosixPath(directory).parts[0].casefold() == top_level
        for directory in directories
    )


def _manifest_metadata(item: PackageFile) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "path": item.path,
        "kind": item.kind,
        "size": item.size,
        "sha256": item.sha256,
        "readable": item.readable,
        "executable_bit": item.executable,
    }
    if item.kind == "script":
        suffix = PurePosixPath(item.path).suffix.lower()
        metadata["execution"] = (
            {"interpreter": "python", "supported": True}
            if suffix == ".py" and item.readable
            else {"interpreter": None, "supported": False}
        )
    return metadata


def _manifest_file_entry(
    manifest: Mapping[str, Any],
    relative_path: str,
) -> dict[str, Any]:
    files = manifest.get("files")
    if not isinstance(files, Sequence) or isinstance(files, (str, bytes, bytearray)):
        raise PackageError("manifest file list is invalid", code="invalid_manifest")
    found: dict[str, Any] | None = None
    for entry in files:
        if not isinstance(entry, Mapping):
            raise PackageError(
                "manifest file entry is invalid", code="invalid_manifest"
            )
        path = entry.get("path")
        if not isinstance(path, str):
            raise PackageError("manifest file path is invalid", code="invalid_manifest")
        try:
            normalized = normalize_relative_path(path)
        except PackageError as exc:
            raise PackageError(
                "manifest contains an unsafe path", code="invalid_manifest"
            ) from exc
        if normalized != path:
            raise PackageError(
                "manifest contains a non-canonical path", code="invalid_manifest"
            )
        if path == relative_path:
            if found is not None:
                raise PackageError(
                    "manifest contains duplicate paths", code="invalid_manifest"
                )
            found = dict(entry)
    if found is None:
        raise PackageError(
            "file is not listed in the package manifest",
            code="file_not_in_manifest",
            path=relative_path,
        )
    return found


def _verify_package_snapshot(package: SkillPackage) -> None:
    manifest = package.manifest
    if not isinstance(manifest, Mapping):
        raise PackageError("package manifest is invalid", code="invalid_snapshot")
    expected_data_hash = manifest.get("data_sha256")
    if expected_data_hash != _data_hash(package.files, package.directories):
        raise PackageError("package data hash is invalid", code="invalid_snapshot")
    expected_manifest_hash = manifest.get("manifest_sha256")
    manifest_without_hash = dict(manifest)
    manifest_without_hash.pop("manifest_sha256", None)
    if expected_manifest_hash != _manifest_hash(manifest_without_hash):
        raise PackageError("package manifest hash is invalid", code="invalid_snapshot")
    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, list) or manifest_files != [
        _manifest_metadata(item) for item in package.files
    ]:
        raise PackageError(
            "package files do not match the manifest",
            code="invalid_snapshot",
        )
    if manifest.get("directories") != list(package.directories):
        raise PackageError(
            "package directories do not match the manifest",
            code="invalid_snapshot",
        )


def _verify_manifest(manifest: Mapping[str, Any]) -> None:
    if not isinstance(manifest, Mapping):
        raise PackageError("package manifest is invalid", code="invalid_manifest")
    expected_hash = manifest.get("manifest_sha256")
    if not isinstance(expected_hash, str) or expected_hash != _manifest_hash(manifest):
        raise PackageError("package manifest hash is invalid", code="invalid_manifest")
    if manifest.get("schema_version") != 1:
        raise PackageError(
            "package manifest version is unsupported", code="invalid_manifest"
        )


def _data_hash(
    files: tuple[PackageFile, ...],
    directories: tuple[str, ...],
) -> str:
    digest = hashlib.sha256()
    for directory in sorted(directories):
        digest.update(b"D\0")
        digest.update(directory.encode("utf-8"))
        digest.update(b"\0")
    for item in sorted(files, key=lambda value: value.path):
        digest.update(b"F\0")
        digest.update(item.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(item.size).encode("ascii"))
        digest.update(b"\0")
        digest.update(item.data)
        digest.update(b"\0")
    return digest.hexdigest()


def _manifest_hash(manifest: Mapping[str, Any]) -> str:
    payload = dict(manifest)
    payload.pop("manifest_sha256", None)
    return _sha256(_json_bytes(payload))


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PackageError(
            "package manifest is not JSON-compatible",
            code="invalid_manifest",
        ) from exc


def _display_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def _frontmatter_text(frontmatter: Mapping[str, Any], key: str, limit: int) -> str:
    return _display_text(frontmatter.get(key), limit)


def _strip_requirement_comment(line: str) -> str:
    marker = line.find(" #")
    return line[:marker].strip() if marker >= 0 else line


def _decode_utf8(data: bytes, path: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageError(
            "text file is not valid UTF-8",
            code="invalid_utf8",
            path=path,
        ) from exc


def _is_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_source_name(name: str) -> None:
    _validate_component(name)
    folded = name.casefold()
    if name.startswith(".") or folded in _SENSITIVE_EXACT_NAMES:
        raise PackageError(
            "hidden or sensitive package entries are not allowed",
            code="sensitive_entry_rejected",
            path=name,
        )
    if folded.startswith(".env.") or folded.endswith(_SENSITIVE_SUFFIXES):
        raise PackageError(
            "sensitive-looking package entries are not allowed",
            code="sensitive_entry_rejected",
            path=name,
        )


def _validate_component(component: str) -> None:
    if not component or component in {".", ".."}:
        raise PackageError("path component is invalid", code="invalid_path")
    if component[-1:] in {" ", "."}:
        raise PackageError(
            "path component is unsafe on supported platforms",
            code="invalid_path",
        )
    if any(character in component for character in '<>:"|?*'):
        raise PackageError(
            "path component contains a reserved character",
            code="invalid_path",
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in component):
        raise PackageError(
            "path component contains control characters", code="invalid_path"
        )
    base = component.partition(".")[0].casefold()
    if base in _WINDOWS_RESERVED_NAMES:
        raise PackageError(
            "path component uses a reserved device name",
            code="invalid_path",
        )


def _record_portable_name(path: str, names: dict[str, str]) -> None:
    key = unicodedata.normalize("NFC", path).casefold()
    previous = names.get(key)
    if previous is not None and previous != path:
        raise PackageError(
            "package paths collide on a supported platform",
            code="path_collision",
            path=path,
        )
    names[key] = path


def _require_stable_source_snapshot(
    files: tuple[PackageFile, ...],
    directories: tuple[str, ...],
    verification_files: tuple[PackageFile, ...],
    verification_directories: tuple[str, ...],
) -> None:
    """Reject semantic source changes without comparing platform stat identity.

    Directory mtimes, inode/device numbers, permission bits, and timestamp
    precision are intentionally absent.  Canonical relative paths and entry
    types identify the tree; regular-file size and content digest identify its
    bounded contents.
    """

    def fingerprint(
        snapshot_files: tuple[PackageFile, ...],
        snapshot_directories: tuple[str, ...],
    ) -> dict[str, tuple[str, int, str]]:
        result = {
            path: ("directory", 0, "") for path in snapshot_directories
        }
        result.update(
            {
                item.path: ("file", item.size, item.sha256)
                for item in snapshot_files
            }
        )
        return result

    expected = fingerprint(files, directories)
    observed = fingerprint(verification_files, verification_directories)
    if expected == observed:
        return
    changed_path = next(
        (
            path
            for path in sorted(expected.keys() | observed.keys())
            if expected.get(path) != observed.get(path)
        ),
        None,
    )
    raise PackageError(
        "package source changed during discovery",
        code="source_changed",
        path=changed_path,
    )


def _is_reparse_point(value: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(value, "st_file_attributes", 0)
    return bool(flag and attributes & flag)


def _assert_resolves_within(path: Path, root: Path) -> None:
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise PackageError(
            "package entry escapes the selected source root",
            code="source_escape",
        ) from exc


def _validate_source_file_stat(
    value: os.stat_result,
    limit: int,
    relative_path: str,
) -> None:
    if stat.S_ISLNK(value.st_mode) or _is_reparse_point(value):
        raise PackageError(
            "package entry became a filesystem link",
            code="symlink_rejected",
            path=relative_path,
        )
    if not stat.S_ISREG(value.st_mode):
        raise PackageError(
            "package entry is not an ordinary file",
            code="special_file_rejected",
            path=relative_path,
        )
    if getattr(value, "st_nlink", 0) != 1:
        raise PackageError(
            "hard-linked files are not allowed",
            code="hardlink_rejected",
            path=relative_path,
        )
    if value.st_size > limit:
        raise PackageError(
            "package file exceeds the configured size limit",
            code="file_too_large",
            path=relative_path,
        )


def _read_source_file(
    path: Path,
    expected_stat: os.stat_result,
    resolved_root: Path,
    limit: int,
    relative_path: str,
) -> bytes:
    _validate_source_file_stat(expected_stat, limit, relative_path)
    try:
        current_stat = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise PackageError(
            "package file changed during discovery",
            code="source_changed",
            path=relative_path,
        ) from exc
    except OSError as exc:
        raise PackageError(
            "package file cannot be inspected safely",
            code="source_unavailable",
            path=relative_path,
        ) from exc
    _validate_source_file_stat(current_stat, limit, relative_path)
    if current_stat.st_size != expected_stat.st_size:
        raise PackageError(
            "package file changed during discovery",
            code="source_changed",
            path=relative_path,
        )
    _assert_resolves_within(path, resolved_root)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        try:
            failed_open_stat = os.stat(path, follow_symlinks=False)
        except FileNotFoundError as changed_exc:
            raise PackageError(
                "package file changed during discovery",
                code="source_changed",
                path=relative_path,
            ) from changed_exc
        except OSError:
            failed_open_stat = None
        if failed_open_stat is not None:
            _validate_source_file_stat(
                failed_open_stat,
                limit,
                relative_path,
            )
            if failed_open_stat.st_size != expected_stat.st_size:
                raise PackageError(
                    "package file changed during discovery",
                    code="source_changed",
                    path=relative_path,
                ) from exc
        raise PackageError(
            "package file cannot be opened safely",
            code="source_unavailable",
            path=relative_path,
        ) from exc
    try:
        try:
            opened_path_stat = os.stat(path, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise PackageError(
                "package file changed during discovery",
                code="source_changed",
                path=relative_path,
            ) from exc
        except OSError as exc:
            raise PackageError(
                "package file cannot be inspected after opening",
                code="source_unavailable",
                path=relative_path,
            ) from exc
        _validate_source_file_stat(opened_path_stat, limit, relative_path)
        if opened_path_stat.st_size != expected_stat.st_size:
            raise PackageError(
                "package file changed during discovery",
                code="source_changed",
                path=relative_path,
            )
        opened_stat = os.fstat(descriptor)
        _validate_source_file_stat(opened_stat, limit, relative_path)
        if opened_stat.st_size != expected_stat.st_size:
            raise PackageError(
                "package file changed during discovery",
                code="source_changed",
                path=relative_path,
            )
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise PackageError(
                "package file exceeds the configured size limit",
                code="file_too_large",
                path=relative_path,
            )
        final_stat = os.fstat(descriptor)
        _validate_source_file_stat(final_stat, limit, relative_path)
        if (
            final_stat.st_size != opened_stat.st_size
            or final_stat.st_size != len(data)
        ):
            raise PackageError(
                "package file changed during discovery",
                code="source_changed",
                path=relative_path,
            )
        try:
            current_stat = os.stat(path, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise PackageError(
                "package file changed during discovery",
                code="source_changed",
                path=relative_path,
            ) from exc
        except OSError as exc:
            raise PackageError(
                "package file cannot be inspected after reading",
                code="source_unavailable",
                path=relative_path,
            ) from exc
        _validate_source_file_stat(current_stat, limit, relative_path)
        if current_stat.st_size != final_stat.st_size:
            raise PackageError(
                "package file changed during discovery",
                code="source_changed",
                path=relative_path,
            )
        return data
    finally:
        os.close(descriptor)


def _require_real_directory(path: Path, label: str) -> None:
    try:
        value = path.lstat()
    except OSError as exc:
        raise PackageError(
            f"{label} is unavailable",
            code="managed_root_unavailable",
        ) from exc
    if (
        stat.S_ISLNK(value.st_mode)
        or not stat.S_ISDIR(value.st_mode)
        or _is_reparse_point(value)
    ):
        raise PackageError(
            f"{label} must be an ordinary directory",
            code="managed_root_invalid",
        )


def _managed_destination(root: Path, relative_path: str) -> Path:
    normalized = normalize_relative_path(relative_path)
    destination = root.joinpath(*PurePosixPath(normalized).parts)
    try:
        destination.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise PackageError(
            "managed path escapes its generation root",
            code="managed_path_escape",
            path=normalized,
        ) from exc
    return destination


def _require_no_symlink_components(root: Path, target: Path) -> None:
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise PackageError(
            "managed path escapes its root", code="managed_path_escape"
        ) from exc
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        try:
            value = current.lstat()
        except OSError as exc:
            raise PackageError(
                "managed package path is missing",
                code="managed_file_missing",
            ) from exc
        if (
            stat.S_ISLNK(value.st_mode)
            or not stat.S_ISDIR(value.st_mode)
            or _is_reparse_point(value)
        ):
            raise PackageError(
                "managed package path contains a link or special entry",
                code="managed_file_invalid",
            )


def _read_managed_file(path: Path, limit: int, relative_path: str) -> bytes:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PackageError(
            "managed package file cannot be opened safely",
            code="managed_file_invalid",
            path=relative_path,
        ) from exc
    try:
        opened_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or stat.S_ISLNK(opened_stat.st_mode)
            or _is_reparse_point(opened_stat)
            or getattr(opened_stat, "st_nlink", 0) != 1
        ):
            raise PackageError(
                "managed package entry is not an ordinary file",
                code="managed_file_invalid",
                path=relative_path,
            )
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise PackageError(
                "file exceeds the requested read limit",
                code="read_limit_exceeded",
                path=relative_path,
            )
        final_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(final_stat.st_mode)
            or stat.S_ISLNK(final_stat.st_mode)
            or _is_reparse_point(final_stat)
            or getattr(final_stat, "st_nlink", 0) != 1
        ):
            raise PackageError(
                "managed package entry is not an ordinary file",
                code="managed_file_invalid",
                path=relative_path,
            )
        if (
            final_stat.st_size != opened_stat.st_size
            or final_stat.st_size != len(data)
        ):
            raise PackageError(
                "managed package file changed while being read",
                code="managed_file_changed",
                path=relative_path,
            )
        return data
    finally:
        os.close(descriptor)


def _directory_sort_key(path: str) -> tuple[int, str]:
    return len(PurePosixPath(path).parts), path
