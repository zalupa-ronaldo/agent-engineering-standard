"""Safe resolution and bootstrap metadata for the Agent Engineering Standard.

The bootstrap path is intentionally small and boring.  It only performs Git
operations with an argv list, reads the two standard entrypoint files, and
records an immutable commit and content hash before project files are touched.
Repository supplied scripts are never imported or executed by this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

import yaml

from .policy import atomic_write, write_json


STANDARD_ID = "agent-engineering-standard"
SUPPORTED_MAJOR = 1
MANIFEST_NAMES = ("STANDARD.yaml", "STANDARD.yml")
ENTRYPOINT = "AGENTS.md"
_SEMVER = re.compile(r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)$")
_ALLOWED_SCHEMES = {"file", "git", "https", "ssh"}
_SENSITIVE_URL_KEY = re.compile(r"(?:token|secret|password|passwd|api[_-]?key|access[_-]?token)", re.I)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class BootstrapError(RuntimeError):
    """A fail-closed bootstrap error.

    The message is safe to show to a user and must not contain command output
    or credential-shaped values.
    """


@dataclass
class ResolvedStandard:
    """A validated, isolated copy of a standard checkout."""

    root: Path
    source: str
    source_kind: str
    requested_ref: str | None
    commit: str | None
    content_hash: str
    manifest: dict[str, Any]
    temporary: tempfile.TemporaryDirectory[str] | None = field(default=None, repr=False)

    @property
    def version(self) -> str:
        return str(self.manifest["version"])

    @property
    def standard_commit(self) -> str | None:
        return self.commit

    @property
    def standard_hash(self) -> str:
        return self.content_hash

    def metadata(self) -> dict[str, Any]:
        """Return journal-safe standard identity metadata."""

        return {
            "id": STANDARD_ID,
            "version": self.version,
            "source": self.source,
            "source_kind": self.source_kind,
            "requested_ref": self.requested_ref,
            "standard_commit": self.commit,
            "standard_hash": self.content_hash,
        }

    def cleanup(self) -> None:
        if self.temporary is not None:
            self.temporary.cleanup()
            self.temporary = None

    def __enter__(self) -> "ResolvedStandard":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.cleanup()


def _safe_text(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BootstrapError(f"{label} must be a non-empty string")
    if _CONTROL.search(value):
        raise BootstrapError(f"{label} contains control characters")
    return value.strip()


def _safe_relative(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise BootstrapError(f"{label} must be a relative path")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise BootstrapError(f"{label} escapes the standard root")
    # A Windows drive path can be absolute even when parsed on POSIX.
    if re.match(r"^[A-Za-z]:[\\/]", value):
        raise BootstrapError(f"{label} must be relative")
    return candidate.as_posix()


def _run_git(args: list[str], *, cwd: Path | None = None, timeout: int = 120) -> str:
    """Run a fixed Git executable with no shell and bounded output."""

    if any("\x00" in part for part in args):
        raise BootstrapError("Git argument contains a NUL byte")
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BootstrapError(f"Git operation failed: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        # Git output can include a URL containing credentials.  Keep only a
        # short generic error in the user-facing exception.
        raise BootstrapError(f"Git operation failed (exit {completed.returncode})")
    return completed.stdout.strip()


def _git_revision(root: Path, revision: str = "HEAD") -> str | None:
    try:
        return _run_git(["-C", str(root), "rev-parse", "--verify", f"{revision}^{{commit}}"], timeout=30)
    except BootstrapError:
        return None


def _git_repository(root: Path) -> bool:
    top = _git_command(root, "rev-parse", "--show-toplevel")
    if not top:
        return False
    try:
        return Path(top).resolve() == root.resolve()
    except OSError:
        return False


def _git_command(root: Path, *args: str) -> str | None:
    try:
        return _run_git(["-C", str(root), *args], timeout=30)
    except BootstrapError:
        return None


def _sanitise_source(source: str) -> str:
    """Avoid persisting URL credentials or secret-looking query parameters."""

    parsed = urlsplit(source)
    if not parsed.scheme:
        return source
    host = parsed.hostname or ""
    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"
    query = "" if parsed.query and _SENSITIVE_URL_KEY.search(parsed.query) else parsed.query
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def _validate_source_url(source: str) -> None:
    parsed = urlsplit(source)
    # SCP-like Git syntax is handled by git itself, but credentials in URLs
    # are rejected before they could enter a journal or exception.
    if parsed.scheme:
        if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
            raise BootstrapError(f"unsupported standard URL scheme: {parsed.scheme}")
        if parsed.username or parsed.password:
            raise BootstrapError("standard URL must not contain inline credentials")
        if parsed.query and _SENSITIVE_URL_KEY.search(parsed.query):
            raise BootstrapError("standard URL contains a credential-like query parameter")
        if parsed.scheme != "file" and not parsed.netloc:
            raise BootstrapError("standard URL has no host")
    elif ":" in source and re.match(r"^[^/\s:@]+@[^/\s:]+:.+", source):
        # git@host:path syntax has no URL query/userinfo to redact.  It is
        # allowed as a Git transport and is still passed as one argv item.
        return
    elif "@" in source and ":" in source and not Path(source).exists():
        raise BootstrapError("unsupported standard source")


def _tree_hash(root: Path) -> str:
    """Hash names and bytes deterministically, excluding the Git directory."""

    digest = hashlib.sha256()
    files: list[Path] = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in sorted(names):
            files.append(Path(directory) / name)
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        if path.is_symlink():
            data = os.readlink(path).encode("utf-8")
            digest.update(b"L")
        elif path.is_file():
            data = path.read_bytes()
            digest.update(b"F")
        else:
            continue
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _manifest_path(root: Path) -> Path:
    for name in MANIFEST_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    raise BootstrapError("standard is missing root STANDARD.yaml")


def _read_manifest(root: Path) -> dict[str, Any]:
    path = _manifest_path(root)
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise BootstrapError("standard manifest could not be read") from exc
    except yaml.YAMLError as exc:
        raise BootstrapError("standard manifest contains invalid YAML") from exc
    if not isinstance(value, dict):
        raise BootstrapError("standard manifest must contain a mapping")
    return value


def validate_manifest(root: str | Path, manifest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Validate the trusted root contract without loading arbitrary files."""

    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise BootstrapError("standard checkout is not a directory")
    value = dict(manifest) if manifest is not None else _read_manifest(root_path)
    if value.get("id") != STANDARD_ID:
        raise BootstrapError(f"standard manifest id must be {STANDARD_ID!r}")
    version = value.get("version")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise BootstrapError("standard manifest version must be semantic version text")
    if int(version.split(".", 1)[0]) != SUPPORTED_MAJOR:
        raise BootstrapError(f"unsupported standard major version: {version}")
    if value.get("entrypoint") != ENTRYPOINT:
        raise BootstrapError("standard entrypoint must be AGENTS.md")
    for key in ("entrypoint", "skill", "policy_schema"):
        relative = _safe_relative(value.get(key), label=f"standard.{key}")
        candidate = (root_path / relative).resolve()
        try:
            candidate.relative_to(root_path)
        except ValueError as exc:
            raise BootstrapError(f"standard.{key} escapes the checkout") from exc
        if not candidate.is_file():
            raise BootstrapError(f"standard.{key} does not exist: {relative}")
        if key == "entrypoint":
            try:
                entrypoint_text = candidate.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise BootstrapError("standard AGENTS.md could not be read") from exc
            if not entrypoint_text.strip():
                raise BootstrapError("standard AGENTS.md is empty")
    agents = value.get("supported_agents")
    if not isinstance(agents, list) or not all(isinstance(agent, str) for agent in agents):
        raise BootstrapError("standard.supported_agents must be a list of strings")
    required = {"codex", "cline", "generic"}
    if not required.issubset(set(agents)):
        raise BootstrapError("standard.supported_agents must include codex, cline, and generic")
    return value


def _copy_plain_source(source: Path, destination: Path) -> None:
    try:
        shutil.copytree(source, destination, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    except (OSError, shutil.Error) as exc:
        raise BootstrapError("could not copy local standard into isolation") from exc


def _checkout_git(source: str, destination: Path, requested_ref: str | None) -> tuple[str, str]:
    _validate_source_url(source)
    # `--no-checkout` ensures no repository hooks or files are processed before
    # the manifest is read. Git itself is the only executable involved.
    _run_git(["clone", "--no-checkout", "--no-tags", source, str(destination)], timeout=300)
    if requested_ref:
        requested_ref = _safe_text(requested_ref, label="standard ref")
        if requested_ref.startswith("-") or _CONTROL.search(requested_ref):
            raise BootstrapError("standard ref is not a valid Git revision")
        revision = _git_revision(destination, requested_ref)
        if revision is None:
            # A tag/commit not included by a no-tags clone is fetched explicitly.
            _run_git(["-C", str(destination), "fetch", "--no-tags", "origin", requested_ref], timeout=300)
            revision = _git_revision(destination, requested_ref)
        if revision is None:
            raise BootstrapError("requested standard ref is not a commit")
    else:
        revision = _git_revision(destination)
        if revision is None:
            raise BootstrapError("standard repository has no commit")
    # Ignore repository-provided attributes while materialising the checkout;
    # this prevents a custom filter process from running before the manifest is
    # trusted. Hooks are not run by clone/checkout, and no project script is
    # imported by this module.
    _run_git(
        ["-c", "core.attributesfile=/dev/null", "-C", str(destination), "checkout", "--detach", "--force", revision],
        timeout=120,
    )
    return revision, "git"


def resolve_standard(
    source: str | Path,
    *,
    requested_ref: str | None = None,
    ref: str | None = None,
    expected_hash: str | None = None,
) -> ResolvedStandard:
    """Resolve a local path or Git URL into a pinned, isolated standard.

    The returned object owns its temporary directory and should be used as a
    context manager.  No project files are touched by this function.
    """

    raw_source = _safe_text(str(source), label="standard source")
    if requested_ref is not None and ref is not None and requested_ref != ref:
        raise BootstrapError("standard ref was provided twice with different values")
    requested_ref = requested_ref if requested_ref is not None else ref
    if requested_ref is not None:
        requested_ref = _safe_text(requested_ref, label="standard ref")
    parsed_source = urlsplit(raw_source)
    if parsed_source.scheme and parsed_source.fragment:
        fragment_ref = _safe_text(parsed_source.fragment, label="standard ref")
        if requested_ref is not None and requested_ref != fragment_ref:
            raise BootstrapError("standard ref disagrees with the URL fragment")
        requested_ref = fragment_ref
        raw_git_source = urlunsplit(
            (parsed_source.scheme, parsed_source.netloc, parsed_source.path, parsed_source.query, "")
        )
    else:
        raw_git_source = raw_source
    source_path = Path(raw_source).expanduser()
    temporary = tempfile.TemporaryDirectory(prefix="agent-standard-")
    checkout = Path(temporary.name) / "standard"
    source_kind = "git"
    commit: str | None = None
    try:
        if source_path.exists():
            source_path = source_path.resolve()
            if not source_path.is_dir():
                raise BootstrapError("local standard source must be a directory")
            if _git_repository(source_path):
                commit, source_kind = _checkout_git(str(source_path), checkout, requested_ref)
            else:
                if requested_ref:
                    raise BootstrapError("a ref can only be used with a Git standard source")
                _copy_plain_source(source_path, checkout)
                source_kind = "directory"
        else:
            _validate_source_url(raw_git_source)
            if not (urlsplit(raw_git_source).scheme or re.match(r"^[^/\s:@]+@[^/\s:]+:.+", raw_git_source)):
                raise BootstrapError(f"standard source does not exist: {raw_source}")
            commit, source_kind = _checkout_git(raw_git_source, checkout, requested_ref)
        manifest = validate_manifest(checkout)
        content_hash = _tree_hash(checkout)
        if expected_hash is not None:
            expected_hash = _safe_text(expected_hash, label="standard hash").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                raise BootstrapError("standard hash must be a SHA-256 hex digest")
            if content_hash != expected_hash:
                raise BootstrapError("standard content hash does not match expected hash")
        return ResolvedStandard(
            root=checkout,
            source=_sanitise_source(raw_source),
            source_kind=source_kind,
            requested_ref=requested_ref,
            commit=commit,
            content_hash=content_hash,
            manifest=manifest,
            temporary=temporary,
        )
    except Exception:
        temporary.cleanup()
        raise


def _git_project_state(root: Path) -> dict[str, Any]:
    """Collect project identity without running project commands."""

    top = _git_command(root, "rev-parse", "--show-toplevel")
    if not top:
        return {
            "is_repository": False,
            "branch": None,
            "head": None,
            "dirty": False,
            "changed_paths": [],
        }
    status = _git_command(root, "status", "--short") or ""
    changed_paths: list[str] = []
    for line in status.splitlines():
        # Git status --short is metadata, but preserve only the path portion;
        # never persist a complete command or file content.
        path = line[3:].strip() if len(line) >= 3 else ""
        if path:
            changed_paths.append(path)
    head = _git_command(root, "rev-parse", "HEAD")
    base = _git_command(root, "rev-parse", "HEAD~1") or head
    return {
        "is_repository": True,
        "branch": _git_command(root, "branch", "--show-current"),
        "head": head,
        "base": base,
        "dirty": bool(status),
        "changed_paths": changed_paths,
        "remote": _sanitise_source(_git_command(root, "config", "--get", "remote.origin.url") or "") or None,
    }


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(6)


def write_run_journal(
    project_root: str | Path,
    standard: ResolvedStandard,
    *,
    run_id: str | None = None,
    status: str = "verified",
    phase: str = "bootstrap",
    events: list[dict[str, Any]] | None = None,
    dry_run: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """Persist a durable, append-friendly journal entry for one bootstrap run."""

    root = Path(project_root).expanduser().resolve()
    run_id = run_id or new_run_id()
    state = _git_project_state(root)
    now = datetime.now(timezone.utc).isoformat()
    payload: dict[str, Any] = {
        "format": 1,
        "run_id": run_id,
        "created_at": now,
        "updated_at": now,
        "status": status,
        "phase": phase,
        "dry_run": bool(dry_run),
        "project": {
            "root": str(root),
            **state,
            "base_sha": state.get("base"),
            "head_sha": state.get("head"),
            "occupied_paths": list(state.get("changed_paths", [])),
        },
        "standard": standard.metadata(),
        # Keep the two pin fields at the top level as well so shell tooling and
        # a future agent can resume without knowing the nested schema first.
        "standard_commit": standard.commit,
        "standard_hash": standard.content_hash,
        "events": events or [{"at": now, "phase": phase, "status": status}],
    }
    path = root / ".agent-policy" / "runs" / f"{run_id}.json"
    if not dry_run:
        write_json(path, payload, overwrite=False)
        # A stable pointer lets the next agent continue without guessing which
        # run is current. It does not overwrite a user's policy files.
        # Keep both names during the 1.0 transition.  `run-journal.json` is
        # the public artifact; `run.json` is a short compatibility alias for
        # agents that adopted an earlier preview.
        write_json(root / ".agent-policy" / "run-journal.json", payload, overwrite=True)
        write_json(root / ".agent-policy" / "run.json", payload, overwrite=True)
    return path, payload


def write_standard_metadata(
    project_root: str | Path,
    standard: ResolvedStandard,
    *,
    dry_run: bool = False,
    overwrite: bool = False,
) -> Path:
    """Write the pinned standard identity used by later agents and evidence."""

    path = Path(project_root).expanduser().resolve() / ".agent-policy" / "standard.json"
    if not dry_run:
        metadata = standard.metadata()
        if path.exists() and not overwrite:
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise BootstrapError("existing standard metadata is unreadable; use --force only after review") from exc
            if existing != metadata:
                raise BootstrapError("project is pinned to a different standard; review and use --force to change it")
        else:
            write_json(path, metadata, overwrite=overwrite)
    return path


__all__ = [
    "BootstrapError",
    "ResolvedStandard",
    "resolve_standard",
    "validate_manifest",
    "write_run_journal",
    "write_standard_metadata",
]
