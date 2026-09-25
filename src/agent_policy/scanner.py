from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import CommandSpec, Finding, Module, ScanResult


SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".tox", ".ruff_cache", "dist", "build", ".agent-policy",
    ".hypothesis", "htmlcov", ".eggs",
}
CRITICAL_WORDS = {"auth", "payment", "payments", "money", "ledger", "billing", "crash", "security", "admin"}
SECRET_NAME_RE = re.compile(r"(^|[._-])(env|secret|token|credential|private|password)([._-]|$)", re.I)
SENSITIVE_URL_RE = re.compile(r"(?:token|secret|password|passwd|api[_-]?key|access[_-]?token)", re.I)


def _safe_remote(value: str | None) -> str | None:
    """Return a journal-safe remote URL without inline credentials."""
    if not value:
        return None
    parsed = urlsplit(value)
    if not parsed.scheme:
        if "@" in value and ":" in value:
            return value.rsplit("@", 1)[-1]
        return value
    host = parsed.hostname or ""
    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"
    query = "" if parsed.query and SENSITIVE_URL_RE.search(parsed.query) else parsed.query
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for directory, dirs, names in os.walk(root):
        # Keep hidden project configuration directories (.github, .clinerules,
        # .cursor) visible.  Only known tool caches and generated directories
        # are excluded.
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS and not name.endswith(".egg-info"))
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_file():
                files.append(path)
    return files


def _git(root: Path) -> dict[str, Any]:
    def run(*args: str) -> str | None:
        try:
            result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode:
            return None
        return result.stdout.strip()

    is_repo = run("rev-parse", "--show-toplevel")
    if not is_repo:
        return {"is_repository": False, "branch": None, "head": None, "base": None, "dirty": False, "status": []}
    status = run("status", "--short") or ""
    return {
        "is_repository": True,
        "branch": run("branch", "--show-current"),
        "head": run("rev-parse", "HEAD"),
        "base": run("rev-parse", "--verify", "HEAD~1"),
        "dirty": bool(status),
        "status": status.splitlines(),
        "remote": _safe_remote(run("config", "--get", "remote.origin.url")),
    }


def _parse_package_json(path: Path) -> tuple[list[str], dict[str, CommandSpec]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], {}
    scripts = value.get("scripts", {}) if isinstance(value, dict) else {}
    if not isinstance(scripts, dict):
        return [], {}
    commands: dict[str, CommandSpec] = {}
    # npm itself resolves script names and does not require a shell from this CLI.
    for name in ("test", "lint", "build", "typecheck", "type-check"):
        if name in scripts and isinstance(scripts[name], str):
            commands["typecheck" if name in {"typecheck", "type-check"} else name] = CommandSpec(("npm", "run", name))
    return ["npm"], commands


def _make_targets(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return set()
    targets: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("."):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:", stripped)
        if match:
            targets.add(match.group(1))
    return targets


def _detect_modules(root: Path, files: list[Path]) -> list[Module]:
    source_roots = [path for path in ("src", "app", "backend", "frontend", "lib", "packages") if (root / path).is_dir()]
    if not source_roots:
        source_roots = ["."] if any(path.suffix in {".py", ".ts", ".tsx", ".js", ".go", ".rs", ".java"} for path in files) else []
    modules: list[Module] = []
    for source_root in source_roots:
        base = root / source_root
        if source_root == ".":
            candidates = sorted({path.parent for path in files if path.suffix in {".py", ".ts", ".tsx", ".js", ".go", ".rs", ".java"}})
            candidates = candidates[:50]
        else:
            candidates = sorted(path for path in base.iterdir() if path.is_dir() and not path.name.startswith(".") and not path.name.endswith(".egg-info"))
            if not candidates and any(path.is_file() for path in base.iterdir()):
                candidates = [base]
        for candidate in candidates:
            try:
                rel = candidate.relative_to(root).as_posix()
            except ValueError:
                continue
            module_id = "root" if rel in {"", "."} else rel.replace("/", ".")
            tests = []
            for test_dir in (root / "tests", root / "test", candidate / "tests"):
                if test_dir.exists():
                    tests.append(test_dir.relative_to(root).as_posix())
            critical = any(word in module_id.lower().split(".") for word in CRITICAL_WORDS)
            modules.append(Module(module_id, [rel], sorted(set(tests)), critical))
    # Deduplicate modules when multiple source roots point to the same path.
    seen: set[str] = set()
    return [module for module in modules if not (module.id in seen or seen.add(module.id))]


def scan_project(path: str | Path = ".") -> ScanResult:
    requested = Path(path).expanduser().resolve()
    # A new-project dry run may point at a path that does not exist yet.  Keep
    # that path as the prospective root instead of accidentally scanning its
    # parent directory and reporting unrelated files.
    root = requested if requested.is_dir() or not requested.exists() else requested.parent
    files = _walk_files(root)
    rel_files = {file.relative_to(root).as_posix() for file in files}
    languages: list[str] = []
    frameworks: list[str] = []
    package_managers: list[str] = []
    commands: dict[str, CommandSpec] = {}
    lockfiles = sorted(path for path in rel_files if Path(path).name in {
        "poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt", "package-lock.json",
        "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "go.sum",
    })
    if any(file.suffix == ".py" for file in files) or "pyproject.toml" in rel_files or "requirements.txt" in rel_files:
        languages.append("python")
        if "pyproject.toml" in rel_files:
            try:
                text = (root / "pyproject.toml").read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                text = ""
            if "fastapi" in text:
                frameworks.append("fastapi")
            if "django" in text:
                frameworks.append("django")
            if "pytest" in text or "[tool.pytest" in text:
                commands["test"] = CommandSpec(("python", "-m", "pytest"))
            if "ruff" in text:
                commands["lint"] = CommandSpec(("ruff", "check", "."))
            elif "flake8" in text:
                commands["lint"] = CommandSpec(("flake8", "."))
        if "requirements.txt" in rel_files and "test" not in commands:
            commands["test"] = CommandSpec(("python", "-m", "pytest"))
        if "uv.lock" in rel_files:
            package_managers.append("uv")
        elif "poetry.lock" in rel_files:
            package_managers.append("poetry")
        else:
            package_managers.append("pip")
    if "package.json" in rel_files:
        languages.append("javascript")
        package_managers.append("npm" if "package-lock.json" in rel_files else "node")
        node_frameworks, node_commands = _parse_package_json(root / "package.json")
        if "npm" not in package_managers and node_frameworks:
            package_managers.extend(node_frameworks)
        commands.update(node_commands)
        try:
            package_text = (root / "package.json").read_text(encoding="utf-8").lower()
        except OSError:
            package_text = ""
        if "react" in package_text:
            frameworks.append("react")
        if "next" in package_text:
            frameworks.append("next")
        if "typescript" in package_text or "tsconfig.json" in rel_files:
            languages.append("typescript")
    if "Cargo.toml" in rel_files:
        languages.append("rust")
        package_managers.append("cargo")
        commands.setdefault("test", CommandSpec(("cargo", "test")))
    if any(file.suffix == ".go" for file in files) or "go.mod" in rel_files:
        languages.append("go")
        package_managers.append("go")
        commands.setdefault("test", CommandSpec(("go", "test", "./...")))
    if "Makefile" in rel_files:
        # Make targets are invoked as argv; shell interpretation stays inside make,
        # so only a checked-in target name is accepted.
        make_targets = _make_targets(root / "Makefile")
        for name in ("test", "check", "lint", "integration"):
            if name in make_targets:
                commands.setdefault(name, CommandSpec(("make", name)))
    ci_files = sorted(path for path in rel_files if path.startswith(".github/workflows/") or path in {".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml"})
    policy_files = sorted(path for path in rel_files if path in {"AGENTS.md", "STANDARD.yaml", "STANDARD.yml", ".agent-policy.yaml", ".agent-policy.yml", ".clinerules"} or path.startswith(".clinerules/"))
    agent_rules = sorted(path for path in rel_files if (
        path == "AGENTS.md" or path in {".clinerules", ".cursor/rules", ".windsurf/rules"}
        or path.startswith(".clinerules/") or path.startswith(".cursor/rules/")
        or path.startswith(".windsurf/rules/")
    ))
    migration_paths = sorted(path for path in rel_files if any(token in path.lower() for token in ("migration", "migrations", "alembic", "flyway")))
    external_integrations = sorted(path for path in rel_files if any(token in path.lower() for token in ("webhook", "provider", "stripe", "telegram", "oauth", "payment")))
    findings: list[Finding] = []
    git = _git(root)
    if not git["is_repository"]:
        findings.append(Finding("GIT-001", "Project is not inside a Git repository", "error"))
    elif git["dirty"]:
        findings.append(Finding("GIT-002", "Working tree contains pre-existing changes; they are not modified by the scanner", "warning"))
    if not policy_files:
        findings.append(Finding("POLICY-001", "No project policy file was found; run agent-policy init", "warning"))
    # Report only names and paths for potential secrets, never values.
    for relative in sorted(rel_files):
        if SECRET_NAME_RE.search(Path(relative).name) and Path(relative).name not in {".env.example", ".env.sample"}:
            findings.append(Finding("SECRET-001", "Potential secret-bearing file requires review", "error", relative))
    return ScanResult(
        root=root,
        git=git,
        languages=sorted(set(languages)),
        frameworks=sorted(set(frameworks)),
        package_managers=sorted(set(package_managers)),
        commands=commands,
        modules=_detect_modules(root, files),
        policy_files=policy_files,
        ci_files=ci_files,
        migration_paths=migration_paths,
        external_integrations=external_integrations,
        lockfiles=lockfiles,
        agent_rules=agent_rules,
        findings=findings,
    )
