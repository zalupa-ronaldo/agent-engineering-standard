from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from .models import CommandSpec, Finding, Module, ScanResult


SHELL_TOKENS = re.compile(r"(?:[;&|`]|\$\(|\)\s*\(|\n|\r)")
DANGEROUS_EXECUTABLES = {"bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh", "curl", "wget", "nc", "netcat", "ssh", "scp", "ftp", "telnet", "rm", "dd"}
SECRET_VALUE = re.compile(r"(?i)(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]")
QUALITY_FLOORS = {"line_coverage_min": 95, "branch_coverage_min": 90, "mutation_score_min": 90}


@dataclass
class PolicyDocument:
    data: dict[str, Any]
    path: Path


def policy_path(root: Path) -> Path | None:
    for name in (".agent-policy.yaml", ".agent-policy.yml"):
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def load_policy(root: str | Path = ".", path: str | Path | None = None) -> PolicyDocument:
    root_path = Path(root).expanduser().resolve()
    selected = Path(path).expanduser().resolve() if path else policy_path(root_path)
    if selected is None or not selected.is_file():
        raise FileNotFoundError("no .agent-policy.yaml or .agent-policy.yml found")
    if root_path not in selected.parents and selected != root_path:
        raise ValueError("policy file must be inside the project root")
    try:
        content = selected.read_text(encoding="utf-8")
        value = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("policy must contain a YAML mapping")
    return PolicyDocument(value, selected)


def _finding(code: str, message: str, severity: str = "error", path: str | None = None) -> Finding:
    return Finding(code, message, severity, path)


def validate_policy(data: dict[str, Any], root: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if data.get("version") != 1:
        findings.append(_finding("POLICY-002", "policy version must be the integer 1"))
    if not isinstance(data.get("project"), dict):
        findings.append(_finding("POLICY-003", "project must be a mapping"))
    else:
        project = data["project"]
        if not isinstance(project.get("name"), str) or not project["name"].strip():
            findings.append(_finding("POLICY-003", "project.name must be a non-empty string"))
        if not isinstance(project.get("modules"), list):
            findings.append(_finding("POLICY-003", "project.modules must be a list"))
    commands = data.get("commands", {})
    if not isinstance(commands, dict):
        findings.append(_finding("POLICY-004", "commands must be a mapping"))
        commands = {}
    for name, command in commands.items():
        if not isinstance(name, str) or not name:
            findings.append(_finding("POLICY-005", "command names must be non-empty strings"))
            continue
        if not isinstance(command, dict):
            findings.append(_finding("POLICY-006", f"command {name!r} must use structured argv"))
            continue
        unknown_fields = set(command) - {"argv", "cwd", "timeout_seconds"}
        if unknown_fields:
            findings.append(_finding("POLICY-021", f"command {name!r} has unknown fields: {sorted(unknown_fields)}"))
        if "shell" in command:
            findings.append(_finding("POLICY-007", f"command {name!r} cannot set shell execution"))
        argv = command.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
            findings.append(_finding("POLICY-008", f"command {name!r} must contain a non-empty argv list"))
            continue
        if any(SHELL_TOKENS.search(item) for item in argv):
            findings.append(_finding("POLICY-009", f"command {name!r} contains shell syntax; use separate argv items"))
        if any(SECRET_VALUE.search(item) for item in argv):
            findings.append(_finding("POLICY-022", f"command {name!r} appears to contain a credential; use an approved secret store"))
        executable = Path(argv[0]).name.lower()
        if executable in DANGEROUS_EXECUTABLES:
            findings.append(_finding("POLICY-010", f"command {name!r} uses blocked executable {executable!r}"))
        cwd = command.get("cwd", ".")
        if not isinstance(cwd, str) or not cwd or Path(cwd).is_absolute() or ".." in Path(cwd).parts:
            findings.append(_finding("POLICY-011", f"command {name!r} cwd must be a relative path inside the project"))
        timeout = command.get("timeout_seconds", 900)
        if not isinstance(timeout, int) or timeout <= 0 or timeout > 86_400:
            findings.append(_finding("POLICY-012", f"command {name!r} timeout_seconds must be between 1 and 86400"))
    quality = data.get("quality", {})
    if not isinstance(quality, dict):
        findings.append(_finding("POLICY-013", "quality must be a mapping"))
    else:
        for key, floor in QUALITY_FLOORS.items():
            if key not in quality:
                findings.append(_finding("POLICY-014", f"quality.{key} must be declared; minimum is {floor}"))
                continue
            value = quality[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < floor or value > 100:
                findings.append(_finding("POLICY-014", f"quality.{key} must be between {floor} and 100"))
    modules = data.get("project", {}).get("modules", []) if isinstance(data.get("project"), dict) else []
    if not isinstance(modules, list):
        findings.append(_finding("POLICY-015", "project.modules must be a list"))
    else:
        seen: set[str] = set()
        for module in modules:
            if not isinstance(module, dict) or not isinstance(module.get("id"), str) or not module["id"].strip():
                findings.append(_finding("POLICY-016", "each module must have a non-empty id"))
                continue
            if module["id"] in seen:
                findings.append(_finding("POLICY-017", f"duplicate module id {module['id']!r}"))
            seen.add(module["id"])
            if "paths" not in module:
                findings.append(_finding("POLICY-018", f"module {module['id']!r} must declare paths"))
            for key in ("paths", "tests"):
                if key in module and (not isinstance(module[key], list) or not all(isinstance(item, str) for item in module[key])):
                    findings.append(_finding("POLICY-018", f"module {module['id']!r} {key} must be a list of strings"))
                if key == "paths" and isinstance(module.get(key), list):
                    for rel in module[key]:
                        if not rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
                            findings.append(_finding("POLICY-020", f"module path escapes project: {rel!r}"))
    release = data.get("release", {})
    if release is not None and not isinstance(release, dict):
        findings.append(_finding("POLICY-019", "release must be a mapping"))
    if root is not None:
        for module in modules if isinstance(modules, list) else []:
            if isinstance(module, dict):
                for rel in module.get("tests", []) if isinstance(module.get("tests"), list) else []:
                    if Path(rel).is_absolute() or ".." in Path(rel).parts:
                        findings.append(_finding("POLICY-021", f"module test path escapes project: {rel!r}"))
    return findings


def policy_from_scan(scan: ScanResult) -> dict[str, Any]:
    commands = {name: spec.as_dict() for name, spec in scan.commands.items()}
    return {
        "version": 1,
        "standard": {"name": "agent-engineering-standard", "version": "1.0.0"},
        "project": {
            "name": scan.root.name,
            "modules": [module.as_dict() for module in scan.modules],
            "languages": scan.languages,
            "frameworks": scan.frameworks,
            "package_managers": scan.package_managers,
            "lockfiles": scan.lockfiles,
            "agent_rules": scan.agent_rules,
            "ci_files": scan.ci_files,
            "migration_paths": scan.migration_paths,
            "external_integrations": scan.external_integrations,
        },
        "commands": commands,
        "quality": dict(QUALITY_FLOORS),
        "architecture": {
            "forbidden_imports": [],
            "max_cyclomatic_complexity": 10,
        },
        "security": {
            "required_checks": ["invalid_input", "authorization", "replay", "dependency_failure", "secret_scan"],
            "unknown_external_result": "blocked",
        },
        "release": {
            "dangerous_actions": "blocked",
            "reversible_deploy_only": True,
            "auto_merge": False,
            "auto_deploy": False,
        },
        "evidence": {
            "require_commit_match": True,
            "include_source_hashes": True,
        },
        "baseline": {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "ratchet": True,
            "known_failures": [],
            "source_commit": scan.git.get("head"),
        },
    }


def dump_yaml(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False)


def atomic_write(path: Path, content: str, overwrite: bool = False) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        return False
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)
    return True


def write_json(path: Path, value: Any, overwrite: bool = True) -> bool:
    return atomic_write(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", overwrite=overwrite)


def command_specs(data: dict[str, Any]) -> dict[str, CommandSpec]:
    result: dict[str, CommandSpec] = {}
    for name, value in data.get("commands", {}).items():
        if isinstance(value, dict) and isinstance(value.get("argv"), list):
            result[name] = CommandSpec(tuple(value["argv"]), value.get("cwd", "."), value.get("timeout_seconds", 900))
    return result
