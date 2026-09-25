from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CommandSpec:
    """A command that can be run by the policy checker.

    Commands are deliberately represented as an argv list.  There is no shell
    string form in this package, which prevents policy data from being treated
    as executable shell code by accident.
    """

    argv: tuple[str, ...]
    cwd: str = "."
    timeout_seconds: int = 900

    def as_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class Finding:
    code: str
    message: str
    severity: str = "warning"
    path: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value = {"code": self.code, "message": self.message, "severity": self.severity}
        if self.path:
            value["path"] = self.path
        return value


@dataclass
class Module:
    id: str
    paths: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    critical: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "paths": self.paths,
            "tests": self.tests,
            "critical": self.critical,
        }


@dataclass
class ScanResult:
    root: Path
    git: dict[str, Any]
    languages: list[str]
    frameworks: list[str]
    package_managers: list[str]
    commands: dict[str, CommandSpec]
    modules: list[Module]
    policy_files: list[str]
    ci_files: list[str]
    migration_paths: list[str]
    external_integrations: list[str]
    lockfiles: list[str] = field(default_factory=list)
    agent_rules: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "git": self.git,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "package_managers": self.package_managers,
            "commands": {key: value.as_dict() for key, value in self.commands.items()},
            "modules": [module.as_dict() for module in self.modules],
            "policy_files": self.policy_files,
            "ci_files": self.ci_files,
            "migration_paths": self.migration_paths,
            "external_integrations": self.external_integrations,
            "lockfiles": self.lockfiles,
            "agent_rules": self.agent_rules,
            "findings": [finding.as_dict() for finding in self.findings],
        }
