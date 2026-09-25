from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
import yaml

from agent_policy.bootstrap import BootstrapError, resolve_standard, validate_manifest, write_run_journal
from agent_policy.cli import main


def make_standard(root: Path, *, version: str = "1.0.0") -> Path:
    (root / "skills" / "agent-engineering").mkdir(parents=True)
    (root / "schemas").mkdir()
    (root / "AGENTS.md").write_text("Read STANDARD.yaml.\n", encoding="utf-8")
    (root / "skills" / "agent-engineering" / "SKILL.md").write_text("skill\n", encoding="utf-8")
    (root / "schemas" / "project-policy.schema.json").write_text("{}\n", encoding="utf-8")
    (root / "STANDARD.yaml").write_text(
        yaml.safe_dump(
            {
                "id": "agent-engineering-standard",
                "version": version,
                "entrypoint": "AGENTS.md",
                "skill": "skills/agent-engineering/SKILL.md",
                "policy_schema": "schemas/project-policy.schema.json",
                "supported_agents": ["codex", "cline", "generic"],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return root


def make_git_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "standard"], check=True)


def test_resolve_plain_standard_and_pin_hash(tmp_path: Path) -> None:
    standard = make_standard(tmp_path / "standard")
    with resolve_standard(standard) as resolved:
        assert resolved.commit is None
        assert len(resolved.content_hash) == 64
        assert resolved.manifest["id"] == "agent-engineering-standard"
        assert resolved.root != standard


def test_resolve_git_standard_pins_commit(tmp_path: Path) -> None:
    standard = make_standard(tmp_path / "standard")
    make_git_repo(standard)
    commit = subprocess.check_output(["git", "-C", str(standard), "rev-parse", "HEAD"], text=True).strip()
    with resolve_standard(standard, requested_ref=commit) as resolved:
        assert resolved.commit == commit
        assert resolved.requested_ref == commit


def test_git_url_fragment_selects_commit(tmp_path: Path) -> None:
    standard = make_standard(tmp_path / "standard")
    make_git_repo(standard)
    commit = subprocess.check_output(["git", "-C", str(standard), "rev-parse", "HEAD"], text=True).strip()
    with resolve_standard(f"file://{standard}#{commit}") as resolved:
        assert resolved.commit == commit
        assert resolved.requested_ref == commit


def test_manifest_rejects_unsupported_version(tmp_path: Path) -> None:
    standard = make_standard(tmp_path / "standard", version="2.0.0")
    with pytest.raises(BootstrapError, match="unsupported standard major"):
        validate_manifest(standard)


def test_url_with_inline_credentials_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(BootstrapError, match="inline credentials"):
        resolve_standard("https://user:password@example.invalid/repo.git")


def test_journal_is_durable_and_does_not_write_on_dry_run(tmp_path: Path) -> None:
    standard = make_standard(tmp_path / "standard")
    project = tmp_path / "project"
    project.mkdir()
    with resolve_standard(standard) as resolved:
        path, payload = write_run_journal(project, resolved, dry_run=True)
        assert payload["standard"]["standard_hash"] == resolved.content_hash
        assert not path.exists()
        path, _ = write_run_journal(project, resolved)
        assert path.is_file()
        journal = json.loads(path.read_text(encoding="utf-8"))
        assert journal["run_id"]
        assert journal["standard_hash"] == resolved.content_hash


def test_bootstrap_cli_records_standard_identity(tmp_path: Path, capsys) -> None:
    standard = make_standard(tmp_path / "standard")
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    make_git_repo(project)
    assert main(["bootstrap", str(standard), str(project), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["standard"]["standard_hash"]
    assert (project / ".agent-policy" / "standard.json").is_file()
    assert list((project / ".agent-policy" / "runs").glob("*.json"))


def test_bootstrap_refuses_to_replace_an_existing_standard_pin(tmp_path: Path, capsys) -> None:
    first = make_standard(tmp_path / "first")
    second = make_standard(tmp_path / "second")
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text("project\n", encoding="utf-8")
    make_git_repo(project)
    assert main(["bootstrap", str(first), str(project), "--json"]) == 0
    capsys.readouterr()
    assert main(["bootstrap", str(second), str(project), "--json"]) == 2
    value = json.loads(capsys.readouterr().out)
    assert value["status"] == "blocked"
    assert "different standard" in value["error"]


def test_bootstrap_does_not_silently_change_standard_pin(tmp_path: Path, capsys) -> None:
    standard = make_standard(tmp_path / "standard")
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    make_git_repo(project)
    assert main(["bootstrap", str(standard), str(project)]) == 0
    capsys.readouterr()
    (standard / "AGENTS.md").write_text("changed\n", encoding="utf-8")
    assert main(["bootstrap", str(standard), str(project), "--json"]) == 2
    value = json.loads(capsys.readouterr().out)
    assert "different standard" in value["error"]
