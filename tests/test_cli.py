from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from agent_policy.cli import main
from agent_policy.policy import validate_policy
from agent_policy.scanner import scan_project


def make_project(tmp_path: Path, *, git: bool = True) -> Path:
    root = tmp_path / "project"
    root.mkdir(parents=True)
    (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n\n[tool.pytest.ini_options]\n", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "demo.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_demo.py").write_text("def test_add():\n    assert 1 + 1 == 2\n", encoding="utf-8")
    if git:
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "initial"], check=True)
    return root


def test_scan_is_read_only_and_detects_python(tmp_path: Path) -> None:
    root = make_project(tmp_path)
    result = scan_project(root)
    assert "python" in result.languages
    assert result.commands["test"].argv == ("python", "-m", "pytest")
    assert not (root / ".agent-policy").exists()


def test_init_dry_run_writes_nothing(tmp_path: Path, capsys) -> None:
    root = make_project(tmp_path)
    assert main(["init", str(root), "--dry-run", "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["dry_run"] is True
    assert not (root / ".agent-policy.yaml").exists()
    assert not (root / "AGENTS.md").exists()


def test_init_then_validate_and_context(tmp_path: Path, capsys) -> None:
    root = make_project(tmp_path)
    assert main(["init", str(root), "--json"]) == 0
    capsys.readouterr()
    assert (root / ".agent-policy.yaml").is_file()
    assert main(["validate", str(root), "--json"]) == 0
    validation = json.loads(capsys.readouterr().out)
    assert validation["valid"] is True
    policy = yaml.safe_load((root / ".agent-policy.yaml").read_text(encoding="utf-8"))
    module_id = policy["project"]["modules"][0]["id"]
    assert main(["context", module_id, str(root), "--json"]) == 0
    context = json.loads(capsys.readouterr().out)
    assert context["module"]["id"] == module_id


def test_validate_rejects_shell_and_low_quality(tmp_path: Path, capsys) -> None:
    root = make_project(tmp_path)
    (root / ".agent-policy.yaml").write_text(
        "version: 1\nproject:\n  name: bad\n  modules: []\ncommands:\n  test:\n    argv: ['sh', '-c', 'echo ok']\nquality:\n  line_coverage_min: 20\n",
        encoding="utf-8",
    )
    assert main(["validate", str(root), "--json"]) == 2
    value = json.loads(capsys.readouterr().out)
    codes = {finding["code"] for finding in value["findings"]}
    assert {"POLICY-010", "POLICY-014"} <= codes


def test_check_runs_argv_without_a_shell(tmp_path: Path, capsys) -> None:
    root = make_project(tmp_path)
    policy = {
        "version": 1,
        "project": {"name": "demo", "modules": []},
        "commands": {"test": {"argv": [sys.executable, "-c", "print('ok')"]}},
        "quality": {"line_coverage_min": 95, "branch_coverage_min": 90, "mutation_score_min": 90},
    }
    (root / ".agent-policy.yaml").write_text(yaml.safe_dump(policy), encoding="utf-8")
    assert main(["check", str(root), "--json"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["status"] == "passed"
    assert (root / ".agent-policy" / "check.json").is_file()


def test_handoff_install_and_evidence(tmp_path: Path, capsys) -> None:
    root = make_project(tmp_path)
    main(["init", str(root)])
    capsys.readouterr()
    assert main(["handoff", str(root), "--goal", "demo", "--next-command", "agent-policy check", "--json"]) == 0
    capsys.readouterr()
    assert (root / ".agent-policy" / "handoff.json").is_file()
    assert main(["install", str(root), "--agent", "all", "--json"]) == 0
    capsys.readouterr()
    assert (root / ".cline" / "skills" / "agent-engineering" / "SKILL.md").is_file()
    assert (root / ".codex" / "skills" / "agent-engineering" / "SKILL.md").is_file()
    assert main(["evidence", str(root), "--json"]) == 1
    evidence = json.loads(capsys.readouterr().out)
    assert evidence["artifact"]


def test_adopt_new_aliases_are_real_commands(tmp_path: Path) -> None:
    existing = make_project(tmp_path / "existing")
    assert main(["adopt", str(existing), "--dry-run"]) == 0
    new_root = tmp_path / "new"
    assert main(["new", str(new_root), "--dry-run"]) == 0
    assert not new_root.exists()


def test_policy_validation_api_rejects_absolute_cwd() -> None:
    findings = validate_policy(
        {
            "version": 1,
            "project": {"modules": []},
            "commands": {"test": {"argv": ["python"], "cwd": "/tmp"}},
            "quality": {"line_coverage_min": 95, "branch_coverage_min": 90, "mutation_score_min": 90},
        }
    )
    assert any(finding.code == "POLICY-011" for finding in findings)


def test_scan_discovers_hidden_ci_rules_and_lockfiles(tmp_path: Path) -> None:
    root = make_project(tmp_path)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    (root / ".cursor" / "rules").mkdir(parents=True)
    (root / ".cursor" / "rules" / "security.md").write_text("rules\n", encoding="utf-8")
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    result = scan_project(root)
    assert ".github/workflows/ci.yml" in result.ci_files
    assert ".cursor/rules/security.md" in result.agent_rules
    assert "uv.lock" in result.lockfiles


def test_scan_registers_root_module_for_root_level_source(tmp_path: Path) -> None:
    root = tmp_path / "plain"
    root.mkdir()
    (root / "root_module.py").write_text("VALUE = 1\n", encoding="utf-8")
    result = scan_project(root)
    assert any(module.id == "root" for module in result.modules)


def test_policy_rejects_secret_shaped_command_and_bool_quality() -> None:
    findings = validate_policy(
        {
            "version": 1,
            "project": {"name": "demo", "modules": []},
            "commands": {"test": {"argv": ["python", "token=secret"]}},
            "quality": {"line_coverage_min": True, "branch_coverage_min": 90, "mutation_score_min": 90},
        }
    )
    codes = {finding.code for finding in findings}
    assert {"POLICY-014", "POLICY-022"} <= codes


def test_baseline_classifies_existing_and_new_failures(tmp_path: Path, capsys) -> None:
    root = make_project(tmp_path)
    policy = {
        "version": 1,
        "project": {"name": "demo", "modules": []},
        "commands": {
            "old": {"argv": ["python", "-c", "raise SystemExit(3)"]},
            "new": {"argv": ["python", "-c", "raise SystemExit(4)"]},
        },
        "quality": {"line_coverage_min": 95, "branch_coverage_min": 90, "mutation_score_min": 90},
    }
    (root / ".agent-policy.yaml").write_text(yaml.safe_dump(policy), encoding="utf-8")
    (root / ".agent-policy").mkdir()
    (root / ".agent-policy" / "baseline.json").write_text(json.dumps({"known_failures": ["old"]}), encoding="utf-8")
    assert main(["check", str(root), "--json"]) == 1
    value = json.loads(capsys.readouterr().out)
    classifications = {item["name"]: item["classification"] for item in value["commands"]}
    assert classifications == {"old": "existing_failure", "new": "new_failure"}


def test_review_requires_independent_attestation(tmp_path: Path, capsys) -> None:
    root = make_project(tmp_path)
    assert main(["init", str(root), "--json"]) == 0
    capsys.readouterr()
    assert main(["review", str(root), "--json"]) == 2
    pending = json.loads(capsys.readouterr().out)
    assert pending["valid"] is False
    assert main(["review", str(root), "--independent", "--activate", "--json"]) == 0
    reviewed = json.loads(capsys.readouterr().out)
    assert reviewed["independent"] is True
