# Agent Engineering Standard

The Agent Engineering Standard is an agent-first bootstrap contract for source
repositories. A person gives an agent this repository URL and a task. The agent
pins the standard, discovers the target, creates a reviewed project policy,
runs a baseline, and then continues the task with durable evidence.

## One-link entrypoint

Give an agent a message like:

```text
Use the Agent Engineering Standard from:
https://github.com/example/agent-engineering-standard

Bootstrap the current repository, then implement:
<task>
```

The agent must resolve the URL, tag, or commit to one immutable `standard_commit`
and compute `standard_hash`. It records both in `.agent-policy/run-journal.json`.
A moving branch cannot silently replace the rules during a task. The fetched
checkout is read as data until `STANDARD.yaml` and `AGENTS.md` pass validation;
scripts and post-install hooks from the standard are never executed as part of
bootstrap.

## What bootstrap does

For an existing project, the portable CLI exposes the same operations an agent
can call:

```bash
agent-policy doctor PROJECT       # read-only discovery
agent-policy scan PROJECT         # read-only scan
agent-policy adopt PROJECT        # draft policy, artifacts, adapters
agent-policy review PROJECT --independent --activate
agent-policy validate PROJECT
agent-policy check PROJECT
agent-policy evidence PROJECT
agent-policy handoff PROJECT --status complete
```

`bootstrap --standard URL PROJECT` is the one-link wrapper. It verifies the
standard checkout, records the pin, and then performs adoption. `--dry-run`
leaves the target unchanged. Existing `AGENTS.md`, CI, policy files, dirty
paths, and user changes are preserved; an agent must not use `reset --hard`,
`clean`, silent stash, or force push to make adoption succeed.

The generated project artifacts are:

```text
.agent-policy.draft.yaml       # proposed policy before activation
.agent-policy.yaml             # active machine policy
.agent-policy/scan.json        # discovery evidence
.agent-policy/module-map.json  # module boundaries and tests
.agent-policy/run-journal.json # standard pin, target SHA, occupied paths
.agent-policy/handoff.json     # continuation state for the next agent
.github/workflows/agent-policy.yml
docs/agent/
```

The policy uses structured `argv` commands, `shell=False`, project-root path
containment, secret redaction, mandatory quality floors, and a ratcheted
baseline. Results are classified as `verified`, `existing_failure`,
`new_failure`, `not_run`, or `blocked`. A completion claim requires fresh
commit-bound evidence.

## New projects

When the task asks for a new project, the agent selects the smallest suitable
template and runs:

```bash
agent-policy new PROJECT --template generic
```

The agent creates the repository structure, policy, tests, lockfiles, CI, a
first vertical scenario, and a handoff. Routine toolchain and test decisions
are automatic. The agent asks only when product behavior is ambiguous, access
or a secret is missing, or an irreversible action is outside machine policy.

## Contract and progressive disclosure

The canonical root files are:

- [`AGENTS.md`](AGENTS.md): short mandatory entrypoint for an agent;
- [`STANDARD.yaml`](STANDARD.yaml): machine-readable manifest and core rules;
- [`skills/agent-engineering/SKILL.md`](skills/agent-engineering/SKILL.md):
  focused skill with references;
- [`schemas/project-policy.schema.json`](schemas/project-policy.schema.json):
  project-policy shape.

The skill routes an agent to only the relevant bootstrap, security, testing,
architecture, or handoff reference. Adapters describe Codex, Cline, and a
portable generic mode; they do not weaken the contract.

## Development

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
python3 -m agent_policy validate .
python3 -m agent_policy scan .
```

See [`docs/getting-started/one-link.md`](docs/getting-started/one-link.md) for
the full agent sequence and [`CONTRIBUTING.md`](CONTRIBUTING.md) for changes to
the policy engine.
