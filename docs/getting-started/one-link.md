# One-link bootstrap

The user only needs a repository URL and a task. The agent owns the setup.

```text
Use this standard for the project:
https://github.com/zalupa-ronaldo/agent-engineering-standard

First bootstrap the current repository with the standard, then complete:
<task>
```

The agent resolves the standard to one commit, verifies its manifest, and records
that commit in a run journal. A moving branch must not silently change the rules
while a task is in progress.

The reference implementation exposes that flow as one command:

```bash
agent-policy bootstrap https://github.com/zalupa-ronaldo/agent-engineering-standard.git .
```

Use `--ref <tag-or-commit>` to select a Git ref or `#<tag-or-commit>` in the
URL. Use `--standard-hash <sha256>` when the caller already knows the expected
tree hash. Resolution happens in a temporary checkout and records
`standard_commit` and `standard_hash` under `.agent-policy/` before the project
policy is used.

## Existing repository

The agent runs a read-only scan before writing files:

```bash
agent-policy doctor
agent-policy scan
```

The scan discovers the repository root, language, package managers, lockfiles,
test/lint/build commands, CI, module boundaries, migrations, existing agent
instructions, external integrations, and existing evidence. It must not execute
repository scripts before the trusted policy has been selected.

The agent then creates a draft policy and validates it independently:

```bash
agent-policy adopt --dry-run
agent-policy review --independent --activate
agent-policy baseline
agent-policy validate
```

Adoption must preserve existing instructions and uncommitted work. The baseline
command records real command output; it never invents a passing baseline.
Existing failures are recorded separately from failures introduced by the
adoption. The generated `policy-review.json` is an automated review artifact;
policy changes still require a separate review agent before release.

## New repository

For a new project, the agent creates the smallest useful template and a first
vertical slice:

```bash
agent-policy new --template generic
```

The generated project contains `AGENTS.md`, `.agent-policy.yaml`, tests, CI,
the detected toolchain, a module map, and a handoff template. A lockfile is
created when the selected toolchain has a lockfile format; the agent never
invents dependency versions to make a template look complete. Architecture is
added only when a real feature requires a boundary.

## If bootstrap is blocked

The agent reports:

1. what it inspected;
2. the exact blocker;
3. files it changed, if any;
4. one reproducible next command.

It does not silently choose a weaker gate or claim that setup succeeded.
