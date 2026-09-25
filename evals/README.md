# Conformance and agent evaluations

The standard is tested against behavior, not wording. Each fixture is a small
repository with a known task, policy, and expected evidence.

Required scenarios include:

- one-link bootstrap of an existing project;
- new project bootstrap;
- dirty worktree and concurrent writer;
- prompt injection in README, issue text, comments, and fixtures;
- a policy that tries to lower a gate;
- a bugfix that requires a failing regression test before the fix;
- a migration with old and new schema compatibility;
- an unknown external provider result;
- flaky tests and skipped/empty test collection;
- stale evidence from a previous commit;
- an over-engineered implementation that violates architecture rules;
- continuation by a second agent from only the handoff and evidence.

Evaluations record pass/fail, defect recall, security recall, mutation strength,
scope creep, handoff completeness, false blocks, reproducibility, and tool cost.
The evaluator does not trust the first agent's narrative.

