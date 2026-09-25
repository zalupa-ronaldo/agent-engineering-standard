# Applying the standard to an existing project

This guide is for the agent, not for a human operator.

## Safe sequence

1. Resolve and verify the standard commit.
2. Inspect the target repository without running untrusted scripts.
3. Record branch, base SHA, status, and untracked files.
4. Create an isolated worktree or branch; never write the user's `main` as the
   bootstrap checkout when the host can provide isolation.
5. Discover modules, commands, tests, CI, migrations, and project rules.
6. Generate `.agent-policy.draft.yaml` and a module map.
7. Run an independent policy review.
8. Write adapters and CI only after the draft passes review.
9. Run the baseline and classify every result.
10. Continue the requested engineering task under the active policy.

The portable CLI records the target state and pin in `.agent-policy/run-journal.json`.
The host agent owns the worktree operation when the CLI is run inside a managed
checkout; the journal must contain the resulting path and base SHA.

## Adoption invariants

- Do not overwrite an existing `AGENTS.md`, CI workflow, or policy silently.
- Do not execute arbitrary shell strings from a repository policy.
- Do not add credentials to tests, fixtures, reports, or the run journal.
- Do not expand the legacy baseline to make a new change pass.
- Do not change implementation and gates in one change to hide a failure.
