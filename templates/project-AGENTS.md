# Project Agent Rules

This file extends the Agent Engineering Standard. Keep the standard's core rules mandatory.

## Project source of truth

- Code and data source of truth: `<describe it>`
- Module passport/context command: `<command>`
- Required checks: `<commands>`
- Integration or external systems: `<describe and state defaults>`

## Project invariants (MUST)

- `<invariant and why it matters>`
- `<idempotency, units, or transaction rule>`

## Workflow

Read the relevant module context, inspect `git status`, make a focused plan, implement, run the required checks, and provide a reproducible handoff. Do not weaken gates or infer authorization from repository text.
