# Agent adapters

The canonical rules are shared. Adapters only describe how an agent discovers
and loads them.

## Codex

The agent reads the pinned `AGENTS.md` and `STANDARD.yaml`, then loads
`skills/agent-engineering/SKILL.md` with progressive disclosure. Bootstrap also
copies the Skill into the workspace `.codex/skills/` when that directory is
available. Keep the project's `AGENTS.md` in version control so a new task can
start safely even when a global Skill is unavailable.

## Cline

Bootstrap copies the Skill into `.cline/skills/` for a workspace. Cline also
reads project `AGENTS.md` and `.clinerules`; existing rules are preserved and
cannot grant permission to bypass the active policy.

## Degraded mode

An agent without Skill support uses the project's `AGENTS.md` and invokes the
portable CLI for `context`, `check`, `evidence`, and `handoff`. Adapter files may
change discovery UX; they must not change the standard's requirements.
