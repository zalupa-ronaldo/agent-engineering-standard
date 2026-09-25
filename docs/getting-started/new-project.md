# Starting a project with the standard

The user supplies a goal. The agent selects a minimal template and records any
technical assumptions in the project policy.

```bash
agent-policy new --template generic
```

Templates may specialize the toolchain, but the core rules stay the same:

- tests are created with the first behavior;
- lockfiles and reproducible commands are committed;
- CI starts before the second feature;
- production credentials are absent from local setup;
- generated policy and adapters are checked for drift;
- the first handoff is created even when the first task finishes.

If the requested product behavior is ambiguous, the agent asks about that
behavior. It does not ask the user to choose routine testing, architecture, or
quality settings.

