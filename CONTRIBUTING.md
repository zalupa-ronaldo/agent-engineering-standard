# Contributing

The standard is itself maintained by agents and people using the same gates it
defines. Keep changes small and explain the rule, failure mode, and observable
check they add.

## Development

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

Policy, schema, CLI, Skill, and adapter changes require tests or fixture
evidence. Do not weaken a gate to make the standard pass. Changes to policy or
the enforcement engine must be reviewed independently from changes to the
examples that they validate.

