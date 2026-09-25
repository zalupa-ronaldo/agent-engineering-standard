# Upgrading the standard

Standard versions are pinned in the project policy. The agent upgrades them with:

```bash
agent-policy upgrade --dry-run
agent-policy upgrade
```

An upgrade shows policy changes, validates generated adapters, preserves local
project constraints, and runs conformance tests. It cannot lower a mandatory
security or correctness gate silently.

