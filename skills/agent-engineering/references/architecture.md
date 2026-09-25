# Architecture and boundaries

Identify ownership and contracts before changing a module. Keep UI, integration adapters, and domain or financial core boundaries explicit. Preserve source-of-truth rules, idempotency, transactional coupling, and units defined by the project.

Prefer the smallest change that satisfies the request. Document architectural decisions when a boundary, data flow, trust assumption, or recovery behavior changes. Do not hide complexity by excluding it from checks.

Avoid speculative abstractions, duplicate sources of truth, hidden global state,
and cross-module shortcuts. A next agent should be able to find the owner,
invariants, inputs, outputs, and tests for every changed path. Keep migrations
backward compatible through expand, backfill, and contract phases; do not mix a
destructive data change into an unrelated feature without a rollback or
reconciliation path.
