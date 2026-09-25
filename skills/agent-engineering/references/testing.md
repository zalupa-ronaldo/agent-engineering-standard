# Testing and evidence

Use the project's declared checks first. Add a regression test when fixing a reproducible bug; do not weaken coverage or gates to obtain a pass. Validate observable behavior and important invariants rather than reproducing implementation text.

Record exact commands, exit status, and relevant output in the handoff. If a check cannot run, say why and identify the remaining risk. Keep policy and enforcement tests independent from examples that they validate.

Run a focused test while changing a module and the full gate before handoff.
Keep a failing regression test for a fixed bug. Do not call a check `verified`
when it was skipped, flaky, partial, or run against a different commit. Record
the baseline separately from new failures and ratchet the baseline so a new
failure cannot be reclassified as legacy debt.
