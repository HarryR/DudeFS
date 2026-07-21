# White-box test-access audit (NOTES 57 item 3)

Inventory of tests reaching into private (`_name`) attributes, each classified as
**migrated** (now public surface) or **blessed** (`# white-box:` at the call site).
The point: during the hygiene refactor, a break at a *blessed* access is test-debt
(update the test); a break at any *other* private access would be a new coupling and
should be treated as a regression signal.

## Migrated to public surface

| Was | Now | Why |
|---|---|---|
| `sim._raw` (×45) | `sim.raw` | The Sim's underlying node list is the intended test seam (`.nodes` is the LoggingNode wrapper); made it a plain public attribute. |
| `WorkerServer._dispatch_line` (×3) | `WorkerServer.dispatch_line` | Tests exercise the JSON-RPC line layer without a socket; a legitimate public seam. |

## Blessed (`# white-box:` at the call site) — production internals, asserted deliberately

| Access | Files | Rationale |
|---|---|---|
| `quorum.Commit._Phase` | test_quorum | Assert the Commit state machine's internal phase across the fetch window — the transition IS the thing under test. |
| `fold._total_order_key`, `fold._authorized_cuts` | test_compaction | Pin the internal total-order + cut-authorization helpers directly. |
| `ChainStore._write_hw`, `_write_attested` | test_store | Seed durable floor state; the acceptor owns the public write path, so tests use the low-level setter to construct fixtures. |

## Test-infrastructure internals (blessed by convention, not annotated per-site)

`World._mseq / _mprev / _hlc / _mgr_op` (test builder) and the sim harness internals
live in `tests/_builders.py` and `dudefs/sim/` — test-support code, not the
production surface a refactor of the kernel would touch. Accesses from other test
files are test→test-infra and carry the same low regression risk as calling a public
builder method; `cut_of()` (now in `_builders.py`) is the consolidated reader of
`World`'s chain head. If the sim/builders are themselves refactored, these move with
them in one place.

## Result

No unclassified private access into a production module remains: the kernel-facing
white-box accesses are the three blessed categories above, all with an explicit
comment naming why the internal is asserted.
