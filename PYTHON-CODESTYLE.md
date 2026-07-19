# DudeFS Python code style

> **Status:** the conventions the `dudefs/` package is written to. Recorded so
> they survive across sessions and contributors. The overriding aims: **strict,
> honest typing** and **a straightforward path to idiomatic Rust and Go** — the
> POC is a reference implementation, so its shapes should translate, not fight
> the translator. Where a Python-ism has no clean Rust/Go analogue, prefer the
> form that does. `make check` (ruff + ty + tests) is the gate; keep it green.

## 0. Toolchain — self-contained, never global

- Dev tooling lives **under the project**: `make install` puts `uv` in `./.uv`
  (via `UV_UNMANAGED_INSTALL`, never `~/.local/bin`) and a `./.venv` with **ruff**
  (lint + format) and **ty** (Astral's Rust type checker). Nothing touches `$HOME`.
- **Never install anything globally, or install anything at all without explicit
  consent.** "We both know this tool" is not consent.
- `ruff` is lint + format; it is **not** a type checker. `ty` is the type checker
  (Pylance/pyright also runs in-editor). Don't conflate them.
- `make check` = `ruff check` + `ruff format --check` + `ty check` + `unittest`.
  It must stay green; that is the definition of "done" for a change.

## 1. Modern Python (target 3.12+)

Use current language features; do **not** hand-stringify hints or reach for
legacy `typing` shims.

- **PEP 695 type aliases**: `type Bencodable = int | bytes | ...`, not
  `Bencodable = "..."` string aliases or `TypeAlias`.
- **Built-in generics and unions**: `list[T]`, `dict[K, V]`, `tuple[...]`,
  `X | None` — never `typing.List`/`Optional`/`Union`.
- **`typing.Self`** for methods returning their own class (classmethods /
  instance methods). Plain unqualified class name where `Self` is invalid
  (staticmethods).
- **`@functools.total_ordering`** to derive the comparison operators from
  `__eq__` + one of `__lt__`/`__le__` (see `HLC`, `Ballot`) — don't hand-write
  `__gt__`/`__ge__` (their absence is also a real bug: `>=` silently works via
  reflected ops but a type checker flags it).
- `from __future__ import annotations` is fine and used — it keeps annotations
  lazy (clean forward refs, no import-time cost). It is *not* the "stringized
  hints" that are discouraged; that means **manually** quoting types.

## 2. Types are strict and honest

The type checker is a design tool, not a formality. Two rules:

1. **No `Any` except at a genuinely dynamic boundary.** The bencode `codec.decode`
   returns `Bencodable` (a real recursive union), not `Any`. `Any`/`object`
   survive only where the value truly is dynamic: `codec.encode(value: object)`
   (accepts anything and validates at runtime), a build-side dict fed straight to
   `encode`, or a decoded control-op body handled dynamically.
2. **The wire→typed boundary is a set of *validating extractors*, not casts.**
   `codec.as_int/as_bytes/as_seq/as_dict` turn a `Bencodable` into a concrete
   type *or raise* `CodecError`. This is real validation — a malformed field
   fails at the boundary, not confusingly three layers down. Prefer these over
   `cast`. The library is **cast-free**: the one place that looked like it needed
   a cast (`Op.from_bytes` re-keying) instead validates via `Field(k)`.

### `tuple` over `list` for immutable/decoded data

`Bencodable`'s sequence arm is `tuple[Bencodable, ...]`, not `list`:

- Decoded wire data is **immutable** by nature — a tuple enforces it and is
  lower-memory.
- Tuples are **covariant** (because immutable), so a `tuple[int, ...]` from
  `HLC.encode()` *is* a `tuple[Bencodable, ...]` — constructing bencodable
  structures needs no cast past `list`'s invariance.
- Tuples are **concrete**, so `isinstance(v, tuple)` narrows cleanly. (A
  covariant *abstract* `Sequence` was tried and reverted: narrowing it back to a
  concrete type degrades the element type to `Unknown`.)

Rule of thumb: **`list` only when you actually mutate it; `tuple` for fixed,
returned, or decoded sequences.**

### `TypedDict` for known-shape records

A dict with a fixed set of string keys is a struct, not a mapping. Use
`TypedDict` (`fold.SnapEntry`, `Cert`, `Genesis`). `dict[str, Any]` for a
known-shape record is a smell (and untranslatable — Rust/Go want a struct).

### Decouple with `Protocol`

To avoid an import cycle between layers, depend on a structural `Protocol`, not
the concrete class (see `handlers.data.StateReader` standing in for the fold's
`StateView`).

## 3. Enums, not string/byte constants

A closed set of values is an enum. This is both a strictness win and the
Rust/Go-faithful form (a Rust `enum`, a Go typed-constant group).

- **Values that go on the wire** (encoded in ops/artifacts) → **`BytesEnum`**
  (`class X(bytes, Enum)`): members *are* bytes, so they encode via the codec,
  hash/compare as their value, and work as dict keys interchangeably with plain
  bytes. Examples: `OpClass`, `Guard`, `Mutation`, `Field`, `TxnField`,
  `ControlKind`, `Cap`.
- **Values persisted / serialized** (DB, wire response) → **`StrEnum`** (stable
  string `.value` round-trips): e.g. `store.EvidenceKind`.
- **Purely in-memory** result/reason enums → **plain `Enum`** with `auto()` —
  the strictest form: a member is *not* equal to a raw string, so it cannot be
  compared to a string by accident. Examples: `acceptor.RejectReason`,
  `handlers.data.OpaqueReason`.

Field-*key* constants are a closed set too — they became `Field`/`TxnField`
(`BytesEnum`), not loose `K_*` module constants. The only bare constant left is
a lone discriminator key (`control.BK_KIND`) where an enum-of-one adds nothing.

## 4. Errors: a typed hierarchy, never string flavours

If you find yourself **testing an error by its string message**, or catching a
typed exception only to re-raise it with `str(e)` as the message, stop — the
distinction wants to be a **type**, not a string.

**Package hierarchy** (`dudefs/errors.py` holds only the root; per-module bases
live in their modules):

```
DudeFSError                      # catch-all: `except DudeFSError`
├── codec.CodecError             # per-module bases: `except codec.CodecError`
├── crypto.CryptoError
└── artifacts.ArtifactError
    ├── artifacts.UnknownField   # typed leaves: `except UnknownField`
    └── artifacts.MissingField   # both carry `.key: bytes` (structured, not a message)
```

A leaf earns its existence by being a distinct *kind* of failure, not a distinct
*message*. Counter-example we removed: a "MalformedField" that only asserted a
decoded tuple's arity — that's a bencode *shape* check, so it lives in the codec
(`codec.as_seq(v, n)` → `CodecError`), in the same family as `as_int`/`as_bytes`,
not as a bespoke artifact error. Artifact leaves are about *keys* (unknown /
missing); shape is the codec's job.

- A consumer can `except DudeFSError` (all), `except <module>.<Base>` (one
  module), or `except <Leaf>` (one failure) — the three granularities.
- **Leaves carry structured data, not string messages.** `UnknownField(key)` and
  `MissingField(key)` expose `.key: bytes`; the constructor sets a human-readable
  message for *display only*. Code branches on the **type** (and reads
  attributes), never on `str(e)`.
- **The catch-all is a real guarantee: no decode/parse path may leak a bare
  `KeyError`/`ValueError`.** Required-field access goes through a helper that
  raises the typed `MissingField` (`artifacts._require`), not `dict[key]`. When a
  stdlib call raises (e.g. `Field(k)` raising `ValueError`), translate it to a
  typed leaf immediately — don't stringify it.
- **Diagnostic messages are fine** on a typed error, as long as they are for
  humans and never the differentiator. A single error type with a message *is*
  acceptable for genuinely fine-grained, minor variants that no one branches on
  (e.g. the many `CodecError` bencode-parse messages) — don't over-fragment those
  into leaves.
- **Result-shaped "errors" are not exceptions.** An acceptor rejection is an
  expected outcome, so it's *returned* (`Rejected(RejectReason)`), not raised —
  a `Result`-style variant. Its reason is a typed enum, not a string.
- Vendored code (`vendor/ed25519.py`) stays standalone and may raise stdlib
  `ValueError` on misuse — it is deliberately not coupled to this hierarchy.

## 5. Small things

- Docstrings cite the normative doc section (`DESIGN §6`, `PROTOCOL §1.1`) — the
  code is an implementation *of* the design; keep the trace.
- Line length 100; ruff formats. Don't hand-align against the formatter.
- Prefer a validating constructor/extractor at a boundary over trusting input and
  failing later. "Parse, don't validate" — turn bytes into typed values once, at
  the edge, and work with the typed values inside.
