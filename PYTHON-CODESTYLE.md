# DudeFS Python code style

> The conventions the `dude/` package is written to. The overriding aims:
> strict, honest typing and a straightforward path to idiomatic Rust and
> Go. The POC is a reference implementation, so its shapes should translate,
> not fight the translator. Where a Python-ism has no clean Rust/Go
> analogue, prefer the form that does. `make check` (ruff + ty + tests)
> is the gate; keep it green.

## 0. Toolchain

Dev tooling lives under the project: `make install` puts `uv` in `./.uv`
and a `./.venv` with ruff (lint + format) and ty (typecheck). Nothing
touches `$HOME`. Never install anything globally, or install anything at
all without explicit consent.

`make check` = `ruff check` + `ruff format --check` + `ty check`. It must
stay green.

## 1. Modern Python (target 3.12+)

Use current language features.

- Built-in generics and unions: `list[T]`, `dict[K, V]`, `tuple[...]`,
  `X | None`. Never `typing.List`, `Optional`, `Union`.
- `typing.Self` for methods returning their own class.
- `@functools.total_ordering` to derive comparison operators.
- `TypedDict` with `Unpack` for shared kwargs patterns (`GuardOpts`).
- `from __future__ import annotations` is present in some files but not
  required on 3.12+. Do not add it to new files.

## 2. Types are strict and honest

The type checker is a design tool, not a formality.

1. No `Any` except at a genuinely dynamic boundary. The bencode
   `codec.decode` returns `Bencodable` (a real recursive union), not
   `Any`.
2. The wire-to-typed boundary is a set of validating extractors, not
   casts. `codec.as_int/as_bytes/as_seq/as_dict` turn a `Bencodable`
   into a concrete type or raise `CodecError`.

### ABCs over type aliases for polymorphic types

A closed set of related types with shared interface is an ABC hierarchy,
not a `type X = A | B` union alias. The ABC defines the abstract
interface (`encode`, `decode`), each subclass owns its own
implementation. This gives isinstance narrowing, registry patterns for
decode dispatch, and a single place to add new variants.

`@dataclass(frozen=True, slots=True)` on ABC subclasses: the decorator
creates a new class when adding `__slots__`, so `__init_subclass__`
registrations see the pre-dataclass class. Register subclasses after
the dataclass decorator runs, not inside `__init_subclass__`.

### `tuple` over `list` for immutable data

Decoded wire data is immutable by nature. `list` only when you actually
mutate it; `tuple` for fixed, returned, or decoded sequences.

### `TypedDict` for known-shape records

A dict with a fixed set of string keys is a struct, not a mapping. Use
`TypedDict`. `dict[str, Any]` for a known-shape record is a smell.

## 3. Enums, not string/byte constants

A closed set of values is an enum.

- Values that go on the wire: `class X(bytes, enum.Enum)`. Members are
  bytes, so they encode via the codec and compare as their value.
  Example: `OpType` for mutation and predicate wire tags.
- Values persisted or serialized: `StrEnum` (stable string `.value`).
- Purely in-memory result/reason enums: plain `Enum` with `auto()`.

## 4. Errors: a typed hierarchy

If you find yourself testing an error by its string message, the
distinction wants to be a type.

The hierarchy (`dude/core/errors.py` holds the root):

```
DudeError                         # catch-all
  codec.CodecError                # wire/parse errors
  StoreError                      # store-layer errors
    OpError                       # operation encoding/decoding
  SessionError                    # session-layer errors
  LinkError                       # network link errors
  RoundError                      # consensus round errors
  CLIError                        # CLI user-facing errors
```

A consumer can `except DudeError` (all), `except StoreError` (one
layer), or `except OpError` (one failure kind).

Leaves carry structured data, not string messages. Code branches on the
type (and reads attributes), never on `str(e)`.

Result-shaped outcomes are not exceptions. An expected outcome is
returned, not raised. `SettleResult` is `Settled | Pending | Unknown`,
not three exception types. `AckResult` is `Accepted | SubmitRefused`.
Exceptions are for genuine, unexpected errors.

## 5. I/O lives at the edges

The store, consensus, and data-structure layers do no I/O. They take
bytes/values and return bytes/typed-values. The transport and substrate
layers own sockets, timeouts, and threading. The session layer bridges
the two: it knows how to submit a transaction and wait for settlement,
but the actual I/O is in the substrate implementation.

A function that both encodes and sends is the smell. The codec builds
the bytes; the transport moves them.

## 6. Small things

- Line length 100; ruff formats. Don't hand-align against the formatter.
- Prefer a validating constructor at a boundary over trusting input and
  failing later. Parse, don't validate.
- Comments name the specific regression that returns silently if deleted.
  If you cannot name one, delete the comment.
