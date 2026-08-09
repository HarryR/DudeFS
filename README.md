# DudeFS — Python proof of concept

DudeFS is a **distributed, authenticated, encrypted coordination store** — a
durable, provenance-carrying `etcd` for a small trust group. State is never
stored, only derived: every client folds the same signed log into byte-identical
state. CAS is decided by per-contention-point Paxos on PRF-opaque tags, so the
storage nodes that arbitrate a write **can never read a key or value** — payloads
are XChaCha20-Poly1305 ciphertext and slot tags are keyed-BLAKE2 opaque — and
every misbehavior below the root of trust mints portable cryptographic evidence.

**Built for:** small, precious, contested state on semi-trusted machines — a few
writers, kilobytes of config/locks/claims, 3–7 rented-or-borrowed nodes, audit
over throughput. **Not for:** write concurrency, big values, low-latency
visibility (finality waits on the skew window δ), or availability-over-durability
(a minority partition blocks; that is the point).

## Developer toolchain (`make`)

Self-contained under the project — nothing installs to your system. `make install`
bootstraps a project-local `uv` (into `./.uv`) and a `./.venv` with **ruff** (lint
+ format), **ty** (typecheck), and **PyNaCl**:

```
make install      # one time
make check        # ruff lint + format-check + ty + tests  (the CI gate; keep it green)
make lint | format | typecheck | test
make clean        # remove .venv + caches   (distclean also removes .uv)
```

Code style: [PYTHON-CODESTYLE.md](PYTHON-CODESTYLE.md) — strict typing, enums over
constants, typed error hierarchy, docstrings citing SPEC anchors.
