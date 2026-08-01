# dude.core.units -- primitive scalar aliases shared across the codebase.
#
# WHY THIS EXISTS. A Python `type Millis = int` alias enforces nothing at runtime and nothing at
# type-check time (int and Millis are interchangeable). But repeating the same alias in eleven
# files was worse: two nodes converging on "Millis" is one shared vocabulary; two nodes each
# redefining it is a coincidence waiting to drift. This module is the one home.
#
# WHY ONLY MILLIS. `NodeId` was also here-shaped, and we deleted it: `crypto.PublicKey` was the
# real type, `NodeId` was a synonym that only two files used while fifty use-sites elsewhere said
# `crypto.PublicKey` -- two vocabularies for one type is exactly the discipline gap the audit is
# for. Alias only when the underlying primitive is the whole story (a wall-time integer) and no
# domain layer above it is doing the work.

from __future__ import annotations

type Millis = int
"""Wall-time in milliseconds. Always a parameter -- nothing in the codebase reads a clock except
`Postman`, so every function that takes `now: Millis` is deterministic in its arguments."""
