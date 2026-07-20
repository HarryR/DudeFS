# DudeFS — Distributed Ultra-Durable Encrypted File System (Python POC).
#
# Normative sources live alongside the code: DESIGN.md (rev 4), PROTOCOL.md,
# ARCHITECTURE.md, MANAGER.md, RESILIENCE.md, FORMAL.md. If code and documents
# disagree, the documents win (IMPLEMENTATION.md).
#
# This package is stdlib-only at runtime, plus one crypto dependency (PyNaCl /
# libsodium — the L0 backend, CRYPTO.md). Milestones M0 (codec + crypto + artifacts), M1 (the
# fold), and M2 (store + acceptor) are implemented; the quorum client, gossip,
# and daemon (M3+) are not yet.

from . import acceptor, artifacts, codec, crypto, errors, fold, store
from .errors import DudeFSError

__all__ = [
    "DudeFSError",
    "acceptor",
    "artifacts",
    "codec",
    "crypto",
    "errors",
    "fold",
    "store",
]
