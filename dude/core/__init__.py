# dude.core — the foundation: canonical encoding, cryptography, the error tree, crash-only.
#
# Nothing here knows about logs, stores, batches or consensus. Everything above depends on it and it
# depends on nothing above, which is what keeps it re-usable and testable in isolation.
