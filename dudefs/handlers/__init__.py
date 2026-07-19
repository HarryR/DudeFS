# DudeFS L6 — payload handlers (the message-handler pattern, ARCHITECTURE L6).
#
# A predicate is an opaque tag at L3 (equality only) and decrypted guards at
# L5/L6 (truth by evaluation). The handler interface is where that duality
# lives. Determinism contract: outputs are a pure function of
# (committed prefix, keyring) — no clocks, no randomness, no I/O.
#
#   data/txn  (AEAD ciphertext) — clients only; needs the keyring.
#   control/* (plaintext)       — nodes and clients; no keyring.
