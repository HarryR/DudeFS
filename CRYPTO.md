# DudeFS crypto transition spec (POC → production suites)

> **Status:** design ruling (NOTES 42), 2026-07-21. Companion to
> [IMPLEMENTATION.md](IMPLEMENTATION.md) §1 (the POC choices this supersedes for
> production) and [DESIGN.md](DESIGN.md) §3/§16. Migration mechanics are already
> designed: **suites are per-`keyepoch`, so every transition here is a key
> rotation** (DESIGN §16) — nothing below needs new protocol machinery. Old-suite
> history stays decodable forever (retained winners never re-encrypt — DESIGN §12
> declared cost (a)).

## 0. The decisions, in one table

| Axis | Ruling | Suite id |
|---|---|---|
| Author + receipt signatures | **Ed25519, permanently for v1** — BLS12-381 DECLINED (below) | `ed25519` (unchanged) |
| Payload AEAD | **XChaCha20-Poly1305-IETF with SIV-style derived nonce** (misuse-resistant in practice; below) | `xcs1` |
| Wrap-sets (key distribution) | **libsodium sealed box** (X25519-XSalsa20-Poly1305, anonymous), recipient key **derived from the member's Ed25519 identity** (`crypto_sign_ed25519_pk_to_curve25519`) — one identity keypair per member, nothing new to distribute or rotate separately | `sbx1` |
| PRF / hashing / KDF | **keyed BLAKE2b** everywhere, domain-separated via `person` (`dude.tag`, `dude.nonce`, `dude.mac`, merkle domains) — unchanged from POC | — |
| Backend | **PyNaCl (libsodium; PyCA-maintained)** for production; the **vendored pure-Python RFC 8032 / auth0 code is retained as the differential-test oracle** (CI keeps a no-native-deps lane; property tests cross-check backends byte-for-byte) | — |

Premise correction that shaped this: PyNaCl ≥ 1.5 **does** ship a first-class
AEAD with associated data — `nacl.secret.Aead` = XChaCha20-Poly1305-IETF — so
nothing is homebrewed from `box`/`secretbox`. `secretbox` (no AD) is used for
nothing; `box` appears only in its sealed form for wraps.

## 1. BLS12-381: declined for v1 (door held open)

The case for BLS was receipt/QC aggregation. Three things ate it:

1. **Rev-6 compaction already ate the receipt problem.** Below-cut receipts and
   QCs are GC'd wholesale (DESIGN §12) — the checkpoint's `retained` commitment
   replaces them — so the steady-state QC population is the dense tail only.
   BLS would compress kilobytes, once.
2. **The scale doesn't ask for it.** n ≤ 7 ⇒ a QC is ≤ 4 × 64 B sigs + bitmap
   ≈ 300 B, on artifacts minted at config-store write rates. The §18 dial
   ledger puts gossip cost in envelopes, not QCs.
3. **The threshold-root path does not need pairings.** The recorded §16
   hardening (threshold manager key) is reachable as **FROST threshold Ed25519
   (RFC 9591)** — verifiers see an ordinary `ed25519` signature; the wire
   format and every verifier stay unchanged. Declining BLS forecloses nothing.

Against those gains: proof-of-possession ceremony + rogue-key surface, pairing
verification cost, and a second native dependency with much weaker Python
support (blst bindings or unacceptably-slow py_ecc). Harry's type-3 pairing
familiarity and the solid Rust/Go libraries are acknowledged and recorded —
the **genesis suite id keeps `bls12-381` reserved** as a lane-3 upgrade if a
future deployment (bigger rosters, cross-org verification) changes the math.

## 2. The AEAD question, answered precisely

**Is associated data necessary here?** Strictly: no — the author's Ed25519
signature covers the whole envelope *including* the payload ciphertext
(DESIGN §5), so payload↔envelope binding does not depend on the AEAD. AD is
**retained anyway**, as `AD = H(envelope-minus-payload)` (unchanged), for three
reasons, all cheap: (1) **fail-closed ordering** — an implementation that
decrypts before verifying signatures (bootstrap batch paths) still fails loudly
on a transplanted ciphertext; (2) AD is the **nonce-derivation input** (below);
(3) cross-context decryption fails at the AEAD layer with no signature check in
sight. "Derive a per-message key from the AD and use a zero nonce" (the
libsodium-KDF pattern) was considered and REJECTED — it has the same footgun
the nonce path has (next paragraph) without solving anything AD-as-AAD doesn't.

**Why misuse resistance is load-bearing here, not a nicety.** Our nonces are
deterministic (derived, not random — the kernel is deterministic by design).
A naive `nonce = H(AD)` is unique for honest authors (AD contains
`author‖seq‖hlc`)… but an **equivocating or crash-retrying author can emit two
different payloads under one header** — same key, same nonce, two plaintexts:
keystream reuse, the classic stream-AEAD catastrophe. This is exactly the MRAE
failure class Harry flagged (and why Deoxys-II appealed). The fix costs one
hash:

```
suite xcs1 (XChaCha-SIV):
  AD     = blake2b(envelope-minus-payload)                      # as today
  nk     = blake2b(key=K_epoch, person=b"dude.nonce")           # nonce subkey
  nonce  = blake2b(key=nk, data=AD ‖ blake2b(P), digest_size=24)  # SIV: covers the PLAINTEXT
  C, tag = XChaCha20-Poly1305-IETF(key=K_epoch, nonce, ad=AD, plaintext=P)
```

With the plaintext folded into the nonce, reuse is structurally impossible:
two payloads under one header get independent nonces. Residual leakage is the
standard MRAE bound — determinism (identical `(key, header, plaintext)` ⇒
identical ciphertext) — unreachable for honest envelopes (unique `(author,
seq)`) and harmless if reached. Key-commitment was examined and is not
load-bearing: the envelope's `keyepoch` field rides inside AD, and all honest
holders of an epoch share one key, so no ciphertext is ever opened under two
candidate keys.

**Deoxys-II: declined, with respect.** It is the right *shape* (true MRAE,
proven in production at Oasis) and both target languages have implementations
(RustCrypto `deoxys`, Oasis's Go port) — but Python support is thin, it would
be our second crypto backend, and `xcs1` obtains the same misuse class from
one boring, everywhere-audited primitive. Recorded fallbacks if a
standards-stamped MRAE is ever demanded: `AES-SIV` (RFC 5297) or
`AES-GCM-SIV` via PyCA `cryptography` — or `dxy2` as a suite id. All are one
keyepoch bump away, by construction.

## 3. Target-language parity (the Rust/Go check)

- **XChaCha20-Poly1305-IETF:** Rust `chacha20poly1305` (RustCrypto, audited) —
  `XChaCha20Poly1305`; Go `golang.org/x/crypto/chacha20poly1305` — `NewX`. ✓
- **Sealed box:** Rust `crypto_box` crate; Go `x/crypto/nacl/box` (the
  anonymous-sender construction is ephemeral-key + box, ~10 lines). ✓
- **Ed25519→X25519 conversion:** standard libsodium function; both ecosystems
  have it (`ed25519-dalek`/`x25519-dalek`, `filippo.io/edwards25519`). ✓
- **FROST (future threshold root):** Rust `frost-ed25519` (Zcash Foundation);
  Go implementations exist and mature. Not v1 code; recorded path only.

## 4. Migration plan (all existing machinery)

1. Land the PyNaCl backend behind the existing L0 `Signer`/`AEAD` boundary;
   the vendored implementations become the differential oracle (a CI lane runs
   the suite on both; artifacts must be byte-identical).
2. Introduce `xcs1` + `sbx1` as suite ids; **enabling them is a `keyepoch`
   rotation** (rotate op + wrap-set, PROTOCOL §3.3) — the encryption-later
   staging (`auth0` → real confidentiality) that IMPLEMENTATION §1 already
   promises, now with a named production suite instead of `b2s1`.
3. `auth0` (and any `b2s1` history, if ever minted) remains decodable forever;
   the `dude status` zero-knowledge banner clears only when the active
   keyepoch's suite is `xcs1`.
4. Slot tags, state roots, op hashes: unchanged (keyed/plain BLAKE2b) — no
   artifact format changes anywhere in this transition.

## 5. What this closes and what stays open

Closed: sig suite (Ed25519, incl. the threshold path), payload AEAD (`xcs1`),
wrap primitive (`sbx1`), backend (PyNaCl + vendored oracle), the AD question
(retained, with stated reasons), BLS (declined-with-door-open), Deoxys-II
(declined-with-fallback-ids). Open, deliberately: the FROST threshold-root
ceremony details (lane-3, §16 worked example); pinned PyNaCl/libsodium minimum
versions at packaging time; whether the CI no-native lane stays mandatory
past M8.
