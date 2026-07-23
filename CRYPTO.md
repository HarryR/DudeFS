# DudeFS crypto transition spec (POC → production suites)

> **Status:** design ruling (NOTES 42, as amended), 2026-07-21. Companion to
> [IMPLEMENTATION.md](IMPLEMENTATION.md) §1 (the POC choices this supersedes)
> and [DESIGN.md](DESIGN.md) §3/§16.
>
> **The one-scheme rule (Harry's ruling).** v1 ships with **exactly one**
> payload encryption scheme — there is no suite menu, no per-op or
> per-keyepoch scheme selector, and therefore no negotiation or downgrade
> surface anywhere on the wire. `auth0` was development scaffolding only (the
> system was never going to ship unencrypted); it is retired with the dev
> deployments that used it — no `auth0` ciphertext ever exists in a shipped
> log, and `b2s1`/`xcp1` are struck before ever existing. If the scheme ever
> changes, that is a **protocol-version event**: a lane-2 `pver` fence at a
> checkpoint barrier (fail-closed via `FoldHalted` — DESIGN §16 machinery,
> already built and tested) plus a key rotation. The active `pver` *determines*
> the scheme; nothing chooses at runtime. The old scheme survives only as
> legacy-decode for pre-fence retained history (DESIGN §12 declared cost (a);
> the re-anchor op is the recorded retirement path). `keyepoch` keeps meaning
> exactly what it means today — *which key* — never *which scheme*.

## 0. The decisions, in one table

| Axis | Ruling (THE scheme — internal names, not wire selectors) |
|---|---|
| Author + receipt signatures | **Ed25519, permanently for v1** — BLS12-381 DECLINED (below) |
| Payload AEAD (`xcs1`) | **XChaCha20-Poly1305-IETF with SIV-style derived nonce** (misuse-resistant in practice; below) |
| Wrap-sets (`sbx1`) | **libsodium sealed box** (X25519-XSalsa20-Poly1305, anonymous), recipient key **derived from the member's Ed25519 identity** (`crypto_sign_ed25519_pk_to_curve25519`) — one identity keypair per member, nothing new to distribute or rotate separately |
| PRF / hashing / KDF | **keyed BLAKE2b** everywhere, domain-separated via `person` (`dude.tag`, `dude.nonce`, `dude.acc` — the accumulator's hash-to-curve input) — unchanged from POC |
| Backend | **PyNaCl (libsodium; PyCA-maintained)** — the single `uv`-managed crypto dependency on top of stdlib. **No vendored oracle, no no-native lane** (NOTES 46 de-hedge): libsodium does not need our differential testing — RFC 8032 and self-generated `xcs1` golden vectors are the conformance surface; `vendor/ed25519.py` is deleted with the swap |

The internal names (`xcs1`, `sbx1`) label the constructions in code and docs;
they are **not** wire-visible selectors — the active `pver` implies them. The
genesis "suite id" field collapses to a genesis-pinned constant asserting this
scheme set (defensive versioning for TOFU bootstrap, not a menu).

Premise correction that shaped this: PyNaCl ≥ 1.5 **does** ship a first-class
AEAD with associated data — `nacl.secret.Aead` = XChaCha20-Poly1305-IETF — so
nothing is homebrewed from `box`/`secretbox`. `secretbox` (no AD) is used for
nothing; `box` appears only in its sealed form for wraps.

**Runner-up, recorded:** PyCA `cryptography` + **AES-256-GCM-SIV** (RFC 8452)
— a standards-stamped MRAE with zero AEAD composition of ours, at the cost of
a hand-rolled (HPKE-shaped) wrap construction and materially weaker Go-side
library support for GCM-SIV. Kept second for those two reasons; flipping is
cheap **before launch only** (after launch it's a pver event like any other).

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
suite xcs1 (XChaCha-SIV) — key chain per finding 21 (K_epoch is the MASTER):
  data_key    = blake2b(key=K_epoch,  person=b"dude.enc")    # THE AEAD key
  slot_secret = blake2b(key=K_epoch,  person=b"dude.slot")   # slot-tag PRF secret
  AD     = blake2b(envelope-minus-payload)                   # as today
  nk     = blake2b(key=data_key, person=b"dude.nonce")       # nonce subkey (under data_key)
  nonce  = blake2b(key=nk, data=AD ‖ blake2b(P), digest_size=24)  # SIV: covers the PLAINTEXT
  C, tag = XChaCha20-Poly1305-IETF(key=data_key, nonce, ad=AD, plaintext=P)
```
(Retagged post-finding-21 — vectors unchanged, the implementation always used
`data_key`; this block is the Rust/Go conformance reference, NOTES 54.)

**K_epoch is THE epoch secret — subkeys derive, they are not distributed
(NOTES 48, finding 21).** The keyring needs two working keys per epoch (the
data key and the slot-tag secret), but the wrap-set seals exactly ONE 32-byte
master: `data_key = blake2b(key=K_epoch, person=b"dude.enc")`, `slot_secret =
blake2b(key=K_epoch, person=b"dude.slot")` (and `nk` above). One wrap
distributes everything; rotation generates one secret; escrow holds one
secret. Wrapping the two working keys independently is REJECTED — it doubles
the distribution/rotation/escrow surface for zero gain.

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
  **Practice caveats, recorded (2026-07-21):** FROST's real-world failure
  modes are (i) round-1 **nonce state** — must be treated like key material
  (single-use, never snapshotted/restored; deterministic nonces are
  *insecure* here — an adversarial co-signer replays them against two
  binding factors and extracts the share), (ii) identifiable-abort without
  robustness (one bad share-holder griefs the session; ROAST is the
  liveness wrapper if ever needed), (iii) DKG operational complexity (or a
  trusted dealer's ceremony-time single point). The headline threshold-sig
  breaks (TSSHOCK, BitForge) were threshold-**ECDSA**, not FROST. Our
  profile is unusually favorable — an offline root signing rarely and
  SERIALLY, so concurrent-session attack surface and abort-liveness both
  shrink to ceremony hygiene. Requirements when scheduled: RFC 9591 via an
  audited library, nonce-state discipline in the tooling, an explicit
  dealer-vs-DKG decision, and a fresh CVE sweep at that date.

## 4. Migration plan — EXECUTING as the M7 swap wave (NOTES 46, option A)

One wave, before the client daemon (WP2) is built, so the keyring's first
daemon consumer lands on real crypto and the demo runs encrypted:

1. `uv add pynacl`. `crypto.SIGNER` → `nacl.signing` (RFC 8032 is
   deterministic — the signature golden vectors must not change); `xcs1` per
   §2; sealed-box wrap/unwrap with the Ed25519→X25519 conversion, and
   wrap-set bodies become REAL sealed boxes.
2. **Deletions, not relocations** (the de-hedge): `vendor/ed25519.py`,
   `auth0` and every suite remnant, and the `aead_suite` parameter threading
   through `fold`/`compact` (collapses to the constant). Tests run the real
   scheme; there is no oracle lane and no dev-crypto mode.
3. Payload golden vectors bump once (ciphertexts change op hashes). KATs: RFC
   8032 via PyNaCl, self-generated `xcs1` vectors, sealed-box roundtrip +
   wrong-recipient failure. The A4/fuzz suites now exercise real ciphertext.
4. Slot tags, hashing: unchanged (keyed/plain BLAKE2b, stdlib). The **state accumulator** is ECMH over the ed25519 prime-order subgroup (`crypto_core_ed25519_from_uniform`/`add`/`sub`, PyNaCl) — not a BLAKE2b Merkle root (ACCUMULATOR.md).
   A future scheme change is a lane-2 `pver` fence + rotation, per the
   one-scheme rule above.

## 5. What this closes and what stays open

Closed: sig suite (Ed25519, incl. the threshold path), payload AEAD (`xcs1`),
wrap primitive (`sbx1`), backend (PyNaCl + vendored oracle), the AD question
(retained, with stated reasons), BLS (declined-with-door-open), Deoxys-II
(declined-with-fallback-ids). Open, deliberately: the FROST threshold-root
ceremony details (lane-3, §16 worked example); pinned PyNaCl/libsodium minimum
versions at packaging time; whether the CI no-native lane stays mandatory
past M8.
