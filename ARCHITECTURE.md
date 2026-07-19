# DudeFS Architecture — layers & interfaces

> **Status:** companion to [DESIGN.md](DESIGN.md) (rev 5). The protocol documents mix concerns deliberately — they are definition-first. An implementation must not. This document cuts the system into strictly-layered black boxes, states each layer's interface and determinism obligations, and gives the deployment matrix (which layers run in a node, a client, the manager tool). The load-bearing pattern is the **payload handler** (L6): predicates apply to *opaque bytes* at the coordination layer and to *decrypted content* at the fold layer, and the handler interface is where that duality lives — it is also what turns the zero-knowledge property from a promise into a build constraint.

Interfaces below are language-neutral pseudocode. The dependency rule is **strictly downward** — a layer may call only layers beneath it.

## L0 — Crypto primitives

Pure black boxes, selected by suite ids in genesis / control ops (crypto agility — DESIGN §16):

```
Signer:    sign(sk, msg) → sig · verify(pk, msg, sig) → bool        # authors: Ed25519 | secp256k1 (open, §17)
MultiSig:  sign_share(sk, msg) → share                              # nodes: v1 Ed25519 list; target BLS12-381 aggregate (DESIGN §8)
           combine(shares, signer_set) → cert
           verify(cert, msg, signer_set, roster) → bool
AEAD:      seal(k, nonce, aad, pt) → ct · open(k, nonce, aad, ct) → pt | ⊥
PRF:       tag(k, preimage) → bytes                                 # slot tags
Hash:      h(bytes) → digest                                        # content addressing
```

`MultiSig` is deliberately shaped so that a concatenated-signature-list instantiation is a drop-in for the BLS aggregate — the QC decision (DESIGN §8) is held loosely by construction.

## L1 — Artifacts & codec

The self-authenticating types — `Op`, `Receipt`, `Promise`, `QC`, `Watermark`, `Checkpoint`, `Evidence` — with canonical serialization and content addressing (`id = Hash(bytes-as-received)`). Two iron rules: **encodings are injective** (everything signed or PRF'd — FORMAL §1 assumes it), and **identity is the received bytes, never a re-serialization** (which is what makes unknown-field pass-through safe under lane-3 evolution). No state, no I/O; every artifact self-verifies given a roster view.

## L2 — Store & spread (node replication substrate)

```
ChainStore: append(op) → ok | gap | fork-evidence      # contiguity-checked (PROTOCOL §2.1)
            get(author, seq) · heads() · receipts · qcs · checkpoints · evidence
Gossip:     summary() · delta(peer_summary) · on_receive(items)
Clock:      floor() · advance(hlc)                     # max(hw, now) − δ; durable, monotone (DESIGN §9)
```

Knows nothing of slots or payloads: `slot_tag` is stored bytes, data payloads are stored ciphertext. GC obeys the checkpoint horizon. The floor and the acceptor state (L3) share one crash-consistent durability domain with the node key — sign-after-fsync (RESILIENCE §0).

## L3 — Acceptor (per-slot coordination, node-side)

```
Acceptor: on_submit(op)              → Receipt | SlotConflict(accepted) | Rejected(reason)
          on_prepare(tag, ballot)    → Promise | Nack(promised)
          on_accept(tag, ballot, op) → Receipt | Nack(promised)
```

State per tag: `(promised, accepted_ballot, accepted_op)` — the single-decree machinery of DESIGN §8. Tags are opaque; the only operation is equality. This layer plus L2's floor is the entire TLA+ surface on the node side.

## L4 — Quorum client (commitment & finality, client-side)

```
Quorum: read()                → {committed_set, frontier, floors}      # PROTOCOL §1.2
        submit(op)            → Committed(qc) | Conflict(info)         # fan-out + QC assembly
        recover(tag, seen)    → Decided(op, qc)                       # ballots, PROTOCOL §1.3.5
        await_final(hlc)      → Frontier                              # watermark collection
```

Pure orchestration over the PROTOCOL verbs; hedging policy (PROTOCOL §4) lives here. No state interpretation whatsoever.

## L5 — Fold (deterministic state derivation)

Two profiles over one engine, differing only in which L6 handlers are registered:

```
Fold(handlers):           apply(committed_set) → (state, verdicts)     # FULL profile — clients
ControlReducer(handlers): observe(op | qc | checkpoint) → control_state  # CONTROL profile — nodes
```

- The **full profile** implements DESIGN §6 exactly: total order `(hlc, author, seq, op_hash)`, per-key lineage `(version, attempt)`, tag attribution, the lineage-advance invariant. **This layer plus the data handler is the Lean oracle target** (FORMAL §2) — byte-identical across implementations or bust.
- The **control profile** is deliberately weaker: roster, cert, and checkpoint state are reachable *without* HLC ordering, because activation is by certificate observation and everything is idempotent (DESIGN §12–§13). Nodes therefore never need the fold's ordering machinery — "nodes never fold data" falls out of the build, not out of discipline.
- Crucially, L5 — not L6 — owns the lineage rules for opaque results: a handler that returns `Opaque` triggers the same deterministic tag-consumption logic (DESIGN §6) in every client. Handlers can't get this wrong because they never touch it.

## L6 — Payload handlers (the message-handler pattern)

```
PayloadHandler:
  handles:  (class, kind, pver_range)                    # selector
  decode(envelope, payload, keyring) → Message | Opaque(reason)
  evaluate(msg, view: StateView)     → {guards_result, mutations, slot_preimage?}
```

**Determinism contract:** outputs are a pure function of `(committed prefix, keyring)` — no clocks, no randomness, no I/O, no negotiation. This is the contract FORMAL A1–A7 quantify over.

The registry is the deployment knob:

| Handler | Payload | Node registers? | Client registers? |
|---|---|---|---|
| `control/roster` | plaintext | ✓ | ✓ |
| `control/cert` (issue/revoke/wrap-set) | plaintext | ✓ | ✓ |
| `control/checkpoint` | plaintext | ✓ | ✓ |
| `data/txn` (slot preimage, guards, mutations) | AEAD ciphertext | **✗ — and no keyring** | ✓ |

Consequences worth spelling out:

- **Zero-knowledge is structural.** A node build simply *contains no data handler and no keyring*: data ops are bytes to store and tags to compare, categorically. DESIGN §5's control-plane carve-out stops being prose and becomes this table.
- **Lane-2 evolution is a handler change.** A new guard predicate or transaction form (DESIGN §16) = a new handler or a widened `pver_range`, activated at a checkpoint fence. L0–L4 never hear about it.
- **The predicate duality has a home.** At L3 a predicate is an opaque tag (equality only, exclusion by refusal); at L5/L6 it is decrypted guards (truth by evaluation). Same op, two layers, two views — by interface rather than by caveat.

## L7 — API & applications

The client node packages L0–L6 as a **daemon exposing the worker API** (PROTOCOL §6: Unix socket, `GET/PUT/CAS/DEL/TXN/WATCH/STATUS`, filesystem permissions as the authorization boundary) — or as an **in-process library** on a thread/fibre with the identical interface and no socket. **Workers sit above L7 entirely**: no keys, no crypto, no quorum awareness; the consistency ladder reaches them only as `ack=`/`level=` knobs. Manager: the same stack plus privileged commands — see [MANAGER.md](MANAGER.md). Watches and any future conveniences are lane-1: strictly above this line.

## Deployment matrix

| Layer | Storage node | Client | Manager tool |
|---|---|---|---|
| L0 crypto | ✓ (receipt signing, MultiSig suite) | ✓ | ✓ (+ root key, possibly HSM) |
| L1 artifacts | ✓ | ✓ | ✓ |
| L2 store & spread | ✓ (durable, gossiping) | cache only | cache only |
| L3 acceptor | ✓ | — | — |
| L4 quorum client | — | ✓ | ✓ |
| L5 fold | control profile | full profile | full profile |
| L6 handlers | control only, **no keyring** | all + keyring | all + keyring |
| L7 API | — | KV API | admin commands |

The manager column is the client column plus a root key and extra L7 commands — the "manager is just another client" principle (DESIGN §2), now visible as a column diff. A fourth tier, the **worker**, would be a column of dashes with a single ✓ *above* L7: it consumes the worker API and contains nothing else — which is the point (PROTOCOL §6). The transport beneath every ✓ in the node/client columns is a plugin (PROTOCOL §7.1): HTTP, SSH, intermediated relays — artifacts don't care.

## Verification & swap points

- **Lean** (FORMAL A1–A7): L5 full profile + `data/txn` handler — compiled as the conformance oracle; differential-fuzz the production L5/L6 against it.
- **TLA+/Quint** (FORMAL B1–B8): L3 + L4, with L2's floor logic for B3; the wire boundary between them is the trace-validation seam.
- **Swappable black boxes:** every L0 primitive (suite ids); the transport beneath the PROTOCOL verbs; the storage engine beneath `ChainStore`. Nothing else is meant to swap.
