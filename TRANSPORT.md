# DudeFS transport & the L_msg envelope

> **Status:** RATIFIED AS AMENDED (Fable, 2026-07-21 — NOTES 59; amendments
> inline, marked ⟦F⟧). Normative under ARCHITECTURE / PROTOCOL §7 (transports,
> endpoints, discovery, relay). If code and this design disagree, the design
> wins. **Scope ⟦F⟧: L_msg covers the CLUSTER wire only** (client-daemon ↔ node,
> node ↔ node, manager ↔ node). The worker socket is exempt — filesystem
> permissions are its entire boundary and workers hold no keys, so they cannot
> sign envelopes (CLIENT.md §1).

The one-line thesis: **the transport is a dumb carrier that only promises "push a
message, get a reply — maybe"; all authentication and confidentiality live in the
*message*, never the channel.** This is the layer that gives the node a peer
identity (so the request gate can work) and gives an untrusted intermediary
nothing — on TCP, HTTPS-through-a-CDN, WebSocket, or XMPP alike.

## 0. Why not "just add Noise / TLS"

Noise and TLS secure a **stream to whoever terminates it**. Half of DudeFS's
candidate carriers aren't streams we terminate:

- **Message-oriented, not a stream** — a WebSocket frame, an HTTP request/response,
  an XMPP stanza. No bidirectional byte stream to run a handshake over.
- **No session** (PROTOCOL §7: "no session state to keep alive"), no ordering
  across calls, no reliability — the "…maybe" is load-bearing.
- **Intermediated, and not-our-TLS** — XMPP rides a server we don't run; HTTPS may
  terminate at Cloudflare. Any channel confidentiality protects the hop to the
  *intermediary*, not the peer. So a channel handshake authenticates "the stream to
  the proxy" — which is **not** "this request came from node X", the one fact the
  membership gate needs.

So channel security is the wrong layer: it can't run on the message carriers, and
where it runs it authenticates the wrong endpoint.

## 1. Three layers

```
  L_msg    authenticated (+ optionally sealed) request/reply envelope   ← peer identity + the gate
  L_art    self-authenticating artifacts (ops, receipts, QCs, …)        ← integrity (already built)
  L_txport push message → reply, maybe   (TCP | HTTPS | WS | XMPP | …)  ← dumb carrier, adds no trust
```

`L_art` exists today (every artifact is signed, verified at consumption).
`L_txport` today is one carrier (a unix socket). **`L_msg` is the missing layer** —
and its absence is exactly why there is no peer identity and no request gate: a
bare `FRONTIER`/`SUBMIT` request is anonymous; only the artifacts *inside* it are
signed, not the request itself.

## 2. The envelope

No anonymous traffic — this is a tightly-controlled control plane over top-secret
config, so **every envelope is authenticated** (the gate always has a `from`). The
carrier's own guarantees decide whether we *also* seal, and that choice is a
property of the **endpoint** (§7), not a per-message negotiation.

**Mode `plain` (auth only)** — for carriers that already reach the peer
confidentially (Tor `.onion`, direct TLS we own, trusted LAN):

```
{ from, to, epoch, ts, nonce, verb, body, sig }
    sig = Ed25519(from_sk, canon(from, to, epoch, ts, nonce, verb, body))
```

**Mode `sealed` (auth + confidentiality)** — for any untrusted-but-encrypted
intermediary (Cloudflare-fronted HTTPS, an XMPP server):

```
outer: { to_hint, sbx1_seal(to_pub, inner) }
inner: { from, to, epoch, ts, nonce, verb, body, sig }   ← the same signed struct
```

**Sign-then-seal**, and the sender identity + signature live *inside* the seal.
`sbx1` is an anonymous-sender sealed box (ephemeral key), so the intermediary sees
only `to_hint` + ciphertext: **"a message, to someone"** — not who, not the verb,
not the slot tags. The recipient unseals (only its key can), verifies the inner
`sig`, then gates. Reuses exactly the L0 primitives already present: `SIGNER` +
`sbx1`.

**Load-bearing fields** (both modes):

- **`to`** — binds the message to one recipient, *inside the seal*. Without it a
  signed request to node A is replayable/reflectable to node B. Non-negotiable.
- **`epoch`** — **diagnostic, never a hard gate ⟦F⟧**: a roster bridge always has
  a window where an activated party talks to a not-yet-activated one; hard
  envelope-level `epoch == current` refusal is the R1 over-strict-gate class.
  The artifact layer already enforces epoch where it is load-bearing (receipts,
  QCs, RERECEIPT). The gate tolerates the bridge window; false-rejection pair
  required (IMPLEMENTATION §6.5).
- **`ts` (+ optional `nonce`)** — freshness within the δ skew window. Verbs are
  idempotent and replay-protected (verified per verb, NOTES 59), so a re-sent
  message is **inert**; `ts` is DoS hygiene, not correctness. No replay cache
  needed for correctness.
- **`canon(...)` ⟦F⟧ = the existing canonical bencode** (IMPLEMENTATION §2) —
  injective and already golden-pinned; no new encoding exists for L_msg.

**Replies** mirror the request's mode (an endpoint property — **always-mirror,
never negotiated ⟦F⟧**). Artifact *content* (FrontierBundle, Receipt) is already
`L_art`-signed; the reply *envelope* is signed by the node. For a **sealed**
reply, the requester puts a fresh ephemeral reply-key *inside* the sealed
request — **REQUIRED in sealed mode, not opt-in ⟦F⟧** (an optional field is a
downgrade lever; a sealed request without a reply-key is malformed) — and the
node seals the reply back to it: confidential both ways, still no session.

## 3. The screening tag `to_hint` — identity-keyed, for multiplexed carriers

`to_hint` exists only to let a node cheaply screen *its own* inbound on a carrier
that **multiplexes several nodes onto one channel** (a relay, an XMPP MUC, a shared
mailbox). On a **direct** carrier the transport already delivers to the right node —
**no `to_hint`** (and `to` stays inside the seal).

```
to_hint = keyed-BLAKE2(key = target_node_identity, person = "dude.screen", H(sealed))
```

- **Sender** keys on the target's identity (from the roster/endpoint record).
- **Receiver** keys on its *own* identity to test a match — **one symmetric hash,
  no ECDH.**
- Domain-separated (`person="dude.screen"`) so the identity-as-screening-key can
  never be confused with any other keyed use of that pubkey.

**What rests on roster secrecy — precisely the FREE-DROP rung and tag
unlinkability, nothing more ⟦F⟧.** Admission (the gate) and data confidentiality
(`xcs1`) do NOT depend on it. Roster-secrecy-from-outsiders is a **best-effort
posture**, not an invariant: membership lives in the control-plane log,
distributed to members over authenticated (and where needed, sealed) channels,
so an outsider cannot cheaply enumerate identities to label tags — it sees
pseudorandom, per-message, unlinkable tags. **If the roster leaks, the
degradation is graceful and bounded**: an observer gains tag-labelling (traffic
analysis a network-positioned adversary largely has anyway, §7) — never entry,
never data. The prior record stands: control-plane metadata is inside the
declared leakage boundary *for members* (DESIGN §7); this section narrows only
what the *network* sees. (The "public roster *slot*" — `H("roster"‖epoch)` — is
a coordination tag, unrelated to the secrecy of membership **contents**.)

**Identity-keyed, deliberately NOT epoch-keyed.** An epoch-scoped screening key
deadlocks a from-scratch sync — you can't screen the very messages that would
deliver you the epoch key. A node always holds its *own* long-term identity, so it
can screen from message zero, before any group key. Node keys rotate cheaply if
ever needed.

Trial-decryption (attempt `sbx1` open on each message; the AEAD tag is the screen)
remains the fallback and is perfectly confidential; at n ≈ 3–7 it is cheap. The tag
is the optimization that avoids the ECDH on a heavily-multiplexed channel.

## 4. The cost ladder (each rung matches an adversary)

- **Never-members (internet noise / DoS):** cannot produce a valid `to_hint` (they
  know no node identity) → **free drop** at the HMAC rung, zero crypto spent.
- **A blocked / ex node (pre-rekey):** *can* forge a tag and a sealed box to a
  survivor → climbs to the **ECDH rung** (unseal) and dies at the **gate**
  (`from` ∉ current roster). It spends our ECDH per probe and gets nothing; a
  survivor re-key demotes it back to free-drop.
- **Current members:** pass all rungs and are served.

The cheap tag exists precisely so random internet traffic costs one symmetric hash,
not an ECDH.

## 5. The request gate — L_msg's first consumer

On inbound, before any store work:

1. unseal if the endpoint is `sealed` (else read `plain`);
2. verify `sig` by `from`;
3. check `to == self`, `ts` fresh, `epoch == current`;
4. **check `from` against the live control-plane view** — current roster member /
   un-revoked cert. *The gate.*
5. dispatch to acceptor / gossip.

Steps 1–4 are cheap and reject at the door — revoked/non-member callers never reach
the fold. There are **no anonymous reads**: every verb has a `from`; the gate policy
may vary by verb but authentication does not.

## 6. Defence in depth — structural vs application data

The gate and the seal protect *the door and the metadata*. The **application values**
are independently protected by the group *data* key (`xcs1`, DESIGN §7). So even a
party that somehow retains structural visibility (the linkage graph, slot tags) still
cannot read values, and — because the data key rotates on eviction — an ex-member's
structural knowledge never becomes a data compromise. The layers fail
**independently**: tag/gate for admission, sealed envelope for metadata, data key for
contents.

## 7. Eviction & the survivor-rekey boundary (stated, not engineered around)

Eviction blocks a node (gate refuses it), cuts it off from new updates (control
plane no longer reaches it), and forces it to the ECDH rung where it dies. It still
knows the *surviving* nodes' identities, so a **network-positioned** ex-member could
label `to_hint`s for survivors — a compound adversary (ex-member **and** tapping the
wire), whose network position already yields sizes/timing/hop traffic analysis that
dominates a target-tag anyway.

**The boundary, pinned so nobody later assumes more:** rotating the *evicted* node's
key buys nothing here (it's gone, not rotated). Fully stripping an ex-member's
tag-labelling requires a **survivor re-key** (rotate the surviving nodes'
identities). That is a *planned* operation, cheap at cluster scale (≤ 1 h, less with
automation) — "recovery is never urgent / the ejected are owed nothing" means it's a
lever you pull, not a constraint to design around. Network-layer unlinkability
(cover traffic, Tor circuits) stays the carrier's job; L_msg does not try to
out-Tor Tor with a routing tag.

## 8. Endpoints carry the profile (ties to NOTES 58)

The AE profile is a **server-side property of the endpoint**, not negotiated: an
endpoint expects exactly one message shape and rejects everything else, so
misconfiguration has nothing to mis-negotiate. Multi-homing is a list of endpoints,
each with the profile its carrier warrants; the **manager signs the endpoint
record**, so a hostile intermediary can't downgrade `sealed → plain`.

```
endpoint(node_id) = [
  (https, "https://cf-proxy/dude",  { lmsg: sealed }),   ← CF sees ciphertext only
  (tor,   "http://…​.onion/dude",    { lmsg: plain  }),   ← Tor gives peer-confidentiality + unlinkability
  (xmpp,  "xmpp:node@server/dude",  { lmsg: sealed }),   ← federation server is the intermediary
]
```

**Smart-Gorilla failover** is exactly this list: a targeted adversary denies one
path → dial another, still authenticated, still confidential, profile chosen for
that carrier. This is the "add TCP / multi-home" step done right — the request gate
is *the first consumer of L_msg*, so "refuse revoked/non-members at the door" falls
out of "the door now knows who is knocking", on every transport, without ever
assuming a stream or owning the TLS.

## 9. Open items for Fable

- Ratify the layer split and the plain/sealed envelope as PROTOCOL §7 normative
  text; fix the canonical `canon(...)` encoding for `sig`.
- Rule the `dude.screen` tag: identity-keyed (agreed) — confirm the person string
  and that it is emitted **only** on multiplexed endpoints.
- Confirm the reply-key mechanism for sealed replies (opt-in via a reply-key inside
  the request, vs always-mirror).
- Where L_msg meets the existing NOTES-58 wave: the gate, endpoint records, on-node
  keygen + PoP, and joint-cert activation are the *consumers*; this doc is the
  substrate they share.
