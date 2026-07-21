# DudeFS transport & the L_msg envelope

> **Status:** the extended rationale behind **PROTOCOL §7.5** (the normative
> statement). Owned and maintained here directly (Harry); kept consistent with the
> code — `dudefs/lmsg.py` (the envelope), `dudefs/link.py` (the connection seam),
> `dudefs/transports/` (the carriers). If code and design disagree, the design wins.
>
> **Scope:** L_msg covers the **cluster wire only** (client-daemon ↔ node,
> node ↔ node, manager ↔ node). The worker socket (CLIENT.md §1) is the one exempt
> surface — it is genuinely local, keyless, and bounded by filesystem permissions,
> so it carries no L_msg. Everywhere else, authentication is the floor.

The one-line thesis: **the transport is a dumb carrier that only promises "push a
message, get a reply — maybe"; all authentication and confidentiality live in the
*message*, never the channel.** This is the layer that gives a node a peer identity
(so the request gate can work) and gives an untrusted intermediary nothing — on TCP,
HTTPS-through-a-CDN, WebSocket, or XMPP alike.

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

Even a carrier that *does* give us a confidential, peer-authenticated link (a
`.onion`, a TLS tunnel we own) authenticates the **tunnel endpoint**, never the DUDE
identity. So we still need message authenticity on top to know *who* the peer is.
Channel security is either the wrong layer or not enough on its own.

## 1. Three layers

```
  L_msg    authenticated (± sealed) request/reply envelope   ← peer identity + the gate
  L_art    self-authenticating artifacts (ops, receipts, QCs) ← integrity
  L_txport push message → reply, maybe (unix | http | …)     ← dumb carrier, adds no trust
```

- **`L_art`** — every artifact is signed and verified at consumption.
- **`L_msg`** — `dudefs/lmsg.py`: the `Envelope`, the seal, the gate. `dudefs/link.py`
  is the one seam where L_msg meets a carrier (`Link(sk, self_pub, to_pub, endpoint)
  .request(...)`), so client, daemon, and manager share exactly one author→dial→
  verify path.
- **`L_txport`** — `dudefs/transports/`: a carrier is a dumb pipe that owns *all* the
  I/O and framing; it takes payloads (envelope bytes) and a pure handler, never a
  socket. Carriers are selected by **scheme** (`unix`, `http`, …), one registry entry
  each: `transports/unix.py`, `transports/http.py`, dispatched by `transports/__init__`.

Absence of L_msg is exactly what would make a bare `FRONTIER`/`SUBMIT` anonymous —
only the artifacts *inside* it are signed, not the request itself. L_msg signs the
request.

## 2. The envelope

No anonymous traffic — this is a tightly-controlled control plane over top-secret
config, so **every envelope is authenticated** (the gate always has a `from`). This
is the floor: a plain envelope is *signed*, even over a local unix socket (which is
only a test convenience for an inherently remote protocol). Sealing is the optional
layer on top, and whether to seal is a property of the **endpoint** (§8), never a
per-message negotiation.

**Plain (auth only)** — for a carrier that already reaches the peer confidentially
(a `.onion`, direct TLS we own, a trusted LAN):

```
{ from, to, epoch, ts, nonce, verb, body, sig }
    sig = Ed25519(from_sk, "dude.msg:" ‖ canon(from, to, epoch, ts, nonce, verb, body))
```

**Sealed (auth + confidentiality)** — for any untrusted-but-encrypted intermediary
(a CDN-fronted HTTPS endpoint, an XMPP server). **Sign-then-seal**: the fully signed
struct plus a fresh ephemeral **reply-key** are wrapped in an `sbx1` anonymous-sender
sealed box to the peer, and the outer is **always** `[to_hint, sealed]`:

```
outer: [ to_hint, sbx1_seal(to_pub, canon(inner_envelope, reply_key)) ]
inner:   the same signed { from, …, sig }        reply_key: a fresh ephemeral pubkey
```

The intermediary sees only `to_hint` + ciphertext: *"a message, to someone"* — not
who, not the verb, not the slot tags. The recipient screens the tag (§3), unseals
(only its key can), verifies the inner `sig`, then gates.

**Load-bearing fields** (both modes):

- **`to`** binds the message to one recipient, *inside the seal* — the anti-reflection
  field; without it a signed request to A is replayable to B. Non-negotiable.
- **`epoch` is diagnostic, never a hard gate.** A roster bridge always has a window
  where an activated party talks to a not-yet-activated one, so an envelope-level
  `epoch == current` refusal is the over-strict-gate (R1) class. The artifact layer
  enforces epoch where it is load-bearing (receipts, QCs, RERECEIPT), not at the door.
- **`ts` (+ optional `nonce`)** is freshness within the δ skew window. Verbs are
  idempotent and replay-protected, so a re-sent message is inert — `ts` is DoS
  hygiene, not correctness. No replay cache needed.
- **`canon(...)`** is the existing canonical bencode (IMPLEMENTATION §2), injective
  and golden-pinned. The `dude.msg:` prefix domain-separates an envelope signature
  from an op signature or a proof-of-possession.

**Replies mirror the request's mode** (always, never negotiated). A **sealed** reply
is symmetric with the request: the node seals its signed reply back to the request's
ephemeral `reply_key` and it is **also** `[to_hint, sealed]` (the tag keyed by the
reply-key), so the requester screens its own reply for one hash before opening it.
The reply-key is **required** in sealed mode — an optional reply-key would be a
downgrade lever, and a sealed request without one is malformed.

## 3. The screening tag `to_hint` — the ECDH pre-filter, always on

Every sealed packet carries `to_hint`. It is a deliberately cheap keyed-BLAKE2 tag,
checked **before** the ECDH unseal, so it is the pre-filter on *every* sealed message —
point-to-point as much as multiplexed:

```
to_hint = keyed-BLAKE2(key = target_identity, person = "dude.screen", digest = 16 bytes)(sealed)
```

- The **sender** keys on the target's identity (from the endpoint record).
- The **receiver** keys on its *own* identity and compares — **one symmetric hash, no
  ECDH.** Match → open it; miss → drop it, for the cost of that one hash.
- Over the (non-deterministic, ephemeral-sender) ciphertext, so it is **per-message
  and unlinkable** — the same (sender, recipient) pair yields a different tag each time.
- Domain-separated (`person = "dude.screen"`) so this keyed use of a pubkey can never
  be confused with any other.

So the ECDH runs only on a tag hit: junk that can't prove knowledge of the recipient
identity is dropped for one hash, never an unseal. This is a DoS floor on a *direct*
carrier, and it is exactly the mechanism a **multiplexed** carrier (a relay, an XMPP
MUC, a shared mailbox — a future additive carrier, not a mode) would reuse to pick its
own inbound out of a firehose; the reply's own `to_hint` gives the same O(1) filtering
in reverse. Nothing about the envelope changes when a multiplexed carrier arrives.

**Identity-keyed, deliberately NOT epoch-keyed.** An epoch-scoped screening key would
deadlock a from-scratch sync — you can't screen the very messages that would deliver
the epoch key. A node always holds its own long-term identity, so it screens from
message zero. Node keys rotate cheaply if ever needed.

**What rests on roster secrecy — precisely the free-drop rung and tag unlinkability,
nothing more.** Admission (the gate) and data confidentiality (`xcs1`) never depend on
it. Roster-secrecy-from-outsiders is a **best-effort posture**, not an invariant:
membership lives in the control-plane log, distributed to members over authenticated
(and where needed sealed) channels, so an outsider can't cheaply enumerate identities
to label tags — it sees pseudorandom, unlinkable tags. **If the roster leaks the
degradation is graceful and bounded:** an observer gains tag-labelling (traffic
analysis a network-positioned adversary largely has anyway, §7) — never entry, never
data. (The "public roster *slot*" — `h("roster"‖epoch)` — is a coordination tag,
unrelated to the secrecy of membership *contents*.)

## 4. The cost ladder (each rung matches an adversary)

- **Never-members (internet noise / DoS):** cannot produce a valid `to_hint` (they
  know no node identity) → **free-dropped at the hash rung**, zero ECDH spent.
- **A blocked / ex node (pre-rekey):** *can* forge a tag and a sealed box to a
  survivor → climbs to the **ECDH rung** (unseal) and dies at the **gate**
  (`from` ∉ current roster). It spends our ECDH per probe and gets nothing; a survivor
  re-key demotes it back to free-drop.
- **Current members:** pass all rungs and are served.

The cheap always-on tag exists precisely so random internet traffic costs one
symmetric hash, not an ECDH.

## 5. The request gate — L_msg's first consumer

On inbound, before any store work:

1. if the endpoint is `sealed`: **screen the `to_hint`** (one hash) and drop on a
   miss; then unseal. If `plain`: decode the envelope.
2. verify `sig` by `from`;
3. check `to == self`, and `ts` fresh (`epoch` is diagnostic — not gated here, §2);
4. **check `from` against the live control-plane view** — current roster member /
   un-revoked cert. *The gate.*
5. dispatch to acceptor / gossip; sign (and, on a sealed endpoint, seal) the reply.

Steps 1–4 reject at the door — revoked/non-member callers never reach the fold. The
gate authorizes the **requester**, never an artifact's author, so it never blocks an
authorized proposer carrying a since-revoked author's op through recovery. There are
**no anonymous reads**: every verb has a `from`; the gate policy may vary by verb
(a node gossips, a certed client writes, root drives) but authentication does not.

**Say-why refusals.** A refusal is served *only* to a sender that already holds our
identity — a valid sig over `to == self`. That signed refusal names the specific door
check it failed (`NOT_A_MEMBER`, `STALE_ENVELOPE`), not a generic `BAD_AUTHZ`, and it
leaks nothing new. A sender that has *not* proven it holds our identity (bad sig,
wrong recipient, un-openable seal) gets **silence** — the carrier's native "nothing"
(a closed frame / no stanza / an HTTP 404) — so a reply never leaks our pubkey to a
party that didn't already have it.

## 6. Defence in depth — structural vs application data

The gate and the seal protect *the door and the metadata*. The **application values**
are independently protected by the group *data* key (`xcs1`, DESIGN §7). So even a
party that somehow retains structural visibility (the linkage graph, slot tags) still
cannot read values, and — because the data key rotates on eviction — an ex-member's
structural knowledge never becomes a data compromise. The layers fail **independently**:
tag/gate for admission, sealed envelope for metadata, data key for contents.

## 7. Eviction & the survivor-rekey boundary (stated, not engineered around)

Eviction blocks a node (the gate refuses it), cuts it off from new updates (the
control plane no longer reaches it), and forces it to the ECDH rung where it dies. It
still knows the *surviving* nodes' identities, so a **network-positioned** ex-member
could label `to_hint`s for survivors — a compound adversary (ex-member **and** tapping
the wire) whose network position already yields sizes/timing/hop traffic analysis that
dominates a target-tag anyway.

**The boundary, pinned so nobody later assumes more:** rotating the *evicted* node's
key buys nothing here (it's gone, not rotated). Fully stripping an ex-member's
tag-labelling requires a **survivor re-key** (rotate the surviving nodes' identities).
That is a *planned* operation, cheap at cluster scale (≤ 1 h, less with automation) —
"recovery is never urgent / the ejected are owed nothing" means it's a lever you pull,
not a constraint to design around. Network-layer unlinkability (cover traffic, Tor
circuits) stays the carrier's job; L_msg does not try to out-Tor Tor with a routing tag.

## 8. Endpoints carry the profile

Reachability is a control-plane **ENDPOINT record** — a manager-signed op mapping
`node_id → [(transport, uri, opts), …]` (PROTOCOL §7.1). The AE profile is a
server-side property of the endpoint: it expects exactly one message shape and rejects
everything else, so misconfiguration has nothing to mis-negotiate. Because the record
is manager-signed, a hostile intermediary can't downgrade `sealed → plain`.

```
endpoint(node_id) = [
  (http, "http://cf-proxy/dude",   { lmsg: sealed }),   ← CF sees ciphertext only
  (unix, "/run/node.sock",         { }),                ← trusted local carrier, plain
  (xmpp, "xmpp:node@server/dude",  { lmsg: sealed }),   ← federation server is the intermediary (future)
]
```

Internally an address is a decomposed **struct**, never a re-parsed string:
`transports.Endpoint(transport, uri, sealed)`. An operator supplies a single
self-describing URL (a custom composite scheme is the input ergonomic — one URL
instead of a flag pile, e.g. `sealed+http://host/dude`), which
`transports.parse_endpoint` decomposes **once** at the CLI edge into that struct; the
struct is what the record and the dial carry. `Link` reads `Endpoint.sealed` to decide
plain vs sealed and `Endpoint.transport` to pick the carrier — one `Link`, all
combinations.

**Everyone dials the same way.** Nodes derive gossip peers, clients derive
`roster_addrs`, and the **manager** dials the roster over these same records — the
control plane *is* the peer registry (the manager keeps a JSON summary of the
decomposed Endpoints so an admin command never re-folds the log). Multi-homing is just
a list; **Smart-Gorilla failover** is dialing the next entry when one path is denied —
still authenticated, still with the profile its carrier warrants.

## 9. Status & what's future

**Built (as of this writing):** the plain + sealed envelope, the always-on `to_hint`
pre-filter, the requester gate with say-why refusals, `Link`, the `transports/`
registry with `unix` + `http` carriers, `Endpoint` + composite-scheme input, and the
manager dialing over roster endpoints. unix/http × plain/sealed all work through one
`Link` and one `serve`.

**Future, additive:** a **multiplexed** carrier (relay / XMPP MUC / mailbox) is a new
`transports/*.py` entry whose server subscribes a shared channel and uses the *same*
`to_hint` to pick its inbound — no change to `lmsg`, `Link`, or the gate. Everything
today is point-to-point, deliberately.
