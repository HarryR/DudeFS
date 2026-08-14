# LightClient inflight unification

## Problem

Three dictionaries track in-flight state: `_pending_bootstrap_mids` (mid → peer),
`_pending_reads` (mid → _PendingRead), and `_bootstrap_peers` (peer → corroboration
state). The expiry loop in `tick()` only knows about `_pending_reads`, so expired
bootstrap messages leave stale entries in `_pending_bootstrap_mids` forever.
`_retry_bootstrap` mints fresh mids every `poll_interval` without cleaning up the old
ones, so a client stuck in BOOTSTRAPPING accumulates entries without bound.

A separate `_bootstrap_retry_at` timer drives re-asks. It exists because TTL used to be
one value for every conversation; `ttl_lite` is now block_time + clock_skew, which lands
at the cadence the client wants — so the request's own expiry replaces the timer.

`poll()` lives on LightClient, but the client should support more than GET — at minimum
SUBMIT. `poll()` tied to the client forces every new operation through one method that
has to distinguish result types. The handle should own the poll.

## Design

### _Inflight: one dict, one entry type

```python
@dataclass(slots=True)
class _Inflight:
    peer: crypto.PublicKey
    result: Any | None = None
```

`_inflight: dict[bytes, _Inflight]` maps mid → entry for ALL in-flight messages (bootstrap,
read, submit, future verbs). Bootstrap requests are distinguished by a flag or a subtype;
operation-specific state lives in a frozen payload dataclass:

```python
@dataclass(frozen=True, slots=True)
class _ReadOp:
    store_id: int
    name: bytes

@dataclass(frozen=True, slots=True)
class _SubmitOp:
    op_hash: crypto.Digest
```

`_bootstrap_peers` stays — it's corroboration state that accumulates across retries, not
in-flight tracking.

### RequestHandle: poll moves off LightClient

`request_get` (and future `submit`) returns a handle, not a raw mid:

```python
class RequestHandle:
    def __init__(self, mid: bytes, inflight: dict[bytes, _Inflight]):
        self._mid = mid
        self._inflight = inflight

    def poll(self) -> GetResult | SubmitResult | Failed | _Pending:
        entry = self._inflight.get(self._mid)
        if entry is None:
            raise LightClientError(...)
        if entry.result is None:
            return PENDING
        result = entry.result
        del self._inflight[self._mid]
        return result
```

Every operation returns the same handle. The caller doesn't need to know whether they're
polling a read or a submit — the result type tells them. `LightClient.poll()` goes away.

### receive: one lookup, isinstance dispatch

```python
reply_to = env.env.reply_to
req = self._inflight.get(reply_to)
if req is None:
    return
if isinstance(req, _BootstrapRequest):
    del self._inflight[reply_to]
    try:
        self._on_bootstrap_reply(req.peer, msg, now)
    except DudeError:
        self._bootstrap_peers.pop(req.peer, None)
    return
# All non-bootstrap replies: dispatch on the wire verb (PROOF_REPLY,
# ACCEPTED, REFUSED), not the inflight entry type. The entry is where the
# result lands, not what decides the dispatch.
try:
    self._on_reply(req, msg, now)
except DudeError as e:
    req.result = Failed(reason=f"responder reply refused: {e}")
```

### tick: expiry-driven bootstrap retry replaces _retry_bootstrap

```python
expired = self.postman.tick(now)
for e in expired:
    req = self._inflight.get(e.mid)
    if isinstance(req, _BootstrapRequest):
        del self._inflight[e.mid]
    elif req is not None:
        req.result = Failed(reason="request expired")

if self.state is State.BOOTSTRAPPING:
    inflight_peers = {
        r.peer for r in self._inflight.values()
        if isinstance(r, _BootstrapRequest)
    }
    stale = [
        peer for peer, entry in self._bootstrap_peers.items()
        if peer not in inflight_peers
        and (entry.anchors_reply is None
             or chain.is_stale(entry.anchors_reply.head.block.bucket, now, self.tunables))
    ]
    if stale:
        self._ask_for_anchors(stale, now)
```

Re-ask fires when a peer has no in-flight request AND no fresh reply. The new message has
TTL = `ttl_lite`, so the next re-ask happens when that message expires. Cadence = TTL,
no separate timer.

## What gets deleted

- `_pending_reads` dict
- `_pending_bootstrap_mids` dict
- `_bootstrap_retry_at` field
- `_retry_bootstrap` method
- `LightClient.poll()` (replaced by `RequestHandle.poll()`)

## What stays unchanged

- `_bootstrap_peers` (corroboration state, not in-flight tracking)
- `_on_bootstrap_reply`, `_check_bootstrap_convergence`, `_promote_to_ready`
- `_advance_head`
- `_bind_session`, `_run`, `start`, `stop`
- All verify helpers

## Staging

The inflight unification can land independently. The handle extraction can land with it
or when `submit` arrives — there's no rework. The internal dict, the expiry loop, and the
bootstrap re-ask logic are identical either way.
