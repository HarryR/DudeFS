# DudeFS

A distributed, authenticated, encrypted coordination store. A durable
key-value layer for a small trust group where the storage nodes that
arbitrate writes do not need access to keys or values.

State is deterministically derived: every participant folds the same
signed log into byte-identical state. Contention is resolved by
quorum consensus on PRF-opaque slot tags (keyed-BLAKE2), payloads are
XChaCha20-Poly1305 ciphertext, and misbehaviour below the root of
trust produces portable cryptographic evidence.

Built for small, precious, contested state on semi-trusted machines.
A few writers, kilobytes of config and locks and claims, 3 to 7
rented-or-borrowed nodes, audit over throughput. Not for write
concurrency, large values, low-latency visibility, or
availability-over-durability (a minority partition blocks; that is
the point).

## Architecture

Five roles cooperate to run a cluster:

- Anchor: the root of trust. Generates the genesis block and issues
  grants (certificates) to all other roles. Offline after provisioning.
- Node: a consensus participant. Nodes run quorum rounds, settle
  transactions, replicate state, and serve reads. A cluster needs 2f+1
  nodes to tolerate f failures.
- Manager: authors roster changes, key rotations, and grants. Drives
  control operations through the consensus layer via the real joint-cert
  flow.
- Client: a light client that syncs committed state from nodes and
  submits transactions. Runs a local daemon that drives quorum reads
  and exposes a JSON-RPC socket for worker processes.
- Compactor: periodically compacts the log and produces checkpoints
  for fast bootstrap of new or recovering nodes.

Nodes are labelled with domains (free-form byte tags like `rack:7` or
`provider:aws-eu`) for diversity-aware provisioning. The system tracks
how many nodes share each domain and warns when a single failure domain
could break quorum.

### Data layer

On top of the encrypted store, three data structures provide
application-level primitives:

- ManagedMap: an encrypted key-value map. Reads and writes go through
  the session layer, which handles encryption, blinding, and
  transactional guards.
- PlaintextMap: a prefix-scoped key-value map over epoch-0 (plaintext)
  keys. Used for coordination metadata that must be scannable without
  decryption, such as queue state and worker registration.
- Queue and Worker: a lease-based job queue with pending/active/lease
  indices, deadline-based expiry, and a worker supervisor that handles
  registration, heartbeat, lease renewal, and handler-thread lifecycle.

## Quickstart

Requires Python 3.12+. Nothing installs outside the project directory.

```
make install
```

This bootstraps a project-local `uv` and virtualenv with all
dependencies (ruff, ty, PyNaCl).

### Running a local cluster

The testbed CLI creates and manages a local cluster for development:

```
dude tb create --nodes 3 --mgmt 1
dude tb provision
dude tb start
```

This creates a 3-node cluster with a manager under `./testbed/`,
runs genesis to provision all nodes, and starts them on localhost
ports 9001-9003. Each role gets its own directory (`.n0`, `.n1`,
`.n2`, `.m0`) with keypairs and config.

```
dude tb status          # show what's running
dude tb observe         # query topology from each node
dude tb stop            # shut everything down
```

You can target individual roles with dotted names:

```
dude tb start .n0       # start just node 0
dude tb stop .m0        # stop just manager 0
dude tb .n0 node pubkey # pass any command through to a role's home
```

### Client operations

With a cluster running, the client CLI reads and writes values:

```
dude --home testbed/.rw0 client get mykey
dude --home testbed/.rw0 client put mykey "some value"
dude --home testbed/.rw0 client del mykey
```

### Gate

```
make check              # lint + format-check + typecheck
make test               # 537 tests, ~5 minutes
make lint | format | typecheck | test
make clean              # remove .venv + caches
```

Green gate before every commit.

## Links

- [PYTHON-CODESTYLE.md](PYTHON-CODESTYLE.md): code style guide
