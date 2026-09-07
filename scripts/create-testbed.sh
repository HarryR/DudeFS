#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

NODES=3
MANAGERS=0
CLIENTS=0
BASE_PORT=9001
TARGET=""

usage() {
    echo "Usage: $0 [--nodes N] [--managers N] [--clients N] [--port BASE] [directory]"
    echo
    echo "Creates a DudeFS testbed with wrapper scripts and config files."
    echo "Defaults to $SOURCE_DIR/testbed/"
    echo "Does not start any processes."
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nodes)    NODES="$2"; shift 2 ;;
        --managers) MANAGERS="$2"; shift 2 ;;
        --clients)  CLIENTS="$2"; shift 2 ;;
        --port)     BASE_PORT="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"; shift
            else
                echo "unexpected argument: $1" >&2; exit 1
            fi
            ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    TARGET="$SOURCE_DIR/testbed"
fi

DUDE="python -m dude.cli"
mkdir -p "$TARGET"
TARGET="$(cd "$TARGET" && pwd)"

write_wrapper() {
    local name="$1" role_dir="$2"
    cat > "$TARGET/$name.sh" << WRAPPER
#!/bin/bash
exec $DUDE --home "$role_dir" "\$@"
WRAPPER
    chmod +x "$TARGET/$name.sh"
}

# --- shared tunables config ---
TUNABLES_TOML='[tunables]
rtt_max = 50
clock_skew = 25
held_convergence_max = 2
'

# --- anchor ---
$DUDE --home "$TARGET/.anchor" anchor init
ANCHOR_PK=$($DUDE --home "$TARGET/.anchor" anchor pubkey)
echo "$TUNABLES_TOML" > "$TARGET/.anchor/anchor/config.toml"
write_wrapper "anchor" "$TARGET/.anchor"

# --- nodes ---
GENESIS_ARGS=""
for i in $(seq 0 $((NODES - 1))); do
    PORT=$((BASE_PORT + i))
    NODE_DIR="$TARGET/.node-$i"

    $DUDE --home "$NODE_DIR" node init --anchor "$ANCHOR_PK"

    cat > "$NODE_DIR/config.toml" << TOML
${TUNABLES_TOML}
[[node.listen.tcp]]
host = "127.0.0.1"
port = $PORT
TOML

    write_wrapper "node-$i" "$NODE_DIR"

    NODE_PK=$($DUDE --home "$NODE_DIR" node pubkey)
    GENESIS_ARGS="$GENESIS_ARGS $NODE_PK tcp:127.0.0.1:$PORT"
done

# --- managers ---
for i in $(seq 0 $((MANAGERS - 1))); do
    MGR_DIR="$TARGET/.manager-$i"
    $DUDE --home "$MGR_DIR" mgr init
    write_wrapper "manager-$i" "$MGR_DIR"
done

# --- clients ---
for i in $(seq 0 $((CLIENTS - 1))); do
    CLIENT_DIR="$TARGET/.client-$i"
    $DUDE --home "$CLIENT_DIR" client init
    write_wrapper "client-$i" "$CLIENT_DIR"
done

echo
echo "Testbed created in $TARGET"
echo
echo "  Anchor:   $ANCHOR_PK"
for i in $(seq 0 $((NODES - 1))); do
    PORT=$((BASE_PORT + i))
    NODE_PK=$($DUDE --home "$TARGET/.node-$i" node pubkey)
    echo "  Node $i:   $NODE_PK  tcp:127.0.0.1:$PORT"
done
for i in $(seq 0 $((MANAGERS - 1))); do
    MGR_PK=$($DUDE --home "$TARGET/.manager-$i" mgr pubkey)
    echo "  Manager $i: $MGR_PK"
done
for i in $(seq 0 $((CLIENTS - 1))); do
    CLIENT_PK=$($DUDE --home "$TARGET/.client-$i" client pubkey)
    echo "  Client $i:  $CLIENT_PK"
done

echo
echo "Next steps:"
echo "  # Start nodes"
for i in $(seq 0 $((NODES - 1))); do
    echo "  $TARGET/node-$i.sh node serve &"
done
echo
echo "  # Provision the cluster"
echo "  $TARGET/anchor.sh anchor genesis$GENESIS_ARGS"
