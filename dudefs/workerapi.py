# DudeFS — the worker API server (WP2, CLIENT.md §1, §3).
#
# JSON-RPC 2.0 over a LOCAL unix socket, kept STRICTLY separate from the p2p node
# socket (daemon.py): filesystem permissions on this socket ARE the whole worker-
# authorization boundary, and no node verb is reachable here (distinct listener,
# distinct dispatch table — CLIENT.md §0, Harry's p2p/local-must-not-bleed rule).
#
# Framing: newline-delimited JSON (one request object or batch array per line).
# Every verb returns IMMEDIATELY from state the ClientDaemon already holds — poll
# is the only idiom, nothing blocks, there is no server push (CLIENT.md §1). A
# `TXN`/`PUT`/`CAS` hands the op to the daemon's background quorum drive and returns
# the op_hash ticket at once.

from __future__ import annotations

import json
import socket
import threading
from typing import Any, cast

from . import artifacts as A
from .artifacts import VERSION_ABSENT
from .client import ClientDaemon, Ladder

_COND = {
    "absent": A.Guard.ABSENT,
    "present": A.Guard.PRESENT,
    "version_eq": A.Guard.VERSION_EQ,
    "value_eq": A.Guard.VALUE_EQ,
}


class WorkerError(Exception):
    """A JSON-RPC error with a code (invalid params / unknown method / bad state)."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------- #
# JSON <-> internal (bytes) marshalling                                        #
# --------------------------------------------------------------------------- #


def _b(s: object) -> bytes:
    if not isinstance(s, str):
        raise WorkerError(-32602, "expected a string (path/value)")
    return s.encode("utf-8")


def _unhex(s: object) -> bytes:
    if not isinstance(s, str):
        raise WorkerError(-32602, "expected a hex string")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise WorkerError(-32602, f"bad hex: {e}") from None


def _ver_out(v: bytes) -> str | None:
    return None if v == VERSION_ABSENT else v.hex()


def _val_out(v: bytes | None) -> str | None:
    if v is None:
        return None
    try:
        return v.decode("utf-8")
    except UnicodeDecodeError:
        return v.hex()  # non-text value (v1 values are text; hex is the honest fallback)


def _hlc_out(h) -> list[int]:
    return [h.wall_ms, h.counter]


def _guard(g: Any) -> list[bytes]:
    if not isinstance(g, dict) or "cond" not in g or "path" not in g:
        raise WorkerError(-32602, "guard needs {path, cond}")
    cond = g["cond"]
    if cond not in _COND:
        raise WorkerError(-32602, f"unknown guard cond {cond!r}")
    kind, path = _COND[cond], _b(g["path"])
    if cond == "version_eq":
        return [kind, path, _unhex(g["version"])]
    if cond == "value_eq":
        return [kind, path, _b(g["value"])]
    return [kind, path]


def _mutation(m: Any) -> list[bytes]:
    if not isinstance(m, dict):
        raise WorkerError(-32602, "mutation must be an object")
    if "set" in m:
        return [A.Mutation.SET, _b(m["set"]), _b(m["value"])]
    if "del" in m:
        return [A.Mutation.DEL, _b(m["del"])]
    raise WorkerError(-32602, "mutation needs `set` or `del`")


def _slot(s: Any) -> tuple[bytes, bytes, int] | None:
    if s is None:
        return None
    if not isinstance(s, dict) or "path" not in s:
        raise WorkerError(-32602, "slot needs {path, version, attempt}")
    v = s.get("version")
    version = VERSION_ABSENT if v in (None, "⊥", "") else _unhex(v)
    return (_b(s["path"]), version, int(s.get("attempt", 0)))


def _guards(raw: object) -> list[list[bytes]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise WorkerError(-32602, "guards must be a list")
    return [_guard(g) for g in raw]


def _mutations(raw: object) -> list[list[bytes]]:
    if not isinstance(raw, list) or not raw:
        raise WorkerError(-32602, "at least one mutation required")
    return [_mutation(m) for m in raw]


def _intent_str(mutations: list[list[bytes]]) -> list[str]:
    out: list[str] = []
    for m in mutations:
        if m[0] == A.Mutation.SET:
            out.append(f"set→{_val_out(m[2])}")
        elif m[0] == A.Mutation.DEL:
            out.append("del")
    return out


def _ladder_out(l: Ladder) -> dict:
    d: dict = {"phase": l.phase, "may_flip": l.may_flip}
    if l.provisional is not None:
        d["provisional"] = l.provisional
    if l.final is not None:
        d["final"] = l.final
    if l.winner is not None:
        d["winner"] = l.winner.hex()
    return d


# --------------------------------------------------------------------------- #
# The verb table (CLIENT.md §3) — TXN primary, PUT/CAS sugar, INSPECT recovery #
# --------------------------------------------------------------------------- #


class WorkerAPI:
    """The JSON-RPC verb surface over one ClientDaemon."""

    def __init__(self, daemon: ClientDaemon):
        self.d = daemon

    def handle(self, method: str, params: dict[str, Any]) -> object:
        fn = getattr(self, f"_v_{method.lower()}", None)
        if fn is None:
            raise WorkerError(-32601, f"unknown method {method!r}")
        return fn(params)

    # ---- writes (op_hash ticket, immediately) ------------------------------ #
    def _v_txn(self, p: dict[str, Any]) -> dict:
        op = self.d.submit(
            _slot(p.get("slot")), _guards(p.get("guards")), _mutations(p.get("mutations"))
        )
        return {"op": op.hex()}

    def _v_put(self, p: dict[str, Any]) -> dict:
        muts = [[A.Mutation.SET, _b(p["path"]), _b(p["value"])]]
        op = self.d.submit(None, _guards(p.get("guards")), muts)
        return {"op": op.hex()}

    def _v_cas(self, p: dict[str, Any]) -> dict:
        path = _b(p["path"])
        expect = p.get("expect")
        if expect in (None, "absent"):
            slot = (path, VERSION_ABSENT, 0)
            guards = [[A.Guard.ABSENT, path]]
        else:
            version = _unhex(expect["version"])
            attempt = int(expect.get("attempt", 0))
            slot = (path, version, attempt)
            guards = [[A.Guard.VERSION_EQ, path, version]]
        op = self.d.submit(slot, guards, _mutations(p.get("mutations")))
        return {"op": op.hex()}

    # ---- reads (folded, local & cheap) ------------------------------------- #
    def _v_get(self, p: dict[str, Any]) -> dict:
        r = self.d.get(_b(p["path"]), level=p.get("level", "local"))
        return {
            "value": _val_out(r["value"]),
            "version": _ver_out(r["version"]),
            "attempt": r["attempt"],
            "present": r["present"],
            "as_of": _hlc_out(r["as_of"]),
            "tier": r["tier"],
        }

    def _v_list(self, p: dict[str, Any]) -> dict:
        delim = p.get("delimiter")
        rows = self.d.list_keys(
            _b(p["prefix"]),
            delimiter=_b(delim) if delim else None,
            level=p.get("level", "local"),
        )
        out = []
        for row in rows:
            if row["prefix"]:
                out.append({"prefix": row["key"].decode("utf-8", "replace")})
            else:
                out.append(
                    {
                        "key": row["key"].decode("utf-8", "replace"),
                        "version": _ver_out(row["version"]),
                        "attempt": row["attempt"],
                        "pending": row["pending"],
                    }
                )
        return {"keys": out}

    def _v_inspect(self, p: dict[str, Any]) -> dict:
        r = self.d.inspect(_b(p["path"]))
        return {
            "final": {
                "present": r["final"]["present"],
                "value": _val_out(r["final"]["value"]),
                "version": _ver_out(r["final"]["version"]),
            },
            "provisional": {
                "present": r["provisional"]["present"],
                "value": _val_out(r["provisional"]["value"]),
                "version": _ver_out(r["provisional"]["version"]),
                "attempt": r["provisional"]["attempt"],
            },
            "may_flip": r["may_flip"],
            "pending": [
                {"op": e["op"].hex(), "phase": e["phase"], "would": _intent_str(e["would"])}
                for e in r["pending"]
            ],
        }

    def _v_status(self, p: dict[str, Any]) -> dict:
        return _ladder_out(self.d.status(_unhex(p["op"])))


# --------------------------------------------------------------------------- #
# The socket shell (the ONLY I/O; newline-delimited JSON)                      #
# --------------------------------------------------------------------------- #


class WorkerServer:
    """Serves the WorkerAPI over a local unix socket. One thread per connection;
    requests are id-correlated so pipelining just works. Never speaks a node verb."""

    def __init__(self, daemon: ClientDaemon, api: WorkerAPI | None = None):
        self.daemon = daemon
        self.api = api or WorkerAPI(daemon)
        self._srv: socket.socket | None = None

    def _one(self, msg: object) -> object | None:
        """Dispatch one JSON-RPC request object -> a response object (or None for a
        notification: no `id`)."""
        if not isinstance(msg, dict):
            return _err(None, -32600, "invalid request")
        rid = msg.get("id")
        try:
            method = msg.get("method")
            if not isinstance(method, str):
                raise WorkerError(-32600, "method must be a string")
            raw_params = msg.get("params") or {}
            if not isinstance(raw_params, dict):
                raise WorkerError(-32602, "params must be an object")
            result = self.api.handle(method, cast("dict[str, Any]", raw_params))
        except WorkerError as e:
            return _err(rid, e.code, e.message)
        except (KeyError, ValueError, TypeError) as e:
            return _err(rid, -32602, f"invalid params: {e}")
        if rid is None:
            return None  # JSON-RPC notification: no reply
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _dispatch_line(self, line: bytes) -> bytes | None:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return _dump(_err(None, -32700, "parse error"))
        if isinstance(payload, list):  # batch
            replies = [r for r in (self._one(m) for m in payload) if r is not None]
            return _dump(replies) if replies else None
        reply = self._one(payload)
        return _dump(reply) if reply is not None else None

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn, conn.makefile("rb") as rf:
            for line in rf:
                line = line.strip()
                if not line:
                    continue
                out = self._dispatch_line(line)
                if out is not None:
                    conn.sendall(out + b"\n")

    def serve_forever(self, path: str, ready: threading.Event | None = None) -> None:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(16)
        self._srv = srv
        if ready is not None:
            ready.set()
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def close(self) -> None:
        if self._srv is not None:
            self._srv.close()


def _err(rid: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _dump(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")
