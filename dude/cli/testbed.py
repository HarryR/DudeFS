from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import click
import dacite

from .state import CLIError

log = logging.getLogger(__name__)

CLUSTER_JSON = "cluster.json"


@dataclass(slots=True)
class TestbedConfig:
    anchor_dir: str
    nodes: list[str] = field(default_factory=list)
    managers: list[str] = field(default_factory=list)
    ro_clients: list[str] = field(default_factory=list)
    rw_clients: list[str] = field(default_factory=list)
    ports: dict[str, int] = field(default_factory=dict)
    base_port: int = 9001

    def save(self, base: Path) -> None:
        (base / CLUSTER_JSON).write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, base: Path) -> TestbedConfig:
        p = base / CLUSTER_JSON
        if not p.exists():
            raise CLIError(f"no testbed at {base} (missing {CLUSTER_JSON})")
        return dacite.from_dict(cls, json.loads(p.read_text()))


def _find_testbed() -> Path:
    p = Path.cwd()
    while p != p.parent:
        if (p / CLUSTER_JSON).exists():
            return p
        p = p.parent
    default = Path.cwd() / "testbed"
    if (default / CLUSTER_JSON).exists():
        return default
    raise CLIError("no testbed found (run 'dude tb create' first)")


def _resolve_alias(alias: str, base: Path) -> Path:
    name = alias.lstrip(".")
    resolved = base / f".{name}"
    if not resolved.is_dir():
        raise CLIError(f"no testbed role '{alias}' (expected {resolved})")
    return resolved


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _read_pid(role_dir: Path) -> int | None:
    for sub in role_dir.iterdir():
        pidfile = sub / "dude.pid"
        if pidfile.exists():
            try:
                return int(pidfile.read_text().strip())
            except (ValueError, OSError):
                pass
    return None


def _role_subdir(role_dir: Path) -> Path:
    for sub in role_dir.iterdir():
        if sub.is_dir() and not sub.name.startswith("__"):
            return sub
    return role_dir


def _dude_cmd() -> list[str]:
    return [sys.executable, "-m", "dude.cli"]


def _run(cmd: list[str]) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    if result.returncode != 0:
        raise CLIError(f"command failed: {' '.join(cmd)}\n{result.stderr}")


def _run_output(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    if result.returncode != 0:
        raise CLIError(f"command failed: {' '.join(cmd)}\n{result.stderr}")
    return result.stdout.strip()


def _write_config(home: Path, toml: str) -> None:
    (home / "config.toml").write_text(toml)


def _wait_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise CLIError(f"port {port} not open after {timeout}s")


def _all_servables(cfg: TestbedConfig) -> list[tuple[str, list[str]]]:
    return [
        *[(n, ["node", "serve"]) for n in cfg.nodes],
        *[(n, ["mgr", "serve"]) for n in cfg.managers],
        *[(n, ["client", "serve"]) for n in cfg.ro_clients],
        *[(n, ["client", "serve"]) for n in cfg.rw_clients],
    ]


def _select_roles(
    cfg: TestbedConfig,
    targets: tuple[str, ...],
) -> list[tuple[str, list[str]]]:
    all_map: dict[str, list[str]] = {}
    for name in cfg.nodes:
        all_map[name] = ["node", "serve"]
    for name in cfg.managers:
        all_map[name] = ["mgr", "serve"]
    for name in cfg.ro_clients + cfg.rw_clients:
        all_map[name] = ["client", "serve"]
    out: list[tuple[str, list[str]]] = []
    for t in targets:
        key = t if t.startswith(".") else f".{t}"
        if key not in all_map:
            raise CLIError(f"unknown target: {t}")
        out.append((key, all_map[key]))
    return out


# ---------------------------------------------------------------------------
# Click group with alias passthrough
# ---------------------------------------------------------------------------


def _cli():
    from . import cli  # noqa: PLC0415

    return cli


class _TestbedGroup(click.Group):
    def resolve_command(self, ctx, args):
        if args and args[0].startswith("."):
            alias = args[0]
            base = ctx.params.get("tb_dir")
            if base:
                base = Path(base)
            else:
                try:
                    base = _find_testbed()
                except CLIError:
                    base = Path.cwd() / "testbed"
            home = _resolve_alias(alias, base)
            _cli()(["--home", str(home), *list(args[1:])], standalone_mode=False)
            ctx.exit(0)
        return super().resolve_command(ctx, args)


@click.group(
    "tb",
    cls=_TestbedGroup,
    invoke_without_command=True,
    help="Local test cluster. Use .a .n0 .m0 etc to pass through to a role.",
)
@click.option("--dir", "tb_dir", type=click.Path(), default=None, help="testbed directory")
@click.pass_context
def group(ctx: click.Context, tb_dir: str | None) -> None:
    if tb_dir:
        ctx.obj = Path(tb_dir)
    else:
        try:
            ctx.obj = _find_testbed()
        except CLIError:
            ctx.obj = Path.cwd() / "testbed"
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@group.command(help="Create a new testbed with keypairs and configs.")
@click.option("--nodes", default=3, help="number of consensus nodes")
@click.option("--mgmt", default=0, help="number of managers")
@click.option("--ro", default=0, help="number of read-only clients")
@click.option("--rw", default=0, help="number of read-write clients")
@click.option("--port", "base_port", default=9001, help="starting TCP port")
@click.pass_obj
def create(base: Path, nodes: int, mgmt: int, ro: int, rw: int, base_port: int) -> None:
    if (base / CLUSTER_JSON).exists():
        raise CLIError(f"testbed already exists at {base}")

    base.mkdir(parents=True, exist_ok=True)
    dude = _dude_cmd()

    tunables_toml = "[tunables]\nrtt_max = 50\nclock_skew = 25\nheld_convergence_max = 2\n"

    anchor_dir = str(base / ".a")
    _run([*dude, "--home", anchor_dir, "anchor", "init"])
    _write_config(Path(anchor_dir), tunables_toml)
    anchor_pk = _run_output([*dude, "--home", anchor_dir, "anchor", "pubkey"])

    cfg = TestbedConfig(anchor_dir=".a", base_port=base_port)

    for i in range(nodes):
        port = base_port + i
        name = f".n{i}"
        role_dir = str(base / name)
        _run([*dude, "--home", role_dir, "node", "init", "--anchor", anchor_pk])
        _write_config(
            Path(role_dir),
            tunables_toml + f'\n[[node.listen.tcp]]\nhost = "127.0.0.1"\nport = {port}\n',
        )
        cfg.nodes.append(name)
        cfg.ports[name] = port

    for i in range(mgmt):
        name = f".m{i}"
        role_dir = str(base / name)
        _run([*dude, "--home", role_dir, "mgr", "init"])
        _write_config(Path(role_dir), tunables_toml)
        cfg.managers.append(name)

    for i in range(ro):
        name = f".ro{i}"
        role_dir = str(base / name)
        _run([*dude, "--home", role_dir, "client", "init"])
        _write_config(Path(role_dir), tunables_toml)
        cfg.ro_clients.append(name)

    for i in range(rw):
        name = f".rw{i}"
        role_dir = str(base / name)
        _run([*dude, "--home", role_dir, "client", "init"])
        _write_config(Path(role_dir), tunables_toml)
        cfg.rw_clients.append(name)

    cfg.save(base)

    click.echo(f"Testbed created in {base}")
    click.echo(f"  Anchor: {anchor_pk}")
    for name in cfg.nodes:
        port = cfg.ports[name]
        pk = _run_output([*dude, "--home", str(base / name), "node", "pubkey"])
        click.echo(f"  {name}: {pk}  tcp:127.0.0.1:{port}")
    for name in cfg.managers:
        pk = _run_output([*dude, "--home", str(base / name), "mgr", "pubkey"])
        click.echo(f"  {name}: {pk}")


@group.command(help="Start nodes (all, or specific targets like .n0 .m1).")
@click.argument("targets", nargs=-1)
@click.pass_obj
def start(base: Path, targets: tuple[str, ...]) -> None:
    cfg = TestbedConfig.load(base)
    dude = _dude_cmd()
    to_start = _select_roles(cfg, targets) if targets else _all_servables(cfg)

    for name, cmd in to_start:
        role_dir = str(base / name)
        pid = _read_pid(Path(role_dir))
        if pid and _pid_alive(pid):
            click.echo(f"{name}: already running (pid {pid})")
            continue
        logfile = base / f"{name.lstrip('.')}.log"
        with open(logfile, "a") as lf:
            proc = subprocess.Popen(  # noqa: S603
                [*dude, "--home", role_dir, *cmd],
                stdout=lf,
                stderr=lf,
            )
        click.echo(f"{name}: started (pid {proc.pid}, log {logfile})")

    if not targets:
        click.echo("waiting for ports...")
        for name in cfg.nodes:
            port = cfg.ports[name]
            _wait_port(port)
        click.echo("all nodes listening")


@group.command(help="Stop nodes (all, or specific targets).")
@click.argument("targets", nargs=-1)
@click.pass_obj
def stop(base: Path, targets: tuple[str, ...]) -> None:
    cfg = TestbedConfig.load(base)
    if targets:
        names = [t if t.startswith(".") else f".{t}" for t in targets]
    else:
        names = [*cfg.nodes, *cfg.managers, *cfg.ro_clients, *cfg.rw_clients]
    for name in names:
        role_dir = base / name
        pid = _read_pid(role_dir)
        if pid and _pid_alive(pid):
            os.kill(pid, signal.SIGTERM)
            click.echo(f"{name}: stopped (pid {pid})")
        else:
            click.echo(f"{name}: not running")


@group.command(help="Run genesis and distribute bootstrap files.")
@click.pass_obj
def provision(base: Path) -> None:
    cfg = TestbedConfig.load(base)
    dude = _dude_cmd()
    anchor_dir = str(base / cfg.anchor_dir)

    genesis_args: list[str] = []
    for name in cfg.nodes:
        role_dir = str(base / name)
        pk = _run_output([*dude, "--home", role_dir, "node", "pubkey"])
        port = cfg.ports[name]
        genesis_args += [pk, f"tcp:127.0.0.1:{port}"]

    _run([*dude, "--home", anchor_dir, "anchor", "genesis", *genesis_args])

    seed_dir = _role_subdir(Path(anchor_dir))
    bootstrap = seed_dir / "bootstrap.json"
    genesis = seed_dir / "genesis.bin"
    if not bootstrap.exists():
        raise CLIError("genesis did not produce bootstrap.json")

    for name in cfg.managers + cfg.ro_clients + cfg.rw_clients:
        role_dir = base / name
        dest = _role_subdir(role_dir)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "bootstrap.json").write_bytes(bootstrap.read_bytes())
        (dest / "genesis.bin").write_bytes(genesis.read_bytes())

    click.echo("cluster provisioned")


@group.command(help="Query cluster topology from each node.")
@click.option("--watch", is_flag=True, help="continuously refresh")
@click.option("--interval", type=float, default=2.0, help="refresh interval (seconds)")
@click.option("--timeout", type=float, default=10.0, help="max wait for oneshot")
@click.option("--json", "as_json", is_flag=True, help="output as JSON")
@click.pass_obj
def observe(base: Path, watch: bool, interval: float, timeout: float, as_json: bool) -> None:
    cfg = TestbedConfig.load(base)
    anchor_dir = str(base / cfg.anchor_dir)
    args = ["--home", anchor_dir, "anchor", "observe", "--timeout", str(timeout)]
    if watch:
        args += ["--watch", "--interval", str(interval)]
    if as_json:
        args += ["--json"]
    _cli()(args, standalone_mode=False)


@group.command(help="Show which roles are running.")
@click.pass_obj
def status(base: Path) -> None:
    cfg = TestbedConfig.load(base)
    all_roles = [
        *[(n, "node") for n in cfg.nodes],
        *[(n, "manager") for n in cfg.managers],
        *[(n, "ro-client") for n in cfg.ro_clients],
        *[(n, "rw-client") for n in cfg.rw_clients],
    ]
    for name, role in all_roles:
        role_dir = base / name
        pid = _read_pid(role_dir)
        port = cfg.ports.get(name, None)
        if pid and _pid_alive(pid):
            port_str = f"  port={port}" if port else ""
            click.echo(f"  {name:6s}  {role:10s}  pid={pid}{port_str}  running")
        else:
            click.echo(f"  {name:6s}  {role:10s}  stopped")
