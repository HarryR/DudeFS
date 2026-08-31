from __future__ import annotations

from typing import TYPE_CHECKING

import click

from ..core import crypto
from ..net.address import Address, AddressError, Scheme
from ..net.link import Acceptor
from ..net.transports.tcp import TCPListener
from ..store.management import Role

if TYPE_CHECKING:
    from .config import DudeConfig


class PublicKeyParam(click.ParamType):
    name = "pubkey"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context | None,
    ) -> crypto.PublicKey:
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            self.fail(f"{value!r} is not valid hex", param, ctx)
        try:
            return crypto.PublicKey(raw)
        except crypto.CryptoError as e:
            self.fail(str(e), param, ctx)


class SignatureParam(click.ParamType):
    name = "signature"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context | None,
    ) -> crypto.Signature:
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            self.fail(f"{value!r} is not valid hex", param, ctx)
        try:
            return crypto.Signature(raw)
        except crypto.CryptoError as e:
            self.fail(str(e), param, ctx)


class RoleParam(click.ParamType):
    name = "role"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context | None,
    ) -> Role:
        try:
            return Role[value.upper()]
        except KeyError:
            choices = ", ".join(r.name.lower() for r in Role)
            self.fail(f"{value!r} is not a valid role (choose from: {choices})", param, ctx)

    def get_metavar(self, param: click.Parameter, ctx: click.Context) -> str:  # noqa: ARG002
        return "[" + "|".join(r.name.lower() for r in Role) + "]"


class AcceptorParam(click.ParamType):
    name = "listen-addr"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context | None,
    ) -> Acceptor:
        try:
            addr = Address.parse(value.encode())
        except AddressError as e:
            self.fail(str(e), param, ctx)
            raise AssertionError("unreachable") from e
        cfg: DudeConfig = ctx.obj  # type: ignore[union-attr]
        if addr.scheme is Scheme.TCP:
            host, _, port_s = addr.value.partition(":")
            return TCPListener(cfg.tunables, listen_host=host, listen_port=int(port_s))
        self.fail(f"unsupported scheme {addr.scheme.value.decode()!r}", param, ctx)
        raise AssertionError("unreachable")


PUBKEY = PublicKeyParam()
SIGNATURE = SignatureParam()
ROLE = RoleParam()
ACCEPTOR = AcceptorParam()
