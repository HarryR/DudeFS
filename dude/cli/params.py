from __future__ import annotations

import click

from ..core import crypto
from ..store.management import Role
from .config import TCPListenConfig


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


class ListenParam(click.ParamType):
    name = "listen-addr"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context | None,
    ) -> TCPListenConfig:
        parts = value.split(":")
        if len(parts) == 3 and parts[0] == "tcp":
            try:
                return TCPListenConfig(host=parts[1], port=int(parts[2]))
            except ValueError:
                self.fail(f"invalid port in {value!r}", param, ctx)
        if len(parts) == 2:
            try:
                return TCPListenConfig(host=parts[0], port=int(parts[1]))
            except ValueError:
                self.fail(f"invalid port in {value!r}", param, ctx)
        self.fail(f"expected tcp:host:port or host:port, got {value!r}", param, ctx)
        raise AssertionError("unreachable")


PUBKEY = PublicKeyParam()
SIGNATURE = SignatureParam()
ROLE = RoleParam()
LISTEN = ListenParam()
