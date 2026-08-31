from __future__ import annotations

import logging
from pathlib import Path

import click

from . import anchor, client, compactor, mgr, node
from .config import DudeConfig


@click.group()
@click.option(
    "--home",
    envvar="DUDE_HOME",
    default="~/.dude",
    type=click.Path(),
    help="DudeFS home directory",
)
@click.option("-v", "--verbose", count=True, help="-v info, -vv debug")
@click.pass_context
def cli(ctx: click.Context, home: str, verbose: int) -> None:
    level = (logging.WARNING, logging.INFO, logging.DEBUG)[min(verbose, 2)]
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname).1s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    ctx.obj = DudeConfig(home=Path(home).expanduser())


cli.add_command(anchor.group)
cli.add_command(node.group)
cli.add_command(client.group)
cli.add_command(mgr.group)
cli.add_command(compactor.group)


def main() -> None:
    cli()
