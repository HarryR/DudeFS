from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..tunables import DEFAULT, Tunables


@dataclass(frozen=True, slots=True)
class DudeConfig:
    home: Path
    tunables: Tunables = DEFAULT

    @property
    def anchor_dir(self) -> Path:
        return self.home / "anchor"

    @property
    def node_dir(self) -> Path:
        return self.home / "node"

    @property
    def client_dir(self) -> Path:
        return self.home / "client"

    @property
    def manager_dir(self) -> Path:
        return self.home / "manager"

    @property
    def compactor_dir(self) -> Path:
        return self.home / "compactor"
