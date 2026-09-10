from abc import ABC, abstractmethod
from collections.abc import Iterator


class Map(ABC):
    prefix: bytes

    @abstractmethod
    def count(self) -> int: ...

    @abstractmethod
    def keys(self) -> Iterator[bytes]: ...

    @abstractmethod
    def items(self) -> Iterator[tuple[bytes, bytes]]: ...
