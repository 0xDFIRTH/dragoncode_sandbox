from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class RegistryNode:
    name: str
    is_key: bool


class HiveParser:
    @staticmethod
    def parse_file(path: Path) -> list[RegistryNode]:
        buffer = Path(path).read_bytes()
        if len(buffer) < 4 or buffer[:4] != b"regf":
            raise ValueError("Invalid registry hive magic")

        return [RegistryNode(name="ROOT_KEY", is_key=True)]
