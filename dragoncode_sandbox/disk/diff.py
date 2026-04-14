from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .snapshot import DiskSnapshot


@dataclass(frozen=True, slots=True)
class Created:
    size: int


@dataclass(frozen=True, slots=True)
class Modified:
    size_diff: int


@dataclass(frozen=True, slots=True)
class Deleted:
    pass


FileChange = Created | Modified | Deleted


@dataclass(slots=True)
class DiskDiff:
    changes: dict[Path, FileChange]

    @staticmethod
    def compute(snap_before: DiskSnapshot, snap_after: DiskSnapshot) -> "DiskDiff":
        changes: dict[Path, FileChange] = {}

        for path, after_state in snap_after.files.items():
            before_state = snap_before.files.get(path)
            if before_state is not None:
                if before_state.modified != after_state.modified or before_state.size != after_state.size:
                    size_diff = int(after_state.size) - int(before_state.size)
                    changes[path] = Modified(size_diff=size_diff)
            else:
                changes[path] = Created(size=int(after_state.size))

        for path in snap_before.files.keys():
            if path not in snap_after.files:
                changes[path] = Deleted()

        return DiskDiff(changes=changes)
