from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Optional
from uuid import uuid4

from .isolation import IsolationLevel


@dataclass(slots=True)
class SampleMetadata:
    sha256: str
    original_name: str
    file_size: int


@dataclass(slots=True)
class SandboxVerdict:
    score: int


class SandboxContext:
    def __init__(self, sample_hash: str, isolation_level: IsolationLevel) -> None:
        self.sample_hash = sample_hash
        self.isolation_level = isolation_level
        self.disk_state_id = str(uuid4())
        self.registry_state_id = str(uuid4())
        self.verdict: Optional[SandboxVerdict] = None
        self._memory_lock = Lock()
        self.memory: dict[str, bytes] = {}

    def set_verdict(self, score: int) -> None:
        self.verdict = SandboxVerdict(score=score)
