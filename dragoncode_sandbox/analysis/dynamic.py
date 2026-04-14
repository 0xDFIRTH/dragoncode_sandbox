from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Union
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class ProcessCreate:
    pid: int
    image: str
    cmd: str


@dataclass(frozen=True, slots=True)
class ProcessTerminate:
    pid: int


@dataclass(frozen=True, slots=True)
class FileWrite:
    path: str
    size: int


@dataclass(frozen=True, slots=True)
class FileRead:
    path: str


@dataclass(frozen=True, slots=True)
class RegistryWrite:
    key: str
    value: str


@dataclass(frozen=True, slots=True)
class NetworkConnect:
    ip: str
    port: int
    proto: str


@dataclass(frozen=True, slots=True)
class Injection:
    target_pid: int
    technique: str


EventType = Union[
    ProcessCreate,
    ProcessTerminate,
    FileWrite,
    FileRead,
    RegistryWrite,
    NetworkConnect,
    Injection,
]


@dataclass(slots=True)
class BehaviorNode:
    id: str
    timestamp: datetime
    event_type: EventType
    risk_score: int


class DynamicEngine:
    def __init__(self) -> None:
        self.nodes: list[BehaviorNode] = []
        self.edges: list[tuple[int, int, str]] = []
        self._pid_map: dict[int, int] = {}
        self._root_node: Optional[int] = None

    def start_logging(self, sample_name: str) -> None:
        root = BehaviorNode(
            id="ROOT",
            timestamp=datetime.now(tz=timezone.utc),
            event_type=ProcessCreate(pid=0, image=sample_name, cmd="analysis_start"),
            risk_score=0,
        )
        self.nodes.append(root)
        self._root_node = len(self.nodes) - 1

    def log_event(self, parent_pid: Optional[int], event: EventType) -> None:
        risk = self._calculate_risk(event)
        node = BehaviorNode(
            id=str(uuid4()),
            timestamp=datetime.now(tz=timezone.utc),
            event_type=event,
            risk_score=risk,
        )
        self.nodes.append(node)
        current_idx = len(self.nodes) - 1

        if parent_pid is not None:
            parent_idx = self._pid_map.get(parent_pid)
            if parent_idx is not None:
                self.edges.append((parent_idx, current_idx, "spawned"))
            elif self._root_node is not None:
                self.edges.append((self._root_node, current_idx, "unknown_parent"))
        elif self._root_node is not None:
            self.edges.append((self._root_node, current_idx, "direct"))

        if isinstance(event, ProcessCreate):
            self._pid_map[event.pid] = current_idx

    @staticmethod
    def _calculate_risk(event: EventType) -> int:
        if isinstance(event, Injection):
            return 100
        if isinstance(event, RegistryWrite) and (
            "Run" in event.key or "Services" in event.key
        ):
            return 80
        if isinstance(event, ProcessCreate) and (
            "powershell" in event.cmd or "cmd.exe" in event.cmd
        ):
            return 60
        if isinstance(event, FileWrite) and (
            event.path.endswith(".exe") or event.path.endswith(".dll")
        ):
            return 50
        return 0

    def get_timeline(self) -> list[BehaviorNode]:
        nodes = list(self.nodes)
        nodes.sort(key=lambda n: n.timestamp)
        return nodes
