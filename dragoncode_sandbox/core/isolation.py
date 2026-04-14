from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class IsolationLevel(str, Enum):
    OBSERVER = "Observer"
    STANDARD = "Standard"
    AIR_GAP = "AirGap"


@dataclass(slots=True)
class RestrictedToken:
    handle: Any


@dataclass(slots=True)
class IsolationLimits:
    memory_mb: int
    allow_ui: bool
    limit_params: dict[str, Any]


class SandboxIsolation:
    def __init__(self, level: IsolationLevel) -> None:
        self._level = level
        self._token: Optional[RestrictedToken] = None
        self._job_handle: int = id(self)
        self.limits = self._define_limits(level)
        self.apply_mitigations()

    @classmethod
    def with_resource_limits(cls, resource_limits: Any) -> "SandboxIsolation":
        iso = cls(IsolationLevel.STANDARD)
        try:
            iso.limits.memory_mb = int(resource_limits.memory.max_mb)
        except Exception:
            pass
        return iso

    def get_job_handle(self) -> int:
        return self._job_handle

    @staticmethod
    def _define_limits(level: IsolationLevel) -> IsolationLimits:
        limit_params: dict[str, Any] = {
            "kill_on_job_close": True,
            "die_on_unhandled_exception": True,
        }

        if level == IsolationLevel.AIR_GAP:
            return IsolationLimits(memory_mb=512, allow_ui=False, limit_params=limit_params)
        if level == IsolationLevel.OBSERVER:
            return IsolationLimits(memory_mb=4096, allow_ui=True, limit_params=limit_params)
        return IsolationLimits(memory_mb=1024, allow_ui=True, limit_params=limit_params)

    def create_restricted_token(self) -> None:
        return None

    def apply_mitigations(self) -> None:
        return None

    def assign_process(self, _process_handle: Any) -> None:
        return None
