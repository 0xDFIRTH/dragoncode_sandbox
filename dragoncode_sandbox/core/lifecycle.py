from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from time import monotonic


class SandboxStage(str, Enum):
    PRE_INSTALL = "PreInstall"
    INSTALL = "Install"
    RUNTIME = "Runtime"
    LONG_RUN = "LongRun"
    TERMINATED = "Terminated"


@dataclass(slots=True)
class LifecycleManager:
    max_duration_sec: float
    state: SandboxStage = SandboxStage.PRE_INSTALL
    _start_time: float | None = None

    def transition_to(self, next_stage: SandboxStage) -> None:
        valid = (
            (self.state == SandboxStage.PRE_INSTALL and next_stage == SandboxStage.INSTALL)
            or (self.state == SandboxStage.PRE_INSTALL and next_stage == SandboxStage.RUNTIME)
            or (self.state == SandboxStage.INSTALL and next_stage == SandboxStage.RUNTIME)
            or (self.state == SandboxStage.RUNTIME and next_stage == SandboxStage.LONG_RUN)
            or (next_stage == SandboxStage.TERMINATED)
        )

        if not valid:
            raise ValueError(f"Invalid Transition: {self.state.value} -> {next_stage.value}")

        self.state = next_stage
        if next_stage == SandboxStage.RUNTIME and self._start_time is None:
            self._start_time = monotonic()

    def get_stage(self) -> SandboxStage:
        return self.state

    def is_expired(self) -> bool:
        if self._start_time is None:
            return False
        return (monotonic() - self._start_time) > self.max_duration_sec
