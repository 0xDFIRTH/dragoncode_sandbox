from __future__ import annotations

import heapq
import threading
import time
from dataclasses import dataclass
from enum import Enum


class TriggerType(str, Enum):
    IMMEDIATE = "Immediate"
    DELAYED = "Delayed"
    ON_REBOOT = "OnReboot"
    ON_USER_INTERACTION = "OnUserInteraction"


@dataclass(frozen=True, slots=True)
class Trigger:
    type: TriggerType
    delay_sec: float = 0.0

    @staticmethod
    def immediate() -> "Trigger":
        return Trigger(type=TriggerType.IMMEDIATE)

    @staticmethod
    def delayed(delay_sec: float) -> "Trigger":
        return Trigger(type=TriggerType.DELAYED, delay_sec=float(delay_sec))

    @staticmethod
    def on_reboot() -> "Trigger":
        return Trigger(type=TriggerType.ON_REBOOT)

    @staticmethod
    def on_user_interaction() -> "Trigger":
        return Trigger(type=TriggerType.ON_USER_INTERACTION)


@dataclass(slots=True)
class AnalysisTask:
    id: str
    priority: int
    trigger: Trigger
    scheduled_time: float


class TaskScheduler:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._heap: list[tuple[float, int, int, AnalysisTask]] = []
        self._counter = 0

    def schedule_task(self, task_id: str, trigger: Trigger) -> None:
        now = time.time()
        if trigger.type == TriggerType.IMMEDIATE:
            scheduled_time = now
        elif trigger.type == TriggerType.DELAYED:
            scheduled_time = now + trigger.delay_sec
        elif trigger.type == TriggerType.ON_REBOOT:
            scheduled_time = now + 30
        elif trigger.type == TriggerType.ON_USER_INTERACTION:
            scheduled_time = now + 5
        else:
            scheduled_time = now

        task = AnalysisTask(
            id=task_id,
            priority=1,
            trigger=trigger,
            scheduled_time=scheduled_time,
        )

        with self._lock:
            heapq.heappush(self._heap, (scheduled_time, -task.priority, self._counter, task))
            self._counter += 1

    def pop_due_tasks(self) -> list[AnalysisTask]:
        due: list[AnalysisTask] = []
        now = time.time()
        with self._lock:
            while self._heap and self._heap[0][0] <= now:
                _, _, _, task = heapq.heappop(self._heap)
                due.append(task)
        return due
