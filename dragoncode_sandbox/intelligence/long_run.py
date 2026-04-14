from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Optional


@dataclass(slots=True)
class LongTermMonitor:
    accumulated_sleep: timedelta = timedelta(0)
    max_sleep_allowed: timedelta = timedelta(seconds=300)
    on_anomaly: Optional[Callable[[str], None]] = None

    def intercept_sleep(self, requested: timedelta) -> timedelta:
        if requested > timedelta(seconds=60):
            if self.on_anomaly:
                self.on_anomaly(f"Detecting Long Sleep ({requested}). Accelerating...")
            self.accumulated_sleep += requested
            return timedelta(milliseconds=100)
        return requested

    def is_time_bomb_detected(self) -> bool:
        return self.accumulated_sleep > timedelta(seconds=3600)
