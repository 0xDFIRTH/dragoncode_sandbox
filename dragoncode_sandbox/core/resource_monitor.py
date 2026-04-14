from __future__ import annotations

import threading
import time
from typing import Any, Optional

from .resource_limits import ResourceLimits, ResourceUsage


class ResourceMonitor:
    def __init__(self, limits: ResourceLimits) -> None:
        self._limits = limits
        self._usage = ResourceUsage()
        self._violations: list[str] = []
        self._lock = threading.Lock()
        self._active = False
        self._thread: Optional[threading.Thread] = None

    def start_monitoring(self, process_handle: Any, _job_handle: Any) -> None:
        if self._active:
            return

        pid = _extract_pid(process_handle)
        self._active = True

        def worker() -> None:
            proc = _try_get_psutil_process(pid)
            if proc is not None:
                try:
                    proc.cpu_percent(interval=None)
                except Exception:
                    proc = None

            while self._active:
                time.sleep(0.5)

                usage = ResourceUsage()
                if proc is not None:
                    try:
                        usage.memory_mb = int(proc.memory_info().rss // (1024 * 1024))
                    except Exception:
                        pass
                    try:
                        usage.cpu_percent = float(proc.cpu_percent(interval=None))
                    except Exception:
                        pass

                violations = usage.check_violations(self._limits)

                with self._lock:
                    self._usage = usage
                    for v in violations:
                        if v not in self._violations:
                            self._violations.append(v)

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()

    def stop_monitoring(self) -> None:
        self._active = False
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=1.0)

    def get_current_usage(self) -> ResourceUsage:
        with self._lock:
            return self._usage.clone()

    def get_violations(self) -> list[str]:
        with self._lock:
            return list(self._violations)

    def has_violations(self) -> bool:
        with self._lock:
            return bool(self._violations)

    def print_usage_report(self) -> None:
        usage = self.get_current_usage()
        print("\n=== Resource Usage Report ===")
        print(f"CPU: {usage.cpu_percent:.1f}%")
        print(f"Memory: {usage.memory_mb} MB")
        print(f"Disk Read: {usage.disk_read_mbps:.1f} MB/s")
        print(f"Disk Write: {usage.disk_write_mbps:.1f} MB/s")
        print(f"Disk IOPS: {usage.disk_iops}")

        violations = self.get_violations()
        if violations:
            print("\nVIOLATIONS DETECTED:")
            for v in violations:
                print(f"  - {v}")
        print("============================\n")


def _extract_pid(process_handle: Any) -> Optional[int]:
    if process_handle is None:
        return None
    if isinstance(process_handle, int):
        return process_handle
    pid = getattr(process_handle, "pid", None)
    if isinstance(pid, int):
        return pid
    return None


def _try_get_psutil_process(pid: Optional[int]):
    if pid is None or pid <= 0:
        return None
    try:
        import psutil  # type: ignore

        return psutil.Process(pid)
    except Exception:
        return None
