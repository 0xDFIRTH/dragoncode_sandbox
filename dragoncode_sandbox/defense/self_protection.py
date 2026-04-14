from __future__ import annotations

import os
import threading
import time


class SelfProtection:
    @staticmethod
    def check_integrity() -> bool:
        if os.name != "nt":
            return False

        try:
            import ctypes

            return bool(ctypes.windll.kernel32.IsDebuggerPresent())
        except Exception:
            return False

    @staticmethod
    def start_heartbeat_monitor() -> None:
        def worker() -> None:
            while True:
                time.sleep(2)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
