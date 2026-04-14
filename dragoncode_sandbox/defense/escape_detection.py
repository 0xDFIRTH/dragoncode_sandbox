from __future__ import annotations


class EscapeDetector:
    @staticmethod
    def monitor_privileges() -> bool:
        return False

    @staticmethod
    def detect_filesystem_breakout(path_accessed: str) -> bool:
        lower = path_accessed.lower()
        if lower.startswith("c:\\windows") and "temp" not in lower:
            return True
        return False
