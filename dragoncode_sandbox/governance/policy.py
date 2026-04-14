from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Policy:
    max_execution_time_sec: int = 300
    allow_network: bool = True
    block_modifying_system_root: bool = True
    allow_dropped_executables: bool = True


class PolicyEnforcer:
    def __init__(self, policy: Policy) -> None:
        self._policy = policy
        self._violations: list[str] = []

    def check_network(self, _target_ip: str) -> bool:
        if not self._policy.allow_network:
            self._violations.append("Network connection attempted while disabled")
            return False
        return True

    def check_file_write(self, path: str) -> bool:
        if self._policy.block_modifying_system_root and path.lower().startswith("c:\\windows"):
            self._violations.append(f"Blocked write to system root: {path}")
            return False
        return True

    def get_violations(self) -> list[str]:
        return list(self._violations)
