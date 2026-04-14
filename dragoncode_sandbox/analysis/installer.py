from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Union


@dataclass(frozen=True, slots=True)
class ServiceCreation:
    name: str


@dataclass(frozen=True, slots=True)
class DriverLoad:
    name: str


@dataclass(frozen=True, slots=True)
class PrivilegeEscalation:
    pass


@dataclass(frozen=True, slots=True)
class PersistenceHook:
    pass


@dataclass(frozen=True, slots=True)
class StandardFileDrop:
    pass


InstallIntent = Union[
    ServiceCreation,
    DriverLoad,
    PrivilegeEscalation,
    PersistenceHook,
    StandardFileDrop,
]


class InstallerAnalyzer:
    @staticmethod
    def analyze_intent(path: Path, command_line: str) -> list[InstallIntent]:
        intents: list[InstallIntent] = []

        if "sc.exe create" in command_line or "CreateService" in command_line:
            intents.append(ServiceCreation(name="Unknown Service"))

        if InstallerAnalyzer._inspect_package_contents_for_sys_files(path):
            intents.append(DriverLoad(name="Kernel Driver Detected"))

        if path.suffix.lower() == ".msi":
            intents.append(PrivilegeEscalation())

        return intents

    @staticmethod
    def _inspect_package_contents_for_sys_files(_path: Path) -> bool:
        return False
