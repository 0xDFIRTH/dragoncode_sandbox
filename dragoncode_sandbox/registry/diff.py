from __future__ import annotations

from dataclasses import dataclass

from .virtualization import RegistryKey


@dataclass(frozen=True, slots=True)
class KeyAdded:
    pass


@dataclass(frozen=True, slots=True)
class KeyDeleted:
    pass


@dataclass(frozen=True, slots=True)
class ValueModified:
    old: str
    new: str


@dataclass(frozen=True, slots=True)
class ValueAdded:
    value: str


@dataclass(frozen=True, slots=True)
class ValueDeleted:
    value: str


RegChange = KeyAdded | KeyDeleted | ValueModified | ValueAdded | ValueDeleted


@dataclass(slots=True)
class RegAlert:
    path: str
    severity: int
    technique: str
    description: str


@dataclass(slots=True)
class RegistryDiff:
    changes: dict[str, RegChange]

    @staticmethod
    def compare(before: RegistryKey, after: RegistryKey) -> "RegistryDiff":
        changes: dict[str, RegChange] = {}
        RegistryDiff._recurse_diff("", before, after, changes)
        return RegistryDiff(changes=changes)

    @staticmethod
    def _recurse_diff(path: str, before: RegistryKey, after: RegistryKey, changes: dict[str, RegChange]) -> None:
        for k, v_after in after.values.items():
            full_path = RegistryDiff._normalize_path(f"{path}\\{k}")
            v_before = before.values.get(k)
            if v_before is not None:
                if v_before != v_after:
                    changes[full_path] = ValueModified(old=v_before, new=v_after)
            else:
                changes[full_path] = ValueAdded(value=v_after)

        for k, v_before in before.values.items():
            if k not in after.values:
                full_path = RegistryDiff._normalize_path(f"{path}\\{k}")
                changes[full_path] = ValueDeleted(value=v_before)

        for k, k_after in after.subkeys.items():
            full_path = f"{path}\\{k}"
            k_before = before.subkeys.get(k)
            if k_before is not None:
                RegistryDiff._recurse_diff(full_path, k_before, k_after, changes)
            else:
                changes[RegistryDiff._normalize_path(full_path)] = KeyAdded()

        for k in before.subkeys.keys():
            if k not in after.subkeys:
                full_path = RegistryDiff._normalize_path(f"{path}\\{k}")
                changes[full_path] = KeyDeleted()

    @staticmethod
    def _normalize_path(path: str) -> str:
        return path.replace("Wow6432Node\\", "")

    def detect_anomalies(self) -> list[RegAlert]:
        alerts: list[RegAlert] = []
        for path, change in self.changes.items():
            lower = path.lower()

            if "currentversion\\run" in lower or "startup" in lower:
                alerts.append(
                    RegAlert(
                        path=path,
                        severity=8,
                        technique="T1547.001",
                        description="Persistence via Run Key or Startup folder",
                    )
                )

            if "services" in lower and isinstance(change, KeyAdded):
                alerts.append(
                    RegAlert(
                        path=path,
                        severity=7,
                        technique="T1543.003",
                        description="New Windows Service entry created",
                    )
                )

            if "inprocserver32" in lower and isinstance(change, ValueModified):
                alerts.append(
                    RegAlert(
                        path=path,
                        severity=9,
                        technique="T1546.015",
                        description="Potential COM Hijacking via InprocServer32 modification",
                    )
                )

            if isinstance(change, (KeyDeleted, ValueDeleted)):
                if (
                    "safeboot" in lower
                    or "windows defender" in lower
                    or "eventlog" in lower
                ):
                    alerts.append(
                        RegAlert(
                            path=path,
                            severity=10,
                            technique="T1562.001",
                            description="Security services or event logs tampering detected (Deletion)",
                        )
                    )

        return alerts
