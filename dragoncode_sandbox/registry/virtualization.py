from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class RegistryKey:
    name: str
    values: dict[str, str] = field(default_factory=dict)
    subkeys: dict[str, "RegistryKey"] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Read:
    pass


@dataclass(frozen=True, slots=True)
class Write:
    value: str


@dataclass(frozen=True, slots=True)
class Delete:
    pass


@dataclass(frozen=True, slots=True)
class Create:
    pass


RegistryOp = Read | Write | Delete | Create


class RegistryVirtualizer:
    def __init__(self) -> None:
        self.hklm_shadow = RegistryKey(name="HKLM")
        self.hkcu_shadow = RegistryKey(name="HKCU")
        self.op_log: list[tuple[str, RegistryOp]] = []

    def intercept_write(self, root: str, key_path: str, value_name: str, data: str) -> None:
        path = f"{root}\\{key_path}\\{value_name}"
        self.op_log.append((path, Write(value=str(data))))

        hive = self.hklm_shadow if root == "HKLM" else self.hkcu_shadow
        hive.values[f"{key_path}\\{value_name}"] = str(data)

    def get_diff(self) -> dict[str, str]:
        diff: dict[str, str] = {}
        for k, v in self.op_log:
            if isinstance(v, Write):
                diff[k] = v.value
        return diff
