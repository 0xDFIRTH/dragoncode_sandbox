from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class FilesystemIsolation:
    def __init__(self, virtual_root: Path) -> None:
        self._virtual_root = Path(virtual_root)
        self._blocked_paths: set[Path] = {
            Path(r"C:\Windows\System32\config"),
            Path(r"C:\Windows\System32\drivers"),
            Path(r"C:\ProgramData"),
            Path(r"C:\Users"),
            Path(r"\\.\PhysicalDrive0"),
            Path(r"\\.\PhysicalDrive1"),
            Path(r"\\.\C:"),
            Path(r"\\.\GLOBALROOT"),
        }
        self._allow_host_access = False

    def validate_path(self, requested_path: Path) -> Path:
        normalized = self._normalize_path(requested_path)

        if self._is_device_path(normalized):
            raise ValueError(f"Device access is blocked: {normalized}")

        if self._is_blocked(normalized):
            raise ValueError(f"Access to blocked path: {normalized}")

        if not self._is_within_virtual_root(normalized) and not self._allow_host_access:
            raise ValueError(
                f"Path outside virtual disk is blocked: {normalized}. Virtual root: {self._virtual_root}"
            )

        return normalized

    def _normalize_path(self, path: Path) -> Path:
        abs_path = path if path.is_absolute() else (self._virtual_root / path)

        parts = list(abs_path.parts)
        if not parts:
            return abs_path

        normalized_parts: list[str] = []
        for part in parts:
            if part in (".", ""):
                continue
            if part == "..":
                if len(normalized_parts) > 1:
                    normalized_parts.pop()
                continue
            normalized_parts.append(part)

        try:
            return Path(*normalized_parts)
        except Exception:
            return abs_path

    def _is_device_path(self, path: Path) -> bool:
        s = str(path).upper()
        return (
            s.startswith("\\\\.\\")
            or s.startswith("\\\\?\\")
            or "PHYSICALDRIVE" in s
            or "GLOBALROOT" in s
            or "DEVICE" in s
        )

    def _is_blocked(self, path: Path) -> bool:
        path_s = str(path).lower()
        for blocked in self._blocked_paths:
            if path_s.startswith(str(blocked).lower()):
                return True
        return False

    def _is_within_virtual_root(self, path: Path) -> bool:
        return str(path).lower().startswith(str(self._virtual_root).lower())

    def block_path(self, path: Path) -> None:
        self._blocked_paths.add(Path(path))

    def validate_symlink_creation(self, target: Path) -> None:
        normalized_target = self._normalize_path(target)
        if not self._is_within_virtual_root(normalized_target):
            raise ValueError(
                f"Symlink creation blocked: target outside virtual disk: {target}"
            )

    def get_virtual_root(self) -> Path:
        return self._virtual_root


@dataclass(slots=True)
class FileOperationGuard:
    isolation: FilesystemIsolation

    @classmethod
    def new(cls, virtual_root: Path) -> "FileOperationGuard":
        return cls(isolation=FilesystemIsolation(virtual_root))

    def intercept_open(self, path: Path) -> Path:
        return self.isolation.validate_path(path)

    def intercept_create(self, path: Path) -> Path:
        return self.isolation.validate_path(path)

    def intercept_delete(self, path: Path) -> Path:
        return self.isolation.validate_path(path)

    def intercept_symlink(self, source: Path, target: Path) -> None:
        self.isolation.validate_path(source)
        self.isolation.validate_symlink_creation(target)
