from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class Allow:
    pass


@dataclass(frozen=True, slots=True)
class Redirect:
    path: Path


@dataclass(frozen=True, slots=True)
class Block:
    pass


@dataclass(frozen=True, slots=True)
class Log:
    pass


Action = Allow | Redirect | Block | Log


@dataclass(slots=True)
class DiffTracker:
    created: set[Path] = field(default_factory=set)
    modified: set[Path] = field(default_factory=set)
    deleted: set[Path] = field(default_factory=set)


@dataclass(slots=True)
class VirtualDisk:
    path: Path
    mounted: bool = False
    handle: int | None = None
    diff: DiffTracker = field(default_factory=DiffTracker)

    @staticmethod
    def create(path: Path, _size_mb: int) -> "VirtualDisk":
        return VirtualDisk(path=Path(path), mounted=False, handle=None, diff=DiffTracker())

    def prepare_authentic_environment(self, mount_point: Path) -> None:
        dirs = [
            "Program Files",
            "Program Files (x86)",
            "Users\\Public",
            "Users\\Default",
            "Windows\\System32",
            "Windows\\Temp",
            "ProgramData",
            "Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        ]

        for d in dirs:
            (Path(mount_point) / d).mkdir(parents=True, exist_ok=True)

        fake_files = [
            ("Users\\Admin\\Documents\\Invoice_2023.docx", "Dummy content for invoice..."),
            ("Users\\Admin\\Pictures\\Family.jpg", "Fake JPEG header content..."),
            ("Windows\\Logs\\cbs.log", "Simulated system logs..."),
        ]

        for rel, content in fake_files:
            full_path = Path(mount_point) / rel
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding="utf-8", errors="ignore")

    def resolve_path(self, requested_path: Path) -> Action:
        if "System32" in str(requested_path):
            return Redirect(path=self.path / "Windows" / "System32")
        return Allow()

    def mount(self) -> str:
        if self.mounted:
            raise RuntimeError("Disk already mounted")

        self.mounted = True
        self.handle = id(self)
        return rf"\\?\Volume{{{uuid4()}}}\\"

    def unmount(self) -> None:
        if not self.mounted:
            return
        self.mounted = False
        self.handle = None

    def create_snapshot(self, _snapshot_name: str) -> None:
        return None

    def __del__(self) -> None:
        try:
            if self.mounted:
                self.unmount()
        except Exception:
            return
