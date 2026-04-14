from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from time import time
from uuid import uuid4


@dataclass(slots=True)
class FileState:
    size: int
    modified: int
    hash: str | None = None


@dataclass(slots=True)
class RegistryState:
    key: str
    values: dict[str, str]


@dataclass(slots=True)
class ServiceState:
    name: str
    status: str


@dataclass(slots=True)
class DiskSnapshot:
    id: str
    timestamp: int
    files: dict[Path, FileState]
    registry: list[RegistryState]
    services: list[ServiceState]

    @staticmethod
    def take_targeted() -> "DiskSnapshot":
        """Takes a snapshot of high-value target directories to save time."""
        files: dict[Path, FileState] = {}
        
        if os.name != 'nt':
            return DiskSnapshot(id=str(uuid4()), timestamp=int(time()), files={}, registry=[], services=[])
            
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
        startup_path = Path(user_profile) / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        temp_path = Path(os.environ.get("TEMP", "C:\\Temp"))
        appdata_path = Path(os.environ.get("APPDATA", "C:\\AppData"))
        
        targets = [startup_path, temp_path, appdata_path]
        
        for root_dir in targets:
            if not root_dir.exists():
                continue
                
            # Scan up to 2 levels deep to avoid massive slowdowns in AppData
            for p in root_dir.rglob("*"):
                try:
                    if not p.is_file():
                        continue
                    # Just an arbitrary depth check using relative_to
                    if len(p.relative_to(root_dir).parts) > 3:
                        continue
                        
                    st = p.stat()
                    files[p] = FileState(size=int(st.st_size), modified=int(st.st_mtime), hash=None)
                except Exception:
                    continue

        return DiskSnapshot(
            id=str(uuid4()),
            timestamp=int(time()),
            files=files,
            registry=[],
            services=[],
        )

    @staticmethod
    def take(root: Path) -> "DiskSnapshot":
        # Keep original method signature for backward compatibility, but make it targeted if it's C:\
        if str(root).startswith("C:\\") and len(str(root)) <= 4:
            return DiskSnapshot.take_targeted()
            
        root_path = Path(root)
        files: dict[Path, FileState] = {}

        for p in root_path.rglob("*"):
            try:
                if not p.is_file():
                    continue
                st = p.stat()
                files[p] = FileState(size=int(st.st_size), modified=int(st.st_mtime), hash=None)
            except Exception:
                continue

        return DiskSnapshot(
            id=str(uuid4()),
            timestamp=int(time()),
            files=files,
            registry=[],
            services=[],
        )
