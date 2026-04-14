from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class FilesystemRedirector:
    root: Path
    overlay: Path

    def resolve_path(self, requested: Path) -> Path:
        try:
            relative = requested.relative_to(self.root)
        except Exception:
            return requested

        overlay_path = self.overlay / relative
        if overlay_path.exists():
            return overlay_path

        return requested

    def prepare_for_write(self, requested: Path) -> Path:
        try:
            relative = requested.relative_to(self.root)
        except Exception:
            return requested

        overlay_path = self.overlay / relative

        if not overlay_path.exists() and requested.exists() and requested.is_file():
            overlay_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(requested, overlay_path)

        return overlay_path
