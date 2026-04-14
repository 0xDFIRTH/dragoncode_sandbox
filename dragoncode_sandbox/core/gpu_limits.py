from __future__ import annotations

from typing import Any

from .resource_limits import GpuLimits, GpuPriority


class GpuController:
    def __init__(self, limits: GpuLimits) -> None:
        self._limits = limits

    def apply_to_process(self, _process_handle: Any) -> None:
        return None

    def get_software_rendering_env_vars(self) -> list[tuple[str, str]]:
        if not self._limits.force_software_rendering:
            return []

        return [
            ("DXGI_ADAPTER", "WARP"),
            ("LIBGL_ALWAYS_SOFTWARE", "1"),
            ("VK_ICD_FILENAMES", ""),
            ("QTWEBENGINE_DISABLE_GPU", "1"),
            ("MESA_GL_VERSION_OVERRIDE", "3.3"),
        ]

    def should_block_gpu_devices(self) -> bool:
        return not self._limits.allow_gpu_access

    def get_blocked_device_paths(self) -> list[str]:
        if self.should_block_gpu_devices():
            return [r"\\?\DISPLAY", r"\\?\GPU"]
        return []

    def _set_gpu_priority(self, _process_handle: Any, _priority: GpuPriority) -> None:
        return None
