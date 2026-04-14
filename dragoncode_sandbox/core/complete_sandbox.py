from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .isolation import SandboxIsolation
from .resource_limits import ResourceLimits, ResourceUsage, ResourceValidator
from .gpu_limits import GpuController
from .resource_monitor import ResourceMonitor
from ..disk.fs_isolation import FilesystemIsolation
from ..disk.virtual_disk import VirtualDisk
from ..defense.network_isolation import CommunicationIsolation
from ..governance.policy import Policy


class CompleteSandbox:
    def __init__(
        self,
        isolation: SandboxIsolation,
        resource_limits: ResourceLimits,
        gpu_controller: GpuController,
        resource_monitor: ResourceMonitor,
        fs_isolation: FilesystemIsolation,
        virtual_disk: Optional[VirtualDisk],
        comm_isolation: CommunicationIsolation,
        policy: Policy,
    ) -> None:
        self.isolation = isolation
        self.resource_limits = resource_limits
        self.gpu_controller = gpu_controller
        self.resource_monitor = resource_monitor
        self.fs_isolation = fs_isolation
        self.virtual_disk = virtual_disk
        self.comm_isolation = comm_isolation
        self.policy = policy

    @classmethod
    def new(cls, resource_limits: ResourceLimits, virtual_disk_root: Path) -> "CompleteSandbox":
        ResourceValidator.validate_all(resource_limits)

        isolation = SandboxIsolation.with_resource_limits(resource_limits)
        gpu_controller = GpuController(resource_limits.gpu)
        resource_monitor = ResourceMonitor(resource_limits)
        fs_isolation = FilesystemIsolation(virtual_disk_root)
        comm_isolation = CommunicationIsolation.new_complete_isolation()

        disk_size_mb = resource_limits.disk.max_size_mb
        virtual_disk: Optional[VirtualDisk]
        try:
            virtual_disk = VirtualDisk.create(virtual_disk_root / "sandbox.vhdx", disk_size_mb)
        except Exception:
            virtual_disk = None

        return cls(
            isolation=isolation,
            resource_limits=resource_limits,
            gpu_controller=gpu_controller,
            resource_monitor=resource_monitor,
            fs_isolation=fs_isolation,
            virtual_disk=virtual_disk,
            comm_isolation=comm_isolation,
            policy=Policy(),
        )

    @classmethod
    def new_with_defaults(cls, virtual_disk_root: Path) -> "CompleteSandbox":
        return cls.new(ResourceLimits(), virtual_disk_root)

    def assign_process(self, process_handle: Any) -> None:
        self.isolation.assign_process(process_handle)
        self.gpu_controller.apply_to_process(process_handle)
        self.resource_monitor.start_monitoring(process_handle, self.isolation.get_job_handle())

        print("[✓] Process assigned to complete sandbox")
        print(
            f"    - CPU: {self.resource_limits.cpu.max_cores} cores max, {self.resource_limits.cpu.max_usage_percent}% usage max"
        )
        print(f"    - Memory: {self.resource_limits.memory.max_mb} MB max")
        print(f"    - Disk: {self.resource_limits.disk.max_size_mb} MB max")
        print(
            f"    - GPU: {'Allowed' if self.resource_limits.gpu.allow_gpu_access else 'Blocked'}"
        )
        print(
            f"    - Network: {'Allowed' if self.comm_isolation.is_network_allowed() else 'Blocked'}"
        )
        print(f"    - Filesystem: Isolated to {self.fs_isolation.get_virtual_root()}")

    def validate_file_access(self, path: Path) -> None:
        self.fs_isolation.validate_path(path)

    def is_network_port_allowed(self, port: int) -> bool:
        return self.comm_isolation.is_port_allowed(int(port))

    def get_resource_usage(self) -> ResourceUsage:
        return self.resource_monitor.get_current_usage()

    def print_usage_report(self) -> None:
        self.resource_monitor.print_usage_report()

    def has_violations(self) -> bool:
        return self.resource_monitor.has_violations()

    def get_violations(self) -> list[str]:
        return self.resource_monitor.get_violations()

    def stop(self) -> None:
        self.resource_monitor.stop_monitoring()
        print("[✓] Sandbox stopped")


@dataclass(slots=True)
class SandboxBuilder:
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    virtual_disk_root: Path = Path(r"C:\Sandbox")
    allow_network: bool = False

    def with_resource_limits(self, limits: ResourceLimits) -> "SandboxBuilder":
        self.resource_limits = limits
        return self

    def with_cpu_limit(self, max_cores: int, max_usage_percent: int) -> "SandboxBuilder":
        self.resource_limits.cpu.max_cores = int(max_cores)
        self.resource_limits.cpu.max_usage_percent = int(max_usage_percent)
        return self

    def with_memory_limit(self, max_mb: int) -> "SandboxBuilder":
        self.resource_limits.memory.max_mb = int(max_mb)
        return self

    def with_disk_limit(self, max_size_mb: int) -> "SandboxBuilder":
        self.resource_limits.disk.max_size_mb = int(max_size_mb)
        return self

    def with_virtual_disk_root(self, root: Path) -> "SandboxBuilder":
        self.virtual_disk_root = root
        return self

    def allow_network_access(self, allow: bool) -> "SandboxBuilder":
        self.allow_network = bool(allow)
        return self

    def build(self) -> CompleteSandbox:
        sandbox = CompleteSandbox.new(self.resource_limits, self.virtual_disk_root)
        if self.allow_network:
            sandbox.comm_isolation = CommunicationIsolation.new_with_network()
        return sandbox
