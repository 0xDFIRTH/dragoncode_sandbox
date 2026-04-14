from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


@dataclass(slots=True)
class CpuLimits:
    min_cores: int = 1
    max_cores: int = 2
    affinity_mask: int = 0b11
    max_usage_percent: int = 50


@dataclass(slots=True)
class MemoryLimits:
    min_mb: int = 128
    max_mb: int = 512
    working_set_min_mb: int = 64
    working_set_max_mb: int = 512
    max_pagefile_mb: int = 256


@dataclass(slots=True)
class DiskLimits:
    min_size_mb: int = 100
    max_size_mb: int = 2048
    max_iops: int = 1000
    max_read_mbps: int = 50
    max_write_mbps: int = 50


class GpuPriority(str, Enum):
    LOW = "Low"
    BELOW_NORMAL = "BelowNormal"
    NORMAL = "Normal"


@dataclass(slots=True)
class GpuLimits:
    allow_gpu_access: bool = False
    rendering_priority: GpuPriority = GpuPriority.LOW
    force_software_rendering: bool = True


@dataclass(slots=True)
class ResourceLimits:
    cpu: CpuLimits = field(default_factory=CpuLimits)
    memory: MemoryLimits = field(default_factory=MemoryLimits)
    disk: DiskLimits = field(default_factory=DiskLimits)
    gpu: GpuLimits = field(default_factory=GpuLimits)


class ResourceValidator:
    @staticmethod
    def validate_cpu(limits: CpuLimits) -> None:
        if limits.min_cores < 1:
            raise ValueError("Minimum cores must be at least 1")
        if limits.max_cores < limits.min_cores:
            raise ValueError("Maximum cores must be >= minimum cores")
        if limits.max_usage_percent < 1 or limits.max_usage_percent > 100:
            raise ValueError("CPU usage percent must be between 1-100")

        bits_set = bin(int(limits.affinity_mask)).count("1")
        if bits_set < limits.min_cores:
            raise ValueError(f"Affinity mask must have at least {limits.min_cores} cores enabled")

    @staticmethod
    def validate_memory(limits: MemoryLimits) -> None:
        if limits.min_mb < 1:
            raise ValueError("Minimum memory must be at least 1 MB")
        if limits.max_mb < limits.min_mb:
            raise ValueError("Maximum memory must be >= minimum memory")
        if limits.working_set_min_mb > limits.max_mb:
            raise ValueError("Working set minimum exceeds maximum memory")
        if limits.working_set_max_mb > limits.max_mb:
            raise ValueError("Working set maximum exceeds maximum memory")
        if limits.working_set_max_mb < limits.working_set_min_mb:
            raise ValueError("Working set maximum must be >= minimum")

    @staticmethod
    def validate_disk(limits: DiskLimits) -> None:
        if limits.min_size_mb < 10:
            raise ValueError("Minimum disk size must be at least 10 MB")
        if limits.max_size_mb < limits.min_size_mb:
            raise ValueError("Maximum disk size must be >= minimum size")
        if limits.max_iops < 1:
            raise ValueError("Maximum IOPS must be at least 1")

    @classmethod
    def validate_all(cls, limits: ResourceLimits) -> None:
        cls.validate_cpu(limits.cpu)
        cls.validate_memory(limits.memory)
        cls.validate_disk(limits.disk)


@dataclass(slots=True)
class ResourceUsage:
    cpu_percent: float = 0.0
    memory_mb: int = 0
    disk_read_mbps: float = 0.0
    disk_write_mbps: float = 0.0
    disk_iops: int = 0

    def clone(self) -> "ResourceUsage":
        return ResourceUsage(
            cpu_percent=float(self.cpu_percent),
            memory_mb=int(self.memory_mb),
            disk_read_mbps=float(self.disk_read_mbps),
            disk_write_mbps=float(self.disk_write_mbps),
            disk_iops=int(self.disk_iops),
        )

    def check_violations(self, limits: ResourceLimits) -> list[str]:
        violations: list[str] = []

        if self.cpu_percent > float(limits.cpu.max_usage_percent):
            violations.append(
                f"CPU usage {self.cpu_percent:.1f}% exceeds limit {limits.cpu.max_usage_percent}%"
            )

        if self.memory_mb > limits.memory.max_mb:
            violations.append(
                f"Memory usage {self.memory_mb} MB exceeds limit {limits.memory.max_mb} MB"
            )

        if self.disk_iops > limits.disk.max_iops:
            violations.append(f"Disk IOPS {self.disk_iops} exceeds limit {limits.disk.max_iops}")

        if self.disk_read_mbps > float(limits.disk.max_read_mbps):
            violations.append(
                f"Disk read {self.disk_read_mbps:.1f} MB/s exceeds limit {limits.disk.max_read_mbps} MB/s"
            )

        if self.disk_write_mbps > float(limits.disk.max_write_mbps):
            violations.append(
                f"Disk write {self.disk_write_mbps:.1f} MB/s exceeds limit {limits.disk.max_write_mbps} MB/s"
            )

        return violations
