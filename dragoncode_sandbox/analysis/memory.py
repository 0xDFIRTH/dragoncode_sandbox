from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Union


@dataclass(frozen=True, slots=True)
class ReflectiveDllInjection:
    size: int


@dataclass(frozen=True, slots=True)
class ProcessHollowing:
    address: int
    reason: str


@dataclass(frozen=True, slots=True)
class ShellcodePattern:
    address: int
    pattern: str


@dataclass(frozen=True, slots=True)
class HighEntropyRegion:
    address: int
    entropy: float


@dataclass(frozen=True, slots=True)
class SuspiciousTransition:
    address: int


MemoryThreat = Union[
    ReflectiveDllInjection,
    ProcessHollowing,
    ShellcodePattern,
    HighEntropyRegion,
    SuspiciousTransition,
]


class MemoryScanner:
    @staticmethod
    def scan_process(process_handle: Optional[int], pid: int) -> list[MemoryThreat]:
        if os.name != "nt":
            return []
        if pid <= 0:
            return []

        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010

            MEM_COMMIT = 0x1000
            MEM_PRIVATE = 0x20000

            PAGE_GUARD = 0x100
            PAGE_NOACCESS = 0x01

            PAGE_EXECUTE = 0x10
            PAGE_EXECUTE_READ = 0x20
            PAGE_EXECUTE_READWRITE = 0x40
            PAGE_EXECUTE_WRITECOPY = 0x80

            PAGE_READWRITE = 0x04

            execute_family = (
                PAGE_EXECUTE
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
            )
            rw_family = PAGE_READWRITE | PAGE_EXECUTE_READWRITE

            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]

            OpenProcess = kernel32.OpenProcess
            OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            OpenProcess.restype = wintypes.HANDLE

            VirtualQueryEx = kernel32.VirtualQueryEx
            VirtualQueryEx.argtypes = [
                wintypes.HANDLE,
                ctypes.c_void_p,
                ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                ctypes.c_size_t,
            ]
            VirtualQueryEx.restype = ctypes.c_size_t

            ReadProcessMemory = kernel32.ReadProcessMemory
            ReadProcessMemory.argtypes = [
                wintypes.HANDLE,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
            ]
            ReadProcessMemory.restype = wintypes.BOOL

            CloseHandle = kernel32.CloseHandle
            CloseHandle.argtypes = [wintypes.HANDLE]
            CloseHandle.restype = wintypes.BOOL

            handle = wintypes.HANDLE(process_handle or 0)
            opened_here = False
            if not handle:
                handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
                opened_here = True

            if not handle:
                return []

            threats: list[MemoryThreat] = []
            address = 0
            mbi = MEMORY_BASIC_INFORMATION()
            mbi_size = ctypes.sizeof(MEMORY_BASIC_INFORMATION)

            while True:
                res = VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
                if res == 0:
                    break

                protect = int(mbi.Protect)
                state = int(mbi.State)
                mem_type = int(mbi.Type)

                if state != MEM_COMMIT or (protect & PAGE_GUARD) != 0 or (protect & PAGE_NOACCESS) != 0:
                    address += int(mbi.RegionSize)
                    continue

                region_size = int(mbi.RegionSize)
                if region_size <= 0:
                    break

                scan_size = min(region_size, 20 * 1024 * 1024)
                has_execute = (protect & execute_family) != 0
                has_write = (protect & rw_family) != 0

                if has_execute and scan_size > 0:
                    buf = ctypes.create_string_buffer(scan_size)
                    bytes_read = ctypes.c_size_t(0)
                    ReadProcessMemory(handle, ctypes.c_void_p(address), buf, scan_size, ctypes.byref(bytes_read))

                    if bytes_read.value:
                        data = buf.raw[: bytes_read.value]

                        if mem_type == MEM_PRIVATE and data.startswith(b"MZ"):
                            threats.append(
                                ProcessHollowing(
                                    address=address,
                                    reason="MZ header in Private/Non-Image memory (Manual Map)",
                                )
                            )

                        if b"\xFC\x48\x83\xE4" in data:
                            threats.append(
                                ShellcodePattern(
                                    address=address,
                                    pattern="Metasploit x64 shellcode prologue",
                                )
                            )

                        if _has_nop_sled(data, 16):
                            threats.append(
                                ShellcodePattern(
                                    address=address,
                                    pattern="Long NOP Sled detected",
                                )
                            )

                        entropy = _calculate_entropy(data)
                        if entropy > 7.5 and len(data) > 1024:
                            threats.append(HighEntropyRegion(address=address, entropy=entropy))

                if has_execute and has_write:
                    pass

                address += region_size

            if opened_here:
                CloseHandle(handle)

            return threats

        except Exception:
            return []


def _has_nop_sled(data: bytes, length: int) -> bool:
    if length <= 0:
        return False
    target = b"\x90" * length
    return target in data


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    length = float(len(data))
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * _log2(p)

    return entropy


def _log2(x: float) -> float:
    import math

    return math.log(x, 2)
