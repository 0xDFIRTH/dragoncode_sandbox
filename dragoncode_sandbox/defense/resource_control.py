import ctypes
from ctypes import wintypes
import os

# --- Constants & Structures ---

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ('ReadOperationCount', ctypes.c_ulonglong),
        ('WriteOperationCount', ctypes.c_ulonglong),
        ('OtherOperationCount', ctypes.c_ulonglong),
        ('ReadTransferCount', ctypes.c_ulonglong),
        ('WriteTransferCount', ctypes.c_ulonglong),
        ('OtherTransferCount', ctypes.c_ulonglong)
    ]

class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('LimitFlags', wintypes.DWORD),
        ('MinimumWorkingSetSize', ctypes.c_size_t),
        ('MaximumWorkingSetSize', ctypes.c_size_t),
        ('ActiveProcessLimit', wintypes.DWORD),
        ('Affinity', ctypes.c_size_t),
        ('PriorityClass', wintypes.DWORD),
        ('SchedulingClass', wintypes.DWORD)
    ]

class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ('IoInfo', IO_COUNTERS),
        ('ProcessMemoryLimit', ctypes.c_size_t),
        ('JobMemoryLimit', ctypes.c_size_t),
        ('PeakProcessMemoryUsed', ctypes.c_size_t),
        ('PeakJobMemoryUsed', ctypes.c_size_t)
    ]

# JobObjectCpuRateControlInformation = 15
class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('ControlFlags', wintypes.DWORD),
        ('CpuRate', wintypes.DWORD), # Union with Weight, but for hard cap we use Rate
                                     # Actually, 10000 = 100%
    ]

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x00000001
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x00000004

class ProcessSandbox:
    def __init__(self, ram_limit_mb: int = 1024, cpu_limit_percent: int = 50):
        if os.name != 'nt':
            self.job_handle = None
            return

        self._kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.job_handle = self._kernel32.CreateJobObjectW(None, None)
        
        if not self.job_handle:
            raise ctypes.WinError(ctypes.get_last_error())

        self._configure_limits(ram_limit_mb, cpu_limit_percent)

    def _configure_limits(self, ram_mb: int, cpu_percent: int):
        # 1. basic limits (Kill on close, Memory)
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | 
            JOB_OBJECT_LIMIT_JOB_MEMORY | 
            JOB_OBJECT_LIMIT_PROCESS_MEMORY
        )
        
        mem_bytes = ram_mb * 1024 * 1024
        info.ProcessMemoryLimit = mem_bytes
        info.JobMemoryLimit = mem_bytes
        
        JobObjectExtendedLimitInformation = 9
        res = self._kernel32.SetInformationJobObject(
            self.job_handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info)
        )
        if not res:
            print(f"[Sandbox] Warning: Failed to set RAM limit ({ram_mb}MB)")

        # 2. CPU limits (if supported, Win8+)
        # rate is 1-10000 (100.00%)
        # cpu_percent is 1-100
        cpu_info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
        cpu_info.ControlFlags = (
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | 
            JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        )
        cpu_info.CpuRate = cpu_percent * 100 # scaling
        
        JobObjectCpuRateControlInformation = 15
        res = self._kernel32.SetInformationJobObject(
            self.job_handle,
            JobObjectCpuRateControlInformation,
            ctypes.byref(cpu_info),
            ctypes.sizeof(cpu_info)
        )
        # Failure is common on older Windows or nested jobs, we ignore it silently or log

    def add_process(self, pid: int) -> bool:
        if not self.job_handle: return False

        PROCESS_SET_QUOTA = 0x0100
        PROCESS_TERMINATE = 0x0001
        h_process = self._kernel32.OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE, 
            False, 
            pid
        )
        
        if not h_process:
            return False

        try:
            res = self._kernel32.AssignProcessToJobObject(self.job_handle, h_process)
            return bool(res)
        finally:
            self._kernel32.CloseHandle(h_process)

    def close(self):
        if self.job_handle:
            self._kernel32.CloseHandle(self.job_handle)
            self.job_handle = None
