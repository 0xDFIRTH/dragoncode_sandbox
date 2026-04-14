from __future__ import annotations

import time
import os

try:
    import winreg
except ImportError:
    winreg = None
try:
    import psutil
except ImportError:
    psutil = None


class AntiVMCountermeasures:
    
    @staticmethod
    def check_vm_artifacts() -> list[str]:
        """Check for common VM artifacts in registry and processes."""
        found = []
        
        # 1. Check Processes
        if psutil:
            vm_processes = {'vmtoolsd.exe', 'vmacthlp.exe', 'vmsrvc.exe', 'vmusrvc.exe', 'vmwaretray.exe', 'vmwareuser.exe', 'vboxservice.exe', 'vboxtray.exe'}
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in vm_processes:
                    found.append(f"Process: {proc.info['name']}")

        # 2. Check Registry
        if winreg:
            keys_to_check = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\Description\System", "VideoBiosVersion", "virtualbox"),
            ]
            
            for entry in keys_to_check:
                try:
                    if len(entry) == 2:
                        # Just checking if key exists
                        hkey, subkey = entry
                        with winreg.OpenKey(hkey, subkey):
                            found.append(f"Registry Key: {subkey}")
                    elif len(entry) == 4:
                        # Checking if value contains substring
                        hkey, subkey, val_name, substring = entry
                        with winreg.OpenKey(hkey, subkey) as key:
                            val, _ = winreg.QueryValueEx(key, val_name)
                            if substring.lower() in str(val).lower():
                                found.append(f"Registry Value: {subkey}\\{val_name} = {val}")
                except OSError:
                    pass
        return found
        
    @staticmethod
    def check_cpuid_hypervisor() -> bool:
        # Without C extensions, we rely on artifacts.
        return len(AntiVMCountermeasures.check_vm_artifacts()) > 0

    @staticmethod
    def check_rdtsc_timing() -> bool:
        start = time.perf_counter_ns()
        for _ in range(1000):
            pass
        end = time.perf_counter_ns()
        delta = end - start
        return delta > 5_000_000

    @classmethod
    def emulate_fake_hardware(cls) -> None:
        print(f"Hypervisor Present (Artifacts): {cls.check_cpuid_hypervisor()}")
        print(f"RDTSC Timing Anomaly: {cls.check_rdtsc_timing()}")
