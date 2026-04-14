"""
response_actions.py
===================
Active defense response actions for DragonCode Sandbox.

Provides a suite of containment primitives that can be invoked automatically
after a Malicious verdict is issued, or triggered manually from the GUI.

Classes
-------
ProcessActions   – Kill / suspend / degrade / quarantine hostile processes.
FileActions      – Quarantine / secure-delete / ACL-deny malicious files.
NetworkActions   – Block IPs, domains, ports; full host-network isolation.
PersistenceActions – Remove autorun entries, scheduled tasks, and services.
RegistryActions  – Restore / lock critical registry keys.
SystemActions    – Hardened-mode toggle and full host isolation.

All methods return bool: True = action succeeded, False = best-effort failed.
"""

from __future__ import annotations

import ctypes
import os
import random
import subprocess
import sys
from typing import Optional

# ---------------------------------------------------------------------------
# Win32 Primitives
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    _kernel32 = ctypes.windll.kernel32
    _ntdll    = ctypes.windll.ntdll

    PROCESS_TERMINATE        = 0x0001
    PROCESS_SUSPEND_RESUME   = 0x0800
    PROCESS_SET_INFORMATION  = 0x0200

    class _PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize",             ctypes.c_ulong),
            ("cntUsage",           ctypes.c_ulong),
            ("th32ProcessID",      ctypes.c_ulong),
            ("th32DefaultHeapID",  ctypes.c_ulong),
            ("th32ModuleID",       ctypes.c_ulong),
            ("cntThreads",         ctypes.c_ulong),
            ("th32ParentProcessID",ctypes.c_ulong),
            ("pcPriClassBase",     ctypes.c_long),
            ("dwFlags",            ctypes.c_ulong),
            ("szExeFile",          ctypes.c_char * 260),
        ]
    TH32CS_SNAPPROCESS = 0x00000002
else:
    _kernel32 = None
    _ntdll    = None


def _ps(cmd: str) -> bool:
    """Run a hidden PowerShell command. Returns True on best-effort success."""
    try:
        full = f'powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command "{cmd}"'
        subprocess.run(full, shell=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def _icacls(path: str, rule: str) -> bool:
    try:
        subprocess.run(
            f'icacls "{path}" {rule}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except Exception:
        return False


def _safe_rename(path: str) -> bool:
    try:
        dirname  = os.path.dirname(path)
        basename = os.path.basename(path)
        new_name = os.path.join(dirname, f"_{basename}_{random.randint(1000, 9999)}.blocked")
        os.rename(path, new_name)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ProcessActions
# ---------------------------------------------------------------------------

class ProcessActions:
    """Terminates, suspends, or degrades hostile processes."""

    @staticmethod
    def kill_process(pid: int) -> bool:
        """Hard-terminate → taskkill → suspend (layered fallback)."""
        if not _kernel32:
            return False
        try:
            h = _kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if h and _kernel32.TerminateProcess(h, 1):
                _kernel32.CloseHandle(h)
                return True
        except Exception:
            pass
        if subprocess.run(
            f"taskkill /F /PID {pid}", shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0:
            return True
        if _ps(f"Stop-Process -Id {pid} -Force"):
            return True
        return ProcessActions.suspend_process(pid)

    @staticmethod
    def kill_process_tree(pid: int) -> bool:
        """Recursively kills all child processes, then the parent."""
        if not _kernel32:
            return False
        try:
            h_snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            pe = _PROCESSENTRY32()
            pe.dwSize = ctypes.sizeof(_PROCESSENTRY32)
            children: list[int] = []
            if _kernel32.Process32First(h_snap, ctypes.byref(pe)):
                while True:
                    if pe.th32ParentProcessID == pid:
                        children.append(pe.th32ProcessID)
                    if not _kernel32.Process32Next(h_snap, ctypes.byref(pe)):
                        break
            _kernel32.CloseHandle(h_snap)
            for c in children:
                ProcessActions.kill_process_tree(c)
        except Exception:
            pass
        return ProcessActions.kill_process(pid)

    @staticmethod
    def suspend_process(pid: int) -> bool:
        """Freeze process via NtSuspendProcess → degrade on failure."""
        if not _kernel32 or not _ntdll:
            return False
        try:
            h = _kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
            if h:
                _ntdll.NtSuspendProcess(h)
                _kernel32.CloseHandle(h)
                return True
        except Exception:
            pass
        return ProcessActions.lower_priority(pid)

    @staticmethod
    def lower_priority(pid: int) -> bool:
        """Degrade process to idle priority / background mode."""
        if not _kernel32:
            return False
        try:
            h = _kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
            if h:
                _kernel32.SetPriorityClass(h, 0x40)            # IDLE_PRIORITY_CLASS
                _kernel32.SetPriorityClass(h, 0x00100000)       # PROCESS_MODE_BACKGROUND_BEGIN
                _kernel32.CloseHandle(h)
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def block_image_execution(image_path: str) -> bool:
        """Prevent re-execution of a file: ACL-deny → rename → header corrupt."""
        if FileActions.deny_execute(image_path):
            return True
        if _safe_rename(image_path):
            return True
        try:
            with open(image_path, "r+b") as f:
                f.seek(0)
                f.write(b"DEAD")
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# FileActions
# ---------------------------------------------------------------------------

class FileActions:
    """Quarantine, delete, or ACL-restrict malicious files."""

    @staticmethod
    def delete_file(path: str) -> bool:
        try:
            os.remove(path)
            return True
        except Exception:
            pass
        try:
            os.chmod(path, 0o777)
            os.remove(path)
            return True
        except Exception:
            pass
        return _safe_rename(path)

    @staticmethod
    def secure_delete(path: str) -> bool:
        """Overwrite with random bytes, then delete."""
        try:
            size = os.path.getsize(path)
            with open(path, "wb") as f:
                f.write(os.urandom(size))
        except Exception:
            pass
        return FileActions.delete_file(path)

    @staticmethod
    def quarantine(path: str) -> bool:
        """Move file to <original>.quarantine to disable execution."""
        import shutil
        try:
            shutil.move(path, path + ".quarantine")
            return True
        except Exception:
            return _safe_rename(path)

    @staticmethod
    def deny_execute(path: str) -> bool:
        return _icacls(path, '/deny Everyone:(RX)')

    @staticmethod
    def deny_write(path: str) -> bool:
        try:
            os.chmod(path, 0o444)
        except Exception:
            pass
        return _icacls(path, '/deny Everyone:(W)')

    @staticmethod
    def schedule_delete_on_reboot(path: str) -> bool:
        """MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT."""
        if not _kernel32:
            return False
        try:
            _kernel32.MoveFileExW(path, None, 0x4)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# NetworkActions
# ---------------------------------------------------------------------------

class NetworkActions:
    """Firewall-based IP/domain/port blocking and full host isolation."""

    @staticmethod
    def block_ip(ip: str, direction: str = "out") -> bool:
        """Add a Windows Firewall rule to block an IP (outbound by default)."""
        name = f"DC_BLOCK_{ip.replace('.', '_')}"
        cmd = (
            f'netsh advfirewall firewall add rule name="{name}" '
            f'dir={direction} action=block remoteip={ip}'
        )
        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    @staticmethod
    def block_domain(domain: str) -> bool:
        """Redirect domain to localhost via hosts file."""
        try:
            with open(r"C:\Windows\System32\drivers\etc\hosts", "a") as f:
                f.write(f"\n127.0.0.1 {domain}\n")
            return True
        except Exception:
            return False

    @staticmethod
    def block_port(port: int, protocol: str = "TCP") -> bool:
        name = f"DC_BLOCK_PORT_{port}"
        cmd = (
            f'netsh advfirewall firewall add rule name="{name}" '
            f'dir=out action=block localport={port} protocol={protocol}'
        )
        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    @staticmethod
    def kill_connections(pid: int) -> bool:
        """Terminate all TCP connections owned by a PID."""
        return _ps(
            f"Get-NetTCPConnection -OwningProcess {pid} "
            f"| Remove-NetTCPConnection -Confirm:$false"
        )

    @staticmethod
    def isolate_host() -> bool:
        """Full outbound block — nuclear option."""
        try:
            subprocess.run("netsh advfirewall set allprofiles state on",
                           shell=True, stdout=subprocess.DEVNULL)
            subprocess.run(
                'netsh advfirewall firewall add rule name="DC_ISOLATE_IN" '
                'dir=in action=block',
                shell=True, stdout=subprocess.DEVNULL
            )
            subprocess.run(
                'netsh advfirewall firewall add rule name="DC_ISOLATE_OUT" '
                'dir=out action=block',
                shell=True, stdout=subprocess.DEVNULL
            )
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# PersistenceActions
# ---------------------------------------------------------------------------

class PersistenceActions:
    """Remove persistence mechanisms planted by malware."""

    @staticmethod
    def clean_autorun_keys() -> bool:
        """Delete all values from HKCU\\...\\Run."""
        try:
            subprocess.run(
                "reg delete "
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /va /f",
                shell=True, stdout=subprocess.DEVNULL
            )
            return True
        except Exception:
            return False

    @staticmethod
    def lock_run_key() -> bool:
        """ACL-deny writes to the HKCU Run key so malware cannot re-add itself."""
        ps = (
            "$k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';"
            "$acl=Get-Acl $k;"
            "$r=New-Object System.Security.AccessControl.RegistryAccessRule("
            "'Everyone','WriteKey','Deny');"
            "$acl.SetAccessRule($r);Set-Acl $k $acl"
        )
        return _ps(ps)

    @staticmethod
    def delete_scheduled_task(task_name: str) -> bool:
        try:
            subprocess.run(
                f'schtasks /delete /tn "{task_name}" /f',
                shell=True, stdout=subprocess.DEVNULL
            )
            return True
        except Exception:
            return False

    @staticmethod
    def disable_scheduled_task(task_name: str) -> bool:
        try:
            subprocess.run(
                f'schtasks /change /tn "{task_name}" /disable',
                shell=True, stdout=subprocess.DEVNULL
            )
            return True
        except Exception:
            return False

    @staticmethod
    def stop_service(service_name: str) -> bool:
        try:
            subprocess.run(f'sc stop "{service_name}"', shell=True,
                           stdout=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    @staticmethod
    def delete_service(service_name: str) -> bool:
        try:
            subprocess.run(f'sc delete "{service_name}"', shell=True,
                           stdout=subprocess.DEVNULL)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# RegistryActions
# ---------------------------------------------------------------------------

class RegistryActions:
    """Restore or lock critical registry keys."""

    @staticmethod
    def restore_value(key: str, name: str, data: str) -> bool:
        try:
            subprocess.run(
                f'reg add "{key}" /v "{name}" /d "{data}" /f',
                shell=True, stdout=subprocess.DEVNULL
            )
            return True
        except Exception:
            return False

    @staticmethod
    def lock_key(key: str) -> bool:
        """ACL-deny FullControl to Everyone for a given registry key."""
        ps_key = key.replace("HKCU", "HKCU:").replace("HKLM", "HKLM:")
        ps = (
            f"$acl=Get-Acl '{ps_key}';"
            "$r=New-Object System.Security.AccessControl.RegistryAccessRule("
            "'Everyone','FullControl','Deny');"
            "$acl.SetAccessRule($r);"
            f"Set-Acl '{ps_key}' $acl"
        )
        return _ps(ps)


# ---------------------------------------------------------------------------
# SystemActions
# ---------------------------------------------------------------------------

class SystemActions:
    """High-level containment: hardened mode, USB lockout, full isolation."""

    @staticmethod
    def enable_hardened_mode() -> bool:
        """Enable UAB prompt + block PowerShell + block script engines."""
        try:
            subprocess.run(
                "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                "\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f",
                shell=True, stdout=subprocess.DEVNULL
            )
        except Exception:
            pass
        ProcessActions.block_image_execution(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        )
        ProcessActions.block_image_execution(
            r"C:\Windows\System32\wscript.exe"
        )
        ProcessActions.block_image_execution(
            r"C:\Windows\System32\cscript.exe"
        )
        return True

    @staticmethod
    def disable_usb() -> bool:
        try:
            subprocess.run(
                "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR "
                "/v Start /t REG_DWORD /d 4 /f",
                shell=True, stdout=subprocess.DEVNULL
            )
            return True
        except Exception:
            return False

    @staticmethod
    def full_containment(pid: Optional[int] = None,
                         image_path: Optional[str] = None) -> dict:
        """
        One-call nuclear containment:
        Kill process → isolate network → clean autorun → lock Run key.

        Returns a dict of action results.
        """
        results: dict[str, bool] = {}
        if pid:
            results["kill_tree"]         = ProcessActions.kill_process_tree(pid)
            results["kill_connections"]  = NetworkActions.kill_connections(pid)
        if image_path:
            results["quarantine_file"]   = FileActions.quarantine(image_path)
        results["isolate_network"]       = NetworkActions.isolate_host()
        results["clean_autorun"]         = PersistenceActions.clean_autorun_keys()
        results["lock_run_key"]          = PersistenceActions.lock_run_key()
        return results
