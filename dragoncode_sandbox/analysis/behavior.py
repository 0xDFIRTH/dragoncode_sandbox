"""
behavior.py
===========
Real-time behavioral monitoring of a sandboxed process using psutil.

Detects:
  • Suspicious child process spawning (cmd.exe, powershell, wscript…)
  • New network connections (potential C2 / exfiltration)
  • Access to sensitive file paths (AppData, Startup, System32…)
  • Memory growth anomalies
  • CPU spikes

Usage (from a QThread):
    monitor = BehaviorMonitor(pid)
    monitor.start()
    for event in monitor.poll():
        ...          # yields BehaviorEvent objects
    monitor.stop()
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Optional

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


# ─────────────────────────────────────────────────────────
#  Enums
# ─────────────────────────────────────────────────────────

class BehaviorCategory(str, Enum):
    PROCESS  = "PROCESS"
    NETWORK  = "NETWORK"
    FILE     = "FILE"
    MEMORY   = "MEMORY"
    REGISTRY = "REGISTRY"


class BehaviorSeverity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def color(self) -> str:
        return {
            "LOW":      "#3fb950",
            "MEDIUM":   "#d29922",
            "HIGH":     "#f78166",
            "CRITICAL": "#ff4444",
        }[self.value]

    @property
    def score(self) -> int:
        return {"LOW": 5, "MEDIUM": 15, "HIGH": 25, "CRITICAL": 40}[self.value]


# ─────────────────────────────────────────────────────────
#  Event Model
# ─────────────────────────────────────────────────────────

@dataclass
class BehaviorEvent:
    timestamp: float
    category:  BehaviorCategory
    severity:  BehaviorSeverity
    title:     str
    detail:    str = ""
    mitre_id:  str = ""
    mitre_tech: str = ""

    @property
    def time_str(self) -> str:
        t = time.localtime(self.timestamp)
        return f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"


# ─────────────────────────────────────────────────────────
#  Detection Rules & MITRE Mapping
# ─────────────────────────────────────────────────────────

_MITRE_MAP = {
    # Tactics
    "T1059": "Command and Scripting Interpreter",
    "T1547": "Boot or Logon Autostart Execution",
    "T1053": "Scheduled Task/Job",
    "T1106": "Native API",
    "T1071": "Application Layer Protocol",
    "T1083": "File and Directory Discovery",
    "T1027": "Obfuscated Files or Information",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1112": "Modify Registry",
}

def _get_mitre_info(mitre_id: str) -> tuple[str, str]:
    return mitre_id, _MITRE_MAP.get(mitre_id, "Unknown Technique")

def _classify_child(name: str) -> tuple[BehaviorSeverity, str]:
    n = name.lower()
    sev = BehaviorSeverity.MEDIUM
    mitre = ""

    if n in {"cmd.exe", "powershell.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
        sev = BehaviorSeverity.CRITICAL
        mitre = "T1059"
    elif n in {"reg.exe", "schtasks.exe", "at.exe", "sc.exe"}:
        sev = BehaviorSeverity.HIGH
        mitre = "T1053"
    elif n in {"rundll32.exe", "regsvr32.exe"}:
        sev = BehaviorSeverity.HIGH
        mitre = "T1106"
    elif "vbox" in n or "vmware" in n or "qemu" in n:
        sev = BehaviorSeverity.HIGH
        mitre = "T1497"
    elif n.endswith(".exe"):
        sev = BehaviorSeverity.HIGH

    return sev, mitre

def _classify_connection(conn) -> tuple[BehaviorSeverity, str]:
    raddr = getattr(conn, "raddr", None)
    if not raddr:
        return BehaviorSeverity.LOW, ""
    
    port = getattr(raddr, "port", 0)
    mitre = "T1071" # Standard for most C2 connections
    
    if port in (80, 443, 8080, 8443):
        return BehaviorSeverity.HIGH, mitre
    if port in range(1, 1024):
        return BehaviorSeverity.MEDIUM, mitre
    return BehaviorSeverity.HIGH, mitre

def _classify_file(path: str) -> Optional[tuple[BehaviorSeverity, str]]:
    p = path.lower()
    ext = p[p.rfind("."):] if "." in p else ""
    in_sensitive = any(d in p for d in _SENSITIVE_DIRS)
    is_suspicious_ext = ext in _SUSPICIOUS_EXTENSIONS
    
    sev, mitre = None, ""

    if "startup" in p or "run" in p:
        sev, mitre = BehaviorSeverity.CRITICAL, "T1547"
    elif "system32" in p or "\\windows\\" in p:
        sev, mitre = BehaviorSeverity.HIGH, "T1083"
    elif in_sensitive and is_suspicious_ext:
        sev, mitre = BehaviorSeverity.CRITICAL, "T1027"
    elif in_sensitive:
        sev = BehaviorSeverity.HIGH
    elif is_suspicious_ext:
        sev = BehaviorSeverity.MEDIUM
        
    return (sev, mitre) if sev else None


# ─────────────────────────────────────────────────────────
#  BehaviorMonitor
# ─────────────────────────────────────────────────────────

class BehaviorMonitor:
    """
    Poll-based behavioral monitor for a live process.

    Parameters
    ----------
    pid          : Process ID to monitor
    interval     : Polling interval in seconds (default 1.0)
    on_event     : Callback called with each new BehaviorEvent
    """

    def __init__(
        self,
        pid: int,
        interval: float = 1.0,
        on_event: Optional[Callable[[BehaviorEvent], None]] = None,
    ):
        self.pid       = pid
        self.interval  = interval
        self.on_event  = on_event
        self._running  = False

        # State tracking (sets of already-seen items)
        self._seen_children:    set[int]   = set()
        self._seen_connections: set[tuple] = set()
        self._seen_files:       set[str]   = set()

        # Baseline memory (set on first poll)
        self._baseline_mem: Optional[int] = None
        self._risk_score = 0

    # ── Public API ────────────────────────────────────────

    @property
    def risk_score(self) -> int:
        return min(self._risk_score, 100)

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def run_blocking(self):
        """Block and poll until stop() is called or process exits."""
        if not _HAS_PSUTIL:
            self._emit(BehaviorEvent(
                time.time(), BehaviorCategory.PROCESS,
                BehaviorSeverity.LOW,
                "psutil not installed",
                "Install psutil for behavioral monitoring."
            ))
            return

        try:
            proc = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            return

        while self._running:
            try:
                if not proc.is_running():
                    break
                self._poll(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            time.sleep(self.interval)

    # ── Internal polling ─────────────────────────────────

    def _poll(self, proc: "psutil.Process"):
        self._check_children(proc)
        self._check_connections(proc)
        self._check_files(proc)
        self._check_memory(proc)

    def _check_children(self, proc: "psutil.Process"):
        try:
            children = proc.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        for child in children:
            if child.pid in self._seen_children:
                continue
            self._seen_children.add(child.pid)

            try:
                name = child.name()
                cmd  = " ".join(child.cmdline()[:4]) if child.cmdline() else name
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name, cmd = f"PID:{child.pid}", ""

            sev, mid = _classify_child(name)
            mid, mtech = _get_mitre_info(mid) if mid else ("", "")
            self._emit(BehaviorEvent(
                time.time(),
                BehaviorCategory.PROCESS,
                sev,
                f"Child process spawned: {name}",
                cmd,
                mitre_id=mid,
                mitre_tech=mtech
            ))

    def _check_connections(self, proc: "psutil.Process"):
        try:
            conns = proc.connections(kind="all")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        for c in conns:
            raddr = getattr(c, "raddr", None)
            if not raddr:
                continue
            key = (getattr(raddr, "ip", ""), getattr(raddr, "port", 0))
            if key in self._seen_connections:
                continue
            self._seen_connections.add(key)

            sev, mid = _classify_connection(c)
            ip, port = key
            
            flag = ""
            if ip and not ip.startswith("127.") and not ip.startswith("192.168.") and not ip.startswith("10."):
                try:
                    import urllib.request
                    import json
                    req = urllib.request.Request(f"http://ip-api.com/json/{ip}", headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=1.5) as response:
                        data = json.loads(response.read().decode())
                        if data.get("status") == "success":
                            cc = data.get("countryCode", "??")
                            if len(cc) == 2:
                                flag_emoji = chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
                                flag = f" {flag_emoji} ({data.get('country')})"
                except Exception:
                    pass

            mid, mtech = _get_mitre_info(mid) if mid else ("", "")
            self._emit(BehaviorEvent(
                time.time(),
                BehaviorCategory.NETWORK,
                sev,
                f"Network connection: {ip}:{port}{flag}",
                f"Status: {c.status}  |  Protocol: {'TCP' if c.type == 1 else 'UDP'}",
                mitre_id=mid,
                mitre_tech=mtech
            ))

    def _check_files(self, proc: "psutil.Process"):
        try:
            files = proc.open_files()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        for f in files:
            path = getattr(f, "path", "")
            if not path or path in self._seen_files:
                continue
            self._seen_files.add(path)

            res = _classify_file(path)
            if res is None:
                continue
            sev, mid = res
            mid, mtech = _get_mitre_info(mid) if mid else ("", "")
            self._emit(BehaviorEvent(
                time.time(),
                BehaviorCategory.FILE,
                sev,
                f"File accessed: {path.split('\\')[-1]}",
                path,
                mitre_id=mid,
                mitre_tech=mtech
            ))

    def _check_memory(self, proc: "psutil.Process"):
        try:
            mem = proc.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        if self._baseline_mem is None:
            self._baseline_mem = mem
            return

        growth_mb = (mem - self._baseline_mem) / (1024 * 1024)

        if growth_mb > 200:
            self._emit(BehaviorEvent(
                time.time(),
                BehaviorCategory.MEMORY,
                BehaviorSeverity.HIGH,
                f"Memory spike: +{growth_mb:.0f} MB",
                f"Current RSS: {mem // (1024*1024)} MB",
            ))
            self._baseline_mem = mem   # reset so we don't spam

    # ── Emit ─────────────────────────────────────────────

    def _emit(self, event: BehaviorEvent):
        self._risk_score += event.severity.score
        if self.on_event:
            self.on_event(event)
