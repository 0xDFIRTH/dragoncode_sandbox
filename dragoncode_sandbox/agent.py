import sys
import os
import time
import json
import subprocess
import ctypes
from datetime import datetime

# Add C:\Project to path so we can import modules
sys.path.append("C:\\Project")

try:
    from dragoncode_sandbox.analysis.memory import MemoryScanner
    from dragoncode_sandbox.analysis.static import StaticEngine
except ImportError:
    # Fallback if structure is different
    sys.path.append("C:\\Project\\dragoncode_sandbox")
    pass

def capture_registry():
    import winreg
    try:
        from dragoncode_sandbox.registry.virtualization import RegistryKey
    except ImportError:
        return None
        
    root = RegistryKey('HKLM')
    paths_to_monitor = [
        'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
    ]
    
    for key_path in paths_to_monitor:
        sub = RegistryKey(key_path)
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(key, i)
                        sub.values[n] = str(v)
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
        root.subkeys[key_path] = sub
        
    return root

def analyze_target(target_path):
    print(f"[*] Analyzing target: {target_path}")
    
    report = {
        "timestamp": str(datetime.now()),
        "target": os.path.basename(target_path),
        "static": {},
        "dynamic": [],
        "behavior": [],
        "registry_alerts": [],
        "verdict": "Scanning..."
    }
    
    # ── Load Sandbox Config (written by Host GUI) ──
    cfg_path = "C:\\Project\\sandbox_config.json"
    cfg = {}
    try:
        if os.path.exists(cfg_path):
            with open(cfg_path, "r") as cf:
                cfg = json.load(cf)
            print(f"[*] Loaded sandbox_config: {cfg}")
        else:
            print("[*] No sandbox_config.json found, using defaults.")
    except Exception as e:
        print(f"[!] Config load error: {e}")

    timeout_sec    = int(cfg.get("timeout_sec", 15))
    enable_memory  = bool(cfg.get("enable_memory", True))
    enable_registry = bool(cfg.get("enable_registry", True))
    block_network  = bool(cfg.get("block_network", False))

    # ── Registry Snapshot Before ──
    snap_before = None
    if enable_registry:
        print("[*] Taking pre-execution Registry Snapshot...")
        snap_before = capture_registry()
    else:
        print("[*] Registry monitoring DISABLED by settings.")

    print("[*] Launching process...")
    try:
        proc = subprocess.Popen([target_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
        pid = proc.pid
        print(f"[+] Process launched. PID: {pid}")
        
        # ── Setup Behavior & Network Monitoring ──
        monitor = None
        proc_obj = None
        try:
            import psutil
            import urllib.request
            from dragoncode_sandbox.analysis.behavior import BehaviorMonitor, BehaviorEvent
            
            def _on_beh_event(ev: BehaviorEvent):
                # Serialize properly
                report["behavior"].append({
                    "time_str": ev.time_str,
                    "category": ev.category.value,
                    "severity": ev.severity.value,
                    "title": ev.title,
                    "detail": ev.detail,
                    "score_weight": ev.severity.score
                })
                print(f"[!] {ev.category.value} [{ev.severity.value}]: {ev.title}")

            proc_obj = psutil.Process(pid)
            monitor = BehaviorMonitor(pid, 0.5, _on_beh_event)
            monitor._baseline_mem = proc_obj.memory_info().rss
        except Exception as e:
            print(f"[-] Behavior Monitor not available: {e}")
        
        # ── Apply Network Isolation if requested ──
        if block_network:
            try:
                from dragoncode_sandbox.defense.response_actions import NetworkActions
                NetworkActions.isolate_host()
                print("[*] Network isolation applied inside Sandbox VM.")
            except Exception as e:
                print(f"[!] Network isolation failed: {e}")

        # Scan Loop — duration controlled by timeout_sec setting
        deadline = time.time() + timeout_sec
        print(f"[*] Scanning for {timeout_sec}s (memory={'ON' if enable_memory else 'OFF'})...")
        while time.time() < deadline:
            # Memory Scanning
            if enable_memory:
                try:
                    from dragoncode_sandbox.analysis.memory import MemoryScanner
                    found = MemoryScanner.scan_process(None, pid)
                    for t in found:
                        alert = str(t)
                        if alert not in report["dynamic"]:
                            print(f"[!] MEMORY THREAT: {alert}")
                            report["dynamic"].append(alert)
                except Exception:
                    pass

            # Behavioral & Network Polling
            if monitor and proc_obj:
                try:
                    if proc_obj.is_running():
                        monitor._poll(proc_obj)
                except Exception:
                    pass

            if proc.poll() is not None:
                print("[*] Process exited early.")
                break

            time.sleep(0.5)

        if proc.poll() is None:
            proc.terminate()

            
    except Exception as e:
        print(f"[!] Execution failed: {e}")
        report["error"] = str(e)

    # ── Registry Snapshot & Diff After ──
    if snap_before:
        print("[*] Taking post-execution Registry Snapshot to detect changes...")
        snap_after = capture_registry()
        try:
            from dragoncode_sandbox.registry.diff import RegistryDiff
            diff = RegistryDiff.compare(snap_before, snap_after)
            alerts = diff.detect_anomalies()
            for al in alerts:
                report["registry_alerts"].append({
                    "path": al.path,
                    "severity": al.severity,
                    "technique": al.technique,
                    "description": al.description
                })
                print(f"[!] REGISTRY THREAT: {al.description} -> {al.path}")
        except Exception as e:
            print(f"[!] Registry diffing failed: {e}")

    # Write Report
    report_filename = f"sandbox_report_{os.path.basename(target_path)}.json"
    report_path = os.path.join("C:\\Project", report_filename)
    print(f"[*] Writing report to {report_path}")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

def _execute_command(cmd: dict) -> dict:
    """Execute a response command inside the Sandbox VM using response_actions."""
    action  = cmd.get("action", "")
    params  = cmd.get("params", {})
    ok      = False
    detail  = ""

    try:
        from dragoncode_sandbox.defense.response_actions import (
            ProcessActions, FileActions, NetworkActions,
            PersistenceActions, SystemActions
        )

        if action == "kill_process":
            ok = ProcessActions.kill_process(int(params["pid"]))
        elif action == "kill_process_tree":
            ok = ProcessActions.kill_process_tree(int(params["pid"]))
        elif action == "suspend_process":
            ok = ProcessActions.suspend_process(int(params["pid"]))
        elif action == "quarantine_file":
            ok = FileActions.quarantine(params["path"])
        elif action == "secure_delete_file":
            ok = FileActions.secure_delete(params["path"])
        elif action == "block_ip":
            ok = NetworkActions.block_ip(params["ip"])
        elif action == "block_domain":
            ok = NetworkActions.block_domain(params["domain"])
        elif action == "block_port":
            ok = NetworkActions.block_port(int(params["port"]))
        elif action == "kill_connections":
            ok = NetworkActions.kill_connections(int(params["pid"]))
        elif action == "isolate_host":
            ok = NetworkActions.isolate_host()
        elif action == "clean_autorun":
            ok = PersistenceActions.clean_autorun_keys()
        elif action == "lock_run_key":
            ok = PersistenceActions.lock_run_key()
        elif action == "delete_scheduled_task":
            ok = PersistenceActions.delete_scheduled_task(params["task_name"])
        elif action == "stop_service":
            ok = PersistenceActions.stop_service(params["service_name"])
        elif action == "full_containment":
            results = SystemActions.full_containment(
                pid=int(params["pid"]) if params.get("pid") else None,
                image_path=params.get("image_path")
            )
            ok     = any(results.values())
            detail = str(results)
        else:
            detail = f"Unknown action: {action}"
    except Exception as e:
        detail = str(e)

    print(f"[Agent CMD] {action} -> {'OK' if ok else 'FAIL'} {detail}")
    return {"id": cmd.get("id"), "action": action, "ok": ok, "detail": detail}


def run_agent():
    print(f"[*] AGENT STARTED inside Windows Sandbox")
    tasks_dir    = "C:\\Project\\tasks"
    commands_dir = "C:\\Project\\commands"
    results_dir  = "C:\\Project\\commands\\results"

    for d in [tasks_dir, commands_dir, results_dir]:
        if not os.path.exists(d):
            os.makedirs(d)

    print(f"[*] Monitoring {tasks_dir} for new executables...")
    print(f"[*] Monitoring {commands_dir} for defense commands...")

    handled_files = set()

    while True:
        try:
            # ── 1. Heartbeat ping/pong ──────────────────────────────────
            ping_file = os.path.join(tasks_dir, "ping.txt")
            if os.path.exists(ping_file):
                try:
                    os.remove(ping_file)
                    with open(os.path.join(tasks_dir, "pong.txt"), "w") as f:
                        f.write("ready")
                except:
                    pass

            # ── 2. Task queue: new executables ──────────────────────────
            for f in os.listdir(tasks_dir):
                if f.lower().endswith(('.exe', '.dll', '.bin')) and f not in handled_files:
                    target_path = os.path.join(tasks_dir, f)
                    time.sleep(0.5)
                    analyze_target(target_path)
                    try:
                        os.remove(target_path)
                        print(f"[*] Task file removed: {f}")
                    except Exception as e:
                        print(f"[!] Could not remove task file: {e}")
                    handled_files.add(f)
                    print(f"[*] Waiting for next task...")

            # ── 3. Command queue: response actions from Host ─────────────
            for fname in os.listdir(commands_dir):
                if not fname.startswith("cmd_") or not fname.endswith(".json"):
                    continue
                cmd_path = os.path.join(commands_dir, fname)
                try:
                    with open(cmd_path, "r") as cf:
                        cmd = json.load(cf)
                    os.remove(cmd_path)   # consume the command
                    result = _execute_command(cmd)
                    # Write result for Host to read
                    result_path = os.path.join(
                        results_dir, f"result_{cmd.get('id', 'unknown')}.json"
                    )
                    with open(result_path, "w") as rf:
                        json.dump(result, rf, indent=2)
                except Exception as e:
                    print(f"[!] Command processing error: {e}")

        except Exception as e:
            print(f"[!] Monitor error: {e}")

        time.sleep(0.5)  # Fast polling mode

if __name__ == "__main__":
    run_agent()
