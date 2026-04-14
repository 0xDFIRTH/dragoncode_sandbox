"""
response_dispatcher.py
======================
Host-side command dispatcher for in-VM defense response.

The Host GUI can send structured containment commands to the Sandbox Agent
via the shared project folder (C:\\Project\\commands\\).

The Agent reads and executes these commands using response_actions.py,
which is also shipped inside the Sandbox, and writes results back to
C:\\Project\\commands\\results\\.

Command JSON format (written by Host):
{
    "id":      "uuid4 string",
    "action":  "kill_process | quarantine_file | block_ip | ...",
    "params":  { "pid": 1234, "ip": "1.2.3.4", ... }
}

Result JSON format (written by Agent):
{
    "id":     "<same uuid>",
    "action": "<same action>",
    "ok":     true | false,
    "detail": "optional message"
}
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any


class ResponseDispatcher:
    """
    Writes response commands into the shared sandbox folder so the in-VM
    agent can pick them up and execute them via response_actions.py.
    """

    SUPPORTED_ACTIONS = {
        "kill_process",
        "kill_process_tree",
        "suspend_process",
        "quarantine_file",
        "secure_delete_file",
        "block_ip",
        "block_domain",
        "block_port",
        "kill_connections",
        "isolate_host",
        "clean_autorun",
        "lock_run_key",
        "delete_scheduled_task",
        "stop_service",
        "full_containment",
    }

    def __init__(self, project_root: str = r"C:\Project"):
        self.commands_dir = Path(project_root) / "commands"
        self.results_dir  = self.commands_dir / "results"
        self.commands_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def send(self, action: str, params: dict[str, Any]) -> str:
        """
        Write a command file for the Agent to pick up.
        Returns the command ID for polling the result.
        """
        if action not in self.SUPPORTED_ACTIONS:
            raise ValueError(f"Unknown action: {action!r}")

        cmd_id  = str(uuid.uuid4())
        payload = {"id": cmd_id, "action": action, "params": params}
        cmd_file = self.commands_dir / f"cmd_{cmd_id}.json"
        cmd_file.write_text(json.dumps(payload, indent=2))
        print(f"[Dispatcher] Sent command: {action} (id={cmd_id[:8]})")
        return cmd_id

    def wait_result(self, cmd_id: str, timeout: float = 10.0) -> dict | None:
        """
        Poll for the result file written by the Agent.
        Returns the result dict or None on timeout.
        """
        result_file = self.results_dir / f"result_{cmd_id}.json"
        deadline = time.time() + timeout
        while time.time() < deadline:
            if result_file.exists():
                try:
                    data = json.loads(result_file.read_text())
                    result_file.unlink(missing_ok=True)
                    return data
                except Exception:
                    pass
            time.sleep(0.25)
        return None

    # ── Convenience helpers ──────────────────────────────────────────────

    def kill_process(self, pid: int) -> str:
        return self.send("kill_process", {"pid": pid})

    def kill_process_tree(self, pid: int) -> str:
        return self.send("kill_process_tree", {"pid": pid})

    def suspend_process(self, pid: int) -> str:
        return self.send("suspend_process", {"pid": pid})

    def quarantine_file(self, path: str) -> str:
        return self.send("quarantine_file", {"path": path})

    def block_ip(self, ip: str) -> str:
        return self.send("block_ip", {"ip": ip})

    def block_domain(self, domain: str) -> str:
        return self.send("block_domain", {"domain": domain})

    def block_port(self, port: int) -> str:
        return self.send("block_port", {"port": port})

    def isolate_sandbox_network(self) -> str:
        return self.send("isolate_host", {})

    def full_containment(self, pid: int | None = None,
                         image_path: str | None = None) -> str:
        return self.send("full_containment",
                         {"pid": pid, "image_path": image_path})
