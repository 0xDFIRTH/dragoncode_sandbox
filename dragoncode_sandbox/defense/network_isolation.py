from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class NetworkIsolation:
    allow_network: bool = False
    blocked_ports: list[int] = field(default_factory=list)

    @staticmethod
    def new() -> "NetworkIsolation":
        return NetworkIsolation(allow_network=False, blocked_ports=[])

    @staticmethod
    def with_network_allowed() -> "NetworkIsolation":
        blocked_ports = [135, 139, 445, 3389, 5985, 5986]
        return NetworkIsolation(allow_network=True, blocked_ports=blocked_ports)

    def is_network_allowed(self) -> bool:
        return bool(self.allow_network)

    def is_port_allowed(self, port: int) -> bool:
        if not self.allow_network:
            return False
        return int(port) not in self.blocked_ports

    def block_port(self, port: int) -> None:
        p = int(port)
        if p not in self.blocked_ports:
            self.blocked_ports.append(p)

    def get_network_isolation_env_vars(self) -> list[tuple[str, str]]:
        if self.allow_network:
            return []

        return [
            ("NoAutoUpdate", "1"),
            ("DOTNET_CLI_TELEMETRY_OPTOUT", "1"),
            ("HTTP_PROXY", ""),
            ("HTTPS_PROXY", ""),
        ]


@dataclass(slots=True)
class ClipboardIsolation:
    allow_clipboard: bool = False

    @staticmethod
    def new() -> "ClipboardIsolation":
        return ClipboardIsolation(allow_clipboard=False)

    def is_clipboard_allowed(self) -> bool:
        return bool(self.allow_clipboard)


@dataclass(slots=True)
class IpcIsolation:
    allow_named_pipes: bool = False
    allowed_pipe_prefixes: list[str] = field(default_factory=list)

    @staticmethod
    def new() -> "IpcIsolation":
        return IpcIsolation(allow_named_pipes=False, allowed_pipe_prefixes=[])

    def is_pipe_allowed(self, pipe_name: str) -> bool:
        if not self.allow_named_pipes:
            return False
        if not self.allowed_pipe_prefixes:
            return False
        return any(pipe_name.startswith(prefix) for prefix in self.allowed_pipe_prefixes)

    def allow_pipe_prefix(self, prefix: str) -> None:
        self.allow_named_pipes = True
        self.allowed_pipe_prefixes.append(str(prefix))


@dataclass(slots=True)
class CommunicationIsolation:
    network: NetworkIsolation
    clipboard: ClipboardIsolation
    ipc: IpcIsolation

    @staticmethod
    def new_complete_isolation() -> "CommunicationIsolation":
        return CommunicationIsolation(
            network=NetworkIsolation.new(),
            clipboard=ClipboardIsolation.new(),
            ipc=IpcIsolation.new(),
        )

    @staticmethod
    def new_with_network() -> "CommunicationIsolation":
        return CommunicationIsolation(
            network=NetworkIsolation.with_network_allowed(),
            clipboard=ClipboardIsolation.new(),
            ipc=IpcIsolation.new(),
        )

    def is_network_allowed(self) -> bool:
        return self.network.is_network_allowed()

    def is_clipboard_allowed(self) -> bool:
        return self.clipboard.is_clipboard_allowed()

    def is_port_allowed(self, port: int) -> bool:
        return self.network.is_port_allowed(port)

    def is_pipe_allowed(self, pipe_name: str) -> bool:
        return self.ipc.is_pipe_allowed(pipe_name)

    def get_all_env_vars(self) -> list[tuple[str, str]]:
        return self.network.get_network_isolation_env_vars()
