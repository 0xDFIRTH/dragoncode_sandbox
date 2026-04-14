from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class BridgeConfig:
    endpoint: str
    api_key: str


class DragonCodeBridge:
    def __init__(self, config: BridgeConfig) -> None:
        self._config = config

    async def send_heartbeat(self) -> None:
        await asyncio.to_thread(self._send_heartbeat_sync)

    def _send_heartbeat_sync(self) -> None:
        return None

    @property
    def config(self) -> BridgeConfig:
        return self._config
