from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path


@dataclass
class SessionRecord:
    timestamp: str
    file_name: str
    md5: str
    verdict: str
    score: int
    report_path: str = ""


class HistoryManager:
    def __init__(self):
        # We will save history inside the user profile folder
        self.history_dir = Path.home() / ".dragoncode_sessions"
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.db_file = self.history_dir / "history.json"
        
        self.sessions: list[SessionRecord] = []
        self._load()

    def _load(self):
        if not self.db_file.exists():
            return
            
        try:
            with open(self.db_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data:
                    self.sessions.append(SessionRecord(**item))
        except Exception as e:
            print(f"[History] Load Error: {e}")

    def save(self):
        try:
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump([asdict(s) for s in self.sessions], f, indent=4)
        except Exception as e:
            print(f"[History] Save Error: {e}")

    def add_session(self, file_name: str, md5: str, verdict: str, score: int, report_path: str = ""):
        record = SessionRecord(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            file_name=file_name,
            md5=md5,
            verdict=verdict,
            score=score,
            report_path=report_path
        )
        self.sessions.insert(0, record) # Push to front
        self.save()

    def get_recent(self, limit=50) -> list[SessionRecord]:
        return self.sessions[:limit]
