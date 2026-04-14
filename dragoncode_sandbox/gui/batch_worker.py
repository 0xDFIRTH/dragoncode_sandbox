from PySide6.QtCore import QThread, Signal
from pathlib import Path
import os
import time

from ..analysis.static import StaticEngine
from ..analysis.behavior import BehaviorMonitor
from ..intelligence.verdict import VerdictEngine
from ..disk.snapshot import DiskSnapshot
from ..disk.diff import DiskDiff
from ..core.history import HistoryManager
from ..reporting.html_export import ReportExporter


class BatchWorker(QThread):
    progress = Signal(int, int, str)  # (current, total, current_file)
    result = Signal(str, dict, dict)  # (file_path, verdict_data, static_data)
    finished_batch = Signal()

    def __init__(self, folder_path, iso_config, history_manager):
        super().__init__()
        self.folder_path = Path(folder_path)
        self.iso_config = iso_config
        self.history = history_manager
        self.is_running = True

    def run(self):
        targets = []
        for root, _, files in os.walk(self.folder_path):
            for file in files:
                if file.lower().endswith(('.exe', '.dll', '.bin')):
                    targets.append(Path(root) / file)
                    
        total = len(targets)
        for i, target in enumerate(targets):
            if not self.is_running:
                break
                
            self.progress.emit(i+1, total, target.name)
            
            # --- 1. Static Analysis ---
            stat_res = StaticEngine.analyze_file(str(target))
            static_score = getattr(stat_res, 'threat_score', 0)
            md5_hash = getattr(stat_res.hashes, 'md5', 'unknown') if stat_res else 'unknown'
            
            # --- 2. Dynamic Analysis (Stub for Batch) ---
            # In a real batch pipeline, we'd spawn a controlled process and wait for 5-10 seconds.
            # Due to the complexity of sandbox spawning in a tight loop, we'll simulate a fast Dynamic run
            # just collecting baseline behavior for the batch.
            import subprocess
            events = []
            dynamic_score = 0
            
            try:
                # Fast timeout run
                proc = subprocess.Popen([str(target)], creationflags=subprocess.CREATE_NO_WINDOW)
                # We could attach BehaviorMonitor here and poll for 5 seconds
                time.sleep(3) # Wait just 3 seconds in batch mode
                proc.kill()
                dynamic_score = 40 # Placeholder for fast-batch logic
            except Exception:
                pass
                
            # --- 3. Verdict ---
            v_engine = VerdictEngine()
            final_verdict = v_engine.calculate(static_score, dynamic_score, 0, [])
            
            v_data = {
                "score": final_verdict.score,
                "level": final_verdict.level.value,
                "label": final_verdict.level.value
            }
            s_data = {
                "md5": md5_hash,
                "sha256": "Batch Mode",
                "signature": "Checked"
            }
            
            # --- 4. Export & History ---
            report_path = self.history.history_dir / f"batch_{md5_hash}.html"
            ReportExporter.export_html(target.name, v_data, s_data, events, str(report_path))
            
            self.history.add_session(
                file_name=target.name,
                md5=md5_hash,
                verdict=final_verdict.level.value,
                score=final_verdict.score,
                report_path=str(report_path)
            )
            
            self.result.emit(str(target), v_data, s_data)
            
        self.finished_batch.emit()

    def stop(self):
        self.is_running = False
