import sys
import os
import time
import json
import subprocess
import shutil
import psutil
from pathlib import Path
try:
    import winreg
except ImportError:
    winreg = None

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QStackedWidget, QFileDialog, QTextEdit, QProgressBar, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QCheckBox, QGroupBox, QFrame,
    QListWidget, QListWidgetItem, QSizePolicy, QScrollArea, QSpinBox, QLineEdit,
    QGridLayout
)
from PySide6.QtCore import Qt, QThread, Signal, Slot, QSize, QTimer, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QIcon, QFont, QColor, QPalette, QBrush, QPainter, QLinearGradient

# Import backend
try:
    from ..analysis.static import StaticEngine, StaticAnalysisResult
    from ..analysis.memory import MemoryScanner, MemoryThreat
    from ..analysis.hash_lookup import lookup_hash, LookupResult
    from ..analysis.behavior import BehaviorMonitor, BehaviorEvent, BehaviorCategory, BehaviorSeverity
    from ..intelligence.verdict import VerdictEngine, Verdict, ThreatLevel
    from ..defense.network_isolation import CommunicationIsolation, NetworkIsolation, ClipboardIsolation
    from ..defense.resource_control import ProcessSandbox
    from ..registry.diff import RegistryDiff, RegAlert
    from ..registry.virtualization import RegistryKey

    from ..disk.snapshot import DiskSnapshot
    from ..disk.diff import DiskDiff, Created, Modified, Deleted
    
    from ..deception.anti_vm import AntiVMCountermeasures
    from ..intelligence.trust_abuse import TrustAnalyzer, TrustVerdict
    from ..intelligence.campaign import CampaignTracker, CampaignMatch

    from ..analysis.strings import StringAnalyzer
    from ..analysis.yara_scan import YaraScanner
    from ..gui.radar import ThreatRadarChart
    from ..reporting.html_export import ReportExporter
    from ..reporting.pdf_export import PDFExporter
    from ..core.history import HistoryManager
    from .batch_worker import BatchWorker
except ImportError:
    print("[ERROR] Run from package root!")
    sys.exit(1)


# ─────────────────────────────────────────────
#  WORKERS
# ─────────────────────────────────────────────

class StaticAnalysisWorker(QThread):
    finished = Signal(object)
    def __init__(self, path):
        super().__init__()
        self.path = path
    def run(self):
        try:
            res = StaticEngine.analyze_file(self.path)
            self.finished.emit(res)
        except Exception:
            self.finished.emit(None)


class HashLookupWorker(QThread):
    """Background thread: query VT / MalwareBazaar for the given SHA-256."""
    finished = Signal(object)   # LookupResult
    def __init__(self, sha256: str, vt_key: str = ""):
        super().__init__()
        self.sha256  = sha256
        self.vt_key  = vt_key
    def run(self):
        result = lookup_hash(self.sha256, self.vt_key)
        self.finished.emit(result)


class BehaviorWorker(QThread):
    """
    Runs BehaviorMonitor in a background thread.
    Emits one BehaviorEvent at a time via Qt signal (thread-safe).
    """
    event   = Signal(object)   # BehaviorEvent
    finished = Signal(int)     # final behavior risk score

    def __init__(self, pid: int):
        super().__init__()
        self.pid     = pid
        self._monitor: BehaviorMonitor | None = None

    def run(self):
        self._monitor = BehaviorMonitor(
            pid      = self.pid,
            interval = 0.8,
            on_event = self.event.emit,
        )
        self._monitor.start()
        self._monitor.run_blocking()
        self.finished.emit(self._monitor.risk_score)

    def stop(self):
        if self._monitor:
            self._monitor.stop()



class RegistryMonitorWorker(QThread):
    finished = Signal(object)
    def capture(self):
        if not winreg:
            return RegistryKey("HKLM")
        root = RegistryKey("HKLM")
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(key, i)
                        root.values[n] = str(v)
                        i += 1
                    except OSError:
                        break
        except:
            pass
        return root


class DynamicAnalysisWorker(QThread):
    log = Signal(str)
    threat = Signal(object)
    finished = Signal(int)
    started = Signal(int)

    def __init__(self, path, isolation, ram_mb, cpu_pct,
                 enable_memory: bool = True, timeout_sec: int = 15):
        super().__init__()
        self.path          = path
        self.isolation     = isolation
        self.ram_mb        = ram_mb
        self.cpu_pct       = cpu_pct
        self.enable_memory = enable_memory
        self.timeout_sec   = timeout_sec
        self.process       = None
        self.sandbox       = None
        self.running       = True
        self.risk          = 0

    def run(self):
        try:
            self.log.emit(f"[*] Launching: {self.path}")
            self.log.emit(f"[*] Resource Limits: {self.ram_mb}MB RAM | {self.cpu_pct}% CPU")
            try:
                self.sandbox = ProcessSandbox(self.ram_mb, self.cpu_pct)
                self.log.emit("[+] Sandbox Container Created (Job Object)")
            except Exception as e:
                self.log.emit(f"[!] Sandbox Init Failed: {e}")
                self.sandbox = None

            env = os.environ.copy()
            for k, v in self.isolation.get_all_env_vars():
                env[k] = v

            creation_flags = subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            self.process = subprocess.Popen([self.path], env=env, creationflags=creation_flags)
            pid = self.process.pid
            self.started.emit(pid)

            if self.sandbox:
                if self.sandbox.add_process(pid):
                    self.log.emit(f"[+] Process {pid} trapped in Sandbox.")
                else:
                    self.log.emit(f"[!] Failed to trap process {pid}!")

            self.log.emit(f"[+] Monitoring started (timeout: {self.timeout_sec}s)...")

            deadline = time.time() + self.timeout_sec
            while self.running and self.process.poll() is None and time.time() < deadline:
                if self.enable_memory:
                    threats = MemoryScanner.scan_process(None, pid)
                    if threats:
                        for t in threats:
                            self.threat.emit(t)
                            self.log.emit(f"[!] THREAT: {t}")
                            self.risk += 20
                time.sleep(1.0)

            self.log.emit(f"[*] Process exited (Code: {self.process.poll()})")
        except Exception as e:
            self.log.emit(f"[!] Error: {e}")
        finally:
            if self.sandbox:
                self.sandbox.close()
            self.finished.emit(min(self.risk, 100))

    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()


# ─────────────────────────────────────────────
#  STYLESHEET CONSTANTS
# ─────────────────────────────────────────────

GLOBAL_STYLE = """
    QMainWindow, QWidget#central {
        background-color: #0a0d14;
    }
    QWidget {
        font-family: 'Segoe UI', 'Consolas', sans-serif;
        color: #c9d1d9;
    }
    QScrollBar:vertical {
        background: #0d1117;
        width: 8px;
        border-radius: 4px;
    }
    QScrollBar::handle:vertical {
        background: #30363d;
        border-radius: 4px;
    }
    QScrollBar::handle:vertical:hover {
        background: #58a6ff;
    }
    QScrollBar:horizontal {
        background: #0d1117;
        height: 8px;
        border-radius: 4px;
    }
    QScrollBar::handle:horizontal {
        background: #30363d;
        border-radius: 4px;
    }
    QToolTip {
        background-color: #161b22;
        color: #c9d1d9;
        border: 1px solid #30363d;
        border-radius: 4px;
        padding: 4px 8px;
    }
"""

SIDEBAR_STYLE = """
    QListWidget {
        background-color: #0d1117;
        border: none;
        border-right: 1px solid #161b22;
        padding-top: 8px;
        outline: none;
    }
    QListWidget::item {
        color: #6e7681;
        padding: 13px 16px;
        font-size: 13px;
        font-weight: 500;
        border-left: 3px solid transparent;
        border-radius: 0px;
        margin: 2px 0px;
    }
    QListWidget::item:selected {
        color: #58a6ff;
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 rgba(88, 166, 255, 0.12),
            stop:1 rgba(88, 166, 255, 0.01));
        border-left: 3px solid #58a6ff;
    }
    QListWidget::item:hover:!selected {
        background-color: rgba(255,255,255,0.04);
        color: #c9d1d9;
        border-left: 3px solid #30363d;
    }
"""

TABLE_STYLE = """
    QTableWidget {
        background-color: #0d1117;
        border: 1px solid #21262d;
        gridline-color: #21262d;
        border-radius: 8px;
        selection-background-color: rgba(88, 166, 255, 0.15);
        selection-color: #58a6ff;
        outline: none;
    }
    QTableWidget::item {
        padding: 8px 12px;
        border-bottom: 1px solid #161b22;
    }
    QTableWidget::item:selected {
        background-color: rgba(88, 166, 255, 0.1);
        color: #58a6ff;
    }
    QHeaderView::section {
        background: #161b22;
        color: #8b949e;
        padding: 8px 12px;
        border: none;
        border-bottom: 1px solid #30363d;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
"""

TEXTEDIT_STYLE = """
    QTextEdit {
        background-color: #0d1117;
        border: 1px solid #21262d;
        color: #c9d1d9;
        border-radius: 8px;
        padding: 12px;
        font-size: 13px;
        selection-background-color: rgba(88, 166, 255, 0.3);
    }
"""

CONSOLE_STYLE = """
    QTextEdit {
        background-color: #010409;
        border: 1px solid #21262d;
        color: #3fb950;
        font-family: 'Cascadia Code', 'Consolas', monospace;
        font-size: 12px;
        border-radius: 8px;
        padding: 12px;
        selection-background-color: rgba(63, 185, 80, 0.2);
    }
"""

SPINBOX_STYLE = """
    QSpinBox {
        background: #161b22;
        color: #c9d1d9;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 5px 10px;
        font-size: 13px;
        min-width: 80px;
    }
    QSpinBox:focus {
        border: 1px solid #58a6ff;
    }
    QSpinBox::up-button, QSpinBox::down-button {
        background: #21262d;
        border: none;
        width: 16px;
    }
    QSpinBox::up-button:hover, QSpinBox::down-button:hover {
        background: #30363d;
    }
"""

CHECKBOX_STYLE = """
    QCheckBox {
        color: #c9d1d9;
        spacing: 10px;
        font-size: 13px;
        padding: 8px 4px;
    }
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border-radius: 5px;
        border: 2px solid #30363d;
        background: #0d1117;
    }
    QCheckBox::indicator:checked {
        background: #1f6feb;
        border: 2px solid #58a6ff;
        image: none;
    }
    QCheckBox::indicator:hover {
        border: 2px solid #58a6ff;
    }
"""

GROUPBOX_STYLE = """
    QGroupBox {
        border: 1px solid #21262d;
        border-radius: 10px;
        margin-top: 18px;
        padding: 16px 12px 12px 12px;
        font-weight: 600;
        font-size: 12px;
        color: #8b949e;
        letter-spacing: 1px;
        text-transform: uppercase;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 16px;
        padding: 0 6px;
        color: #58a6ff;
        background: #0a0d14;
    }
"""


# ─────────────────────────────────────────────
#  CUSTOM WIDGETS
# ─────────────────────────────────────────────

class SidebarItem(QListWidgetItem):
    def __init__(self, icon, text):
        super().__init__(f"  {icon}  {text}")
        self.setSizeHint(QSize(0, 46))


class ThreatMeter(QFrame):
    """Premium metric card with glowing accent border."""
    def __init__(self, label, score=0, accent="#58a6ff"):
        super().__init__()
        self.accent = accent
        self._label_text = label
        self.setObjectName("ThreatMeter")
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self._apply_frame_style(accent)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(6)
        layout.setContentsMargins(20, 20, 20, 16)

        self.lbl_title = QLabel(label.upper())
        self.lbl_title.setAlignment(Qt.AlignCenter)
        self.lbl_title.setStyleSheet(
            "color: #6e7681; font-size: 10px; font-weight: 700; "
            "letter-spacing: 2px; background: transparent; border: none;"
        )

        self.lbl_value = QLabel(str(score))
        self.lbl_value.setAlignment(Qt.AlignCenter)
        self.lbl_value.setStyleSheet(
            f"color: {accent}; font-size: 42px; font-weight: 800;"
            "background: transparent; border: none; line-height: 1;"
        )

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(score)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(3)
        self._apply_bar_style(accent)

        layout.addWidget(self.lbl_title)
        layout.addWidget(self.lbl_value)
        layout.addSpacing(4)
        layout.addWidget(self.bar)

    def _apply_frame_style(self, color):
        self.setStyleSheet(f"""
            QFrame#ThreatMeter {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #161b22, stop:1 #0d1117);
                border: 1px solid {color}44;
                border-top: 2px solid {color};
                border-radius: 12px;
            }}
        """)

    def _apply_bar_style(self, color):
        self.bar.setStyleSheet(f"""
            QProgressBar {{
                background: #21262d;
                border-radius: 2px;
                border: none;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {color}, stop:1 {color}88);
                border-radius: 2px;
            }}
        """)

    def set_value(self, val, label=None):
        self.lbl_value.setText(str(val) if label is None else label)
        try:
            self.bar.setValue(int(val))
        except:
            pass

    def set_accent(self, color):
        self.accent = color
        self.lbl_value.setStyleSheet(
            f"color: {color}; font-size: 42px; font-weight: 800;"
            "background: transparent; border: none;"
        )
        self._apply_bar_style(color)
        self._apply_frame_style(color)


class PrimaryButton(QPushButton):
    def __init__(self, text, color="#1f6feb", hover_color="#388bfd"):
        super().__init__(text)
        self._color = color
        self._hover = hover_color
        self._apply_style(color)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(38)

    def _apply_style(self, bg):
        self.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: #ffffff;
                border: none;
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 12px;
                letter-spacing: 0.5px;
            }}
            QPushButton:hover {{
                background: {self._hover};
            }}
            QPushButton:pressed {{
                background: {self._color};
                padding-top: 9px;
                padding-bottom: 7px;
            }}
            QPushButton:disabled {{
                background: #21262d;
                color: #484f58;
            }}
        """)


class DangerButton(PrimaryButton):
    def __init__(self, text):
        super().__init__(text, color="#b91c1c", hover_color="#dc2626")


class SuccessButton(PrimaryButton):
    def __init__(self, text):
        super().__init__(text, color="#166534", hover_color="#16a34a")


class GhostButton(QPushButton):
    def __init__(self, text):
        super().__init__(text)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(38)
        self.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #6e7681;
                border: 1px solid #30363d;
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover {
                background: #161b22;
                color: #c9d1d9;
                border-color: #8b949e;
            }
            QPushButton:disabled {
                color: #484f58;
                border-color: #21262d;
            }
        """)


class SectionLabel(QLabel):
    def __init__(self, text):
        super().__init__(text.upper())
        self.setStyleSheet("""
            color: #8b949e;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1.5px;
            padding: 8px 0px 4px 0px;
            border: none;
            background: transparent;
        """)


class Divider(QFrame):
    def __init__(self):
        super().__init__()
        self.setFrameShape(QFrame.HLine)
        self.setStyleSheet("color: #21262d; background: #21262d; border: none; max-height: 1px;")


class IntelMetricCard(QFrame):
    def __init__(self, label, value, icon=""):
        super().__init__()
        self.setFixedWidth(200)
        self.setFixedHeight(100)
        l = QVBoxLayout(self)
        l.setContentsMargins(16, 16, 16, 16)
        
        self.lbl_title = QLabel(label.upper())
        self.lbl_title.setStyleSheet("color: #8b949e; font-size: 10px; font-weight: 700; letter-spacing: 1px;")
        l.addWidget(self.lbl_title)
        
        self.lbl_value = QLabel(value)
        self.lbl_value.setStyleSheet("color: #e6edf3; font-size: 18px; font-weight: 800;")
        self.lbl_value.setWordWrap(True)
        l.addWidget(self.lbl_value)
        
        self.setStyleSheet("""
            IntelMetricCard {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)

    def set_value(self, val, color=None):
        self.lbl_value.setText(val)
        if color:
            self.lbl_value.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: 800;")


class MitreGrid(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QGridLayout(self)
        self.layout.setSpacing(6)
        self.cells = {}
        
        techniques = [
            ("T1059", "Execution"),
            ("T1547", "Persistence"),
            ("T1053", "Scheduling"),
            ("T1106", "Native API"),
            ("T1071", "C2 Comm"),
            ("T1083", "Discovery"),
            ("T1027", "Obfuscation"),
            ("T1497", "Anti-VM"),
            ("T1112", "Registry"),
            ("T1218", "Proxy Exec"),
            ("T1041", "Exfiltrate"),
            ("T1055", "Injection")
        ]
        
        for i, (tid, name) in enumerate(techniques):
            cell = QLabel(f"{tid}\n{name}")
            cell.setAlignment(Qt.AlignCenter)
            cell.setFixedSize(110, 60)
            cell.setStyleSheet("""
                background: #0d1117;
                color: #484f58;
                border: 1px solid #21262d;
                border-radius: 4px;
                font-size: 10px;
                font-weight: 600;
            """)
            self.layout.addWidget(cell, i // 4, i % 4)
            self.cells[tid] = cell

    def highlight(self, tid):
        if tid in self.cells:
            self.cells[tid].setStyleSheet("""
                background: #3e1c1c;
                color: #f78166;
                border: 1px solid #f78166;
                border-radius: 4px;
                font-size: 10px;
                font-weight: 800;
            """)

    def reset(self):
        for cell in self.cells.values():
            cell.setStyleSheet("""
                background: #0d1117;
                color: #484f58;
                border: 1px solid #21262d;
                border-radius: 4px;
                font-size: 10px;
                font-weight: 600;
            """)


# ─────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DragonCode Sandbox  ·  Enterprise Edition")
        self.resize(1280, 820)
        self.setObjectName("central")
        self.setStyleSheet(GLOBAL_STYLE)
        self.worker_dyn = None

        # State
        self.current_file = None
        self.static_res = None
        self.static_score = 0
        self.dynamic_score = 0
        self.reg_snap = None
        self.verdict_engine = VerdictEngine()
        self.isolation_config = CommunicationIsolation.new_complete_isolation()
        self.reg_worker = RegistryMonitorWorker()

        self.campaign_tracker = CampaignTracker()
        self.history_manager = HistoryManager()
        self.disk_snapshot = None
        self.disk_diff = None
        self._behavior_iocs = []
        self.append_mode = False
        
        self.setAcceptDrops(True)

        self.setup_ui()

    def setup_ui(self):
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ──
        sidebar_container = QWidget()
        sidebar_container.setFixedWidth(230)
        sidebar_container.setStyleSheet("background: #0d1117;")
        sb_layout = QVBoxLayout(sidebar_container)
        sb_layout.setContentsMargins(0, 0, 0, 0)
        sb_layout.setSpacing(0)

        # Logo area
        logo_frame = QFrame()
        logo_frame.setFixedHeight(72)
        logo_frame.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                stop:0 #0d1117, stop:1 #111827);
            border-bottom: 1px solid #1f2937;
        """)
        logo_l = QVBoxLayout(logo_frame)
        logo_l.setContentsMargins(16, 10, 16, 10)
        logo_l.setSpacing(2)
        dragon_lbl = QLabel("🐉  DragonCode")
        dragon_lbl.setStyleSheet(
            "color: #58a6ff; font-size: 15px; font-weight: 800; letter-spacing: 0.5px;"
            "border: none; background: transparent;"
        )
        ver_lbl = QLabel("Sandbox  ·  Enterprise v2.0")
        ver_lbl.setStyleSheet(
            "color: #484f58; font-size: 9px; letter-spacing: 0.5px;"
            "border: none; background: transparent;"
        )
        logo_l.addWidget(dragon_lbl)
        logo_l.addWidget(ver_lbl)
        sb_layout.addWidget(logo_frame)

        # Nav items
        self.sidebar = QListWidget()
        self.sidebar.setStyleSheet(SIDEBAR_STYLE)
        self.sidebar.setFocusPolicy(Qt.NoFocus)
        self.sidebar.addItem(SidebarItem("⬡", "Dashboard"))
        self.sidebar.addItem(SidebarItem("🔬", "Static Analysis"))
        self.sidebar.addItem(SidebarItem("⚙", "Dynamic Execution"))
        self.sidebar.addItem(SidebarItem("📋", "Registry Monitor"))
        self.sidebar.addItem(SidebarItem("🛡", "Defense Config"))
        self.sidebar.addItem(SidebarItem("🧠", "Intelligence Hub"))
        self.sidebar.addItem(SidebarItem("🌐", "Network Traffic"))
        self.sidebar.addItem(SidebarItem("⚙️", "Settings"))
        self.sidebar.addItem(SidebarItem("💾", "Analysis History"))
        self.sidebar.addItem(SidebarItem("📦", "Batch Analysis"))
        self.sidebar.currentRowChanged.connect(self.change_page)
        sb_layout.addWidget(self.sidebar)

        # Footer
        footer = QLabel("v2.0  ·  Enterprise")
        footer.setStyleSheet(
            "color: #484f58; font-size: 10px; padding: 12px 16px;"
            "border-top: 1px solid #161b22; border-left:none; border-right:none; border-bottom:none;"
            "background: transparent;"
        )
        sb_layout.addWidget(footer)

        root.addWidget(sidebar_container)

        # ── Content ──
        content_wrapper = QWidget()
        content_wrapper.setStyleSheet("background: #0a0d14;")
        content_v = QVBoxLayout(content_wrapper)
        content_v.setContentsMargins(0, 0, 0, 0)
        content_v.setSpacing(0)

        # Top bar / Header
        header_frame = QFrame()
        header_frame.setFixedHeight(64)
        header_frame.setStyleSheet("""
            background: #0d1117;
            border-bottom: 1px solid #161b22;
        """)
        header_l = QHBoxLayout(header_frame)
        header_l.setContentsMargins(24, 0, 24, 0)

        self.lbl_file = QLabel("No sample loaded")
        self.lbl_file.setStyleSheet(
            "font-size: 13px; font-weight: 500; color: #6e7681;"
            "background: transparent; border: none;"
        )

        self.lbl_badge = QLabel("READY")
        self.lbl_badge.setStyleSheet("""
            background: #161b22;
            color: #3fb950;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            border: 1px solid #238636;
            border-radius: 4px;
            padding: 2px 8px;
        """)

        self.btn_load = PrimaryButton("⬆  Load Sample")
        self.btn_load.clicked.connect(self.load_sample)
        self.btn_load.setFixedWidth(140)

        header_l.addWidget(self.lbl_file)
        header_l.addWidget(self.lbl_badge)
        header_l.addStretch()
        header_l.addWidget(self.btn_load)
        content_v.addWidget(header_frame)

        # Page stack
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background: #0a0d14;")
        content_v.addWidget(self.stack)

        self.page_dashboard = self.create_dashboard()
        self.page_static = self.create_static_page()
        self.page_dynamic = self.create_dynamic_page()
        self.page_registry = self.create_registry_page()
        self.page_defense = self.create_defense_page()
        self.page_intel = self.create_intel_page()
        self.page_network = self.create_network_page()
        self.page_settings = self.create_settings_page()
        self.page_history = self.create_history_page()
        self.page_batch = self.create_batch_page()

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_static)
        self.stack.addWidget(self.page_dynamic)
        self.stack.addWidget(self.page_registry)
        self.stack.addWidget(self.page_defense)
        self.stack.addWidget(self.page_intel)
        self.stack.addWidget(self.page_network)
        self.stack.addWidget(self.page_settings)
        self.stack.addWidget(self.page_history)
        self.stack.addWidget(self.page_batch)

        root.addWidget(content_wrapper)
        self.sidebar.setCurrentRow(0)
        
        # Restore user preferences
        self._load_settings()

    # ─────────────────────────────────────────────
    #  PAGES
    # ─────────────────────────────────────────────

    def create_dashboard(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: #0a0d14; }")

        p = QWidget()
        outer = QVBoxLayout(p)
        outer.setContentsMargins(32, 32, 32, 32)
        outer.setSpacing(0)

        # ── Hero Banner ─────────────────────────────────────────────
        hero = QFrame()
        hero.setObjectName("HeroBanner")
        hero.setStyleSheet("""
            QFrame#HeroBanner {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0d1117, stop:0.5 #111827, stop:1 #0d1117);
                border: 1px solid #1f2937;
                border-radius: 14px;
            }
        """)
        hero.setMinimumHeight(110)
        hero_l = QHBoxLayout(hero)
        hero_l.setContentsMargins(28, 20, 28, 20)
        hero_l.setSpacing(24)

        # Left side: icon + title
        hero_text = QVBoxLayout()
        hero_text.setSpacing(4)
        hero_title = QLabel("Threat Analysis Dashboard")
        hero_title.setStyleSheet(
            "color: #e6edf3; font-size: 20px; font-weight: 800;"
            "background: transparent; border: none;"
        )
        hero_sub = QLabel(
            "Load a sample and run Static + Dynamic analysis to generate a full threat report."
        )
        hero_sub.setStyleSheet(
            "color: #6e7681; font-size: 12px; background: transparent; border: none;"
        )
        hero_sub.setWordWrap(True)
        hero_text.addWidget(hero_title)
        hero_text.addWidget(hero_sub)
        hero_l.addLayout(hero_text, 1)

        # Right side: verdict badge (large)
        self.card_verdict = ThreatMeter("Final Verdict", 0, "#58a6ff")
        self.card_verdict.set_value(0, "UNKNOWN")
        self.card_verdict.setFixedWidth(180)
        self.card_verdict.setFixedHeight(100)
        self.card_verdict.lbl_value.setStyleSheet(
            "color: #58a6ff; font-size: 28px; font-weight: 800;"
            "background: transparent; border: none;"
        )
        hero_l.addWidget(self.card_verdict)
        outer.addWidget(hero)
        outer.addSpacing(24)

        # ── Workflow Steps ────────────────────────────────────────
        steps_row = QHBoxLayout()
        steps_row.setSpacing(0)

        def _step(num, label, done=False):
            w = QFrame()
            w.setStyleSheet(
                "background: #0d1117; border: 1px solid #21262d; border-radius: 8px;"
            )
            sl = QVBoxLayout(w)
            sl.setContentsMargins(16, 10, 16, 10)
            sl.setSpacing(2)
            num_lbl = QLabel(num)
            num_lbl.setStyleSheet(
                f"color: {'#3fb950' if done else '#484f58'}; font-size: 11px;"
                "font-weight: 700; background: transparent; border: none;"
            )
            txt_lbl = QLabel(label)
            txt_lbl.setStyleSheet(
                f"color: {'#c9d1d9' if done else '#6e7681'}; font-size: 12px;"
                "background: transparent; border: none;"
            )
            sl.addWidget(num_lbl)
            sl.addWidget(txt_lbl)
            return w

        def _arrow():
            a = QLabel("→")
            a.setFixedWidth(28)
            a.setAlignment(Qt.AlignCenter)
            a.setStyleSheet(
                "color: #30363d; font-size: 16px; background: transparent; border: none;"
            )
            return a

        self.step_load    = _step("01", "Load Sample")
        self.step_static  = _step("02", "Static Analysis")
        self.step_dynamic = _step("03", "Dynamic Execution")
        self.step_verdict = _step("04", "Final Verdict")

        steps_row.addWidget(self.step_load)
        steps_row.addWidget(_arrow())
        steps_row.addWidget(self.step_static)
        steps_row.addWidget(_arrow())
        steps_row.addWidget(self.step_dynamic)
        steps_row.addWidget(_arrow())
        steps_row.addWidget(self.step_verdict)
        outer.addLayout(steps_row)
        outer.addSpacing(24)

        # ── Metric Cards ──────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(16)
        self.card_static  = ThreatMeter("Static Risk", 0, "#3fb950")
        self.card_static.set_value("—")
        self.card_dynamic = ThreatMeter("Dynamic Risk", 0, "#3fb950")
        self.card_dynamic.set_value("—")

        # Extra info card
        self.card_file_info = QFrame()
        self.card_file_info.setObjectName("FileInfoCard")
        self.card_file_info.setStyleSheet("""
            QFrame#FileInfoCard {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #161b22, stop:1 #0d1117);
                border: 1px solid #30363d44;
                border-top: 2px solid #30363d;
                border-radius: 12px;
            }
        """)
        self.card_file_info.setMinimumHeight(150)
        fi_l = QVBoxLayout(self.card_file_info)
        fi_l.setContentsMargins(20, 20, 20, 16)
        fi_l.setSpacing(6)
        fi_title = QLabel("TARGET FILE")
        fi_title.setStyleSheet(
            "color: #6e7681; font-size: 10px; font-weight: 700; letter-spacing: 2px;"
            "background: transparent; border: none;"
        )
        self.lbl_fi_name = QLabel("No file loaded")
        self.lbl_fi_name.setStyleSheet(
            "color: #8b949e; font-size: 14px; font-weight: 600;"
            "background: transparent; border: none;"
        )
        self.lbl_fi_name.setWordWrap(True)
        self.lbl_fi_size = QLabel("—")
        self.lbl_fi_size.setStyleSheet(
            "color: #484f58; font-size: 11px;"
            "background: transparent; border: none;"
        )
        fi_l.addWidget(fi_title)
        fi_l.addSpacing(4)
        fi_l.addWidget(self.lbl_fi_name)
        fi_l.addWidget(self.lbl_fi_size)
        fi_l.addStretch()

        cards_row.addWidget(self.card_static)
        cards_row.addWidget(self.card_dynamic)
        cards_row.addWidget(self.card_file_info)
        outer.addLayout(cards_row)
        outer.addSpacing(24)

        # ── Lower Split: Interpretation + Radar ──
        lower_split = QHBoxLayout()
        lower_split.setSpacing(24)
        
        interp_vbox = QVBoxLayout()
        interp_lbl = QLabel("ANALYSIS INTERPRETATION")
        interp_lbl.setStyleSheet(
            "color: #6e7681; font-size: 10px; font-weight: 700; letter-spacing: 2px;"
            "background: transparent; border: none; padding-bottom: 8px;"
        )
        interp_vbox.addWidget(interp_lbl)

        self.txt_explanation = QTextEdit()
        self.txt_explanation.setReadOnly(True)
        self.txt_explanation.setFixedHeight(180)
        self.txt_explanation.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #21262d;
                border-left: 3px solid #1f6feb;
                color: #c9d1d9;
                border-radius: 8px;
                padding: 14px;
                font-size: 13px;
                line-height: 1.6;
            }
        """)
        self.txt_explanation.setPlaceholderText(
            "Run Static and Dynamic analysis to generate a full threat interpretation..."
        )
        interp_vbox.addWidget(self.txt_explanation)
        
        self.btn_export_html = PrimaryButton("📄  Export Report")
        self.btn_export_html.clicked.connect(self.export_report)
        self.btn_export_html.setEnabled(False)
        interp_vbox.addWidget(self.btn_export_html)
        interp_vbox.addStretch()

        radar_vbox = QVBoxLayout()
        radar_vbox.setAlignment(Qt.AlignTop | Qt.AlignHCenter)
        radar_lbl = QLabel("THREAT RADAR")
        radar_lbl.setStyleSheet(
            "color: #6e7681; font-size: 10px; font-weight: 700; letter-spacing: 2px;"
            "background: transparent; border: none; padding-bottom: 8px;"
        )
        radar_vbox.addWidget(radar_lbl, alignment=Qt.AlignHCenter)
        self.radar_chart = ThreatRadarChart()
        radar_vbox.addWidget(self.radar_chart)

        lower_split.addLayout(interp_vbox, 2)
        lower_split.addLayout(radar_vbox, 1)

        outer.addLayout(lower_split)
        
        outer.addStretch()

        scroll.setWidget(p)
        return scroll

    def export_report(self):
        import re
        s_score = getattr(self, "static_score", 0)
        d_score = getattr(self, "dynamic_score", 0)
        avg_score = (s_score + d_score) // 2

        if avg_score <= 30:
            level = "Benign (Safe)"
        elif avg_score <= 50:
            level = "Suspicious (Moderate)"
        else:
            level = "Malicious (Critical)"

        verdict_data = {
            "static_score": s_score,
            "dynamic_score": d_score,
            "score": avg_score,
            "level": level,
            "label": level
        }
        
        raw_trust = self.lbl_trust_verdict.text().split(':')[-1] if hasattr(self, "lbl_trust_verdict") else "Unsigned"
        clean_trust = re.sub('<[^<]+>', '', raw_trust).strip()

        static_info = {
            "md5": self.lbl_md5.text() if hasattr(self, "lbl_md5") else "N/A",
            "sha256": self.lbl_sha256.text() if hasattr(self, "lbl_sha256") else "N/A",
            "signature": clean_trust
        }
        dynamic_events = []
        for row in range(self.table_behavior.rowCount()):
            dynamic_events.append({
                "time": self.table_behavior.item(row, 0).text(),
                "category": self.table_behavior.item(row, 1).text(),
                "severity": self.table_behavior.item(row, 2).text(),
                "title": self.table_behavior.item(row, 3).text(),
            })
            
        dest_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Save Analysis Report", "",
            "PDF Document (*.pdf);;HTML Document (*.html)"
        )
        if not dest_path:
            return
            
        import webbrowser
        if selected_filter == "PDF Document (*.pdf)":
            PDFExporter.export_pdf(
                self.current_file or "unknown_file.exe",
                verdict_data,
                static_info,
                dynamic_events,
                dest_path
            )
            webbrowser.open(f"file://{dest_path}")
        else:
            ReportExporter.export_html(
                self.current_file or "unknown_file.exe",
                verdict_data,
                static_info,
                dynamic_events,
                dest_path
            )
            webbrowser.open(f"file://{dest_path}")

    def create_network_page(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(28, 28, 28, 28)
        l.setSpacing(16)

        title = QLabel("Network Traffic")
        title.setStyleSheet("font-size: 22px; font-weight: 700; color: #e6edf3; background: transparent;")
        l.addWidget(title)
        l.addWidget(Divider())

        self.table_network = QTableWidget(0, 4)
        self.table_network.setHorizontalHeaderLabels(["Time", "IP:Port", "Protocol/Status", "Severity"])
        self.table_network.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_network.setStyleSheet(TABLE_STYLE)
        self.table_network.setAlternatingRowColors(True)
        self.table_network.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_network.verticalHeader().setVisible(False)
        l.addWidget(self.table_network)

        return p

    def create_history_page(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(28, 28, 28, 28)
        l.setSpacing(16)

        title = QLabel("Analysis History")
        title.setStyleSheet("font-size: 22px; font-weight: 700; color: #e6edf3; background: transparent;")
        l.addWidget(title)
        l.addWidget(Divider())

        self.table_history = QTableWidget(0, 5)
        self.table_history.setHorizontalHeaderLabels(["Date", "Target", "MD5", "Verdict", "Score"])
        self.table_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_history.setStyleSheet(TABLE_STYLE)
        self.table_history.setAlternatingRowColors(True)
        self.table_history.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_history.verticalHeader().setVisible(False)
        self.table_history.itemDoubleClicked.connect(self._open_history_report)
        l.addWidget(self.table_history)

        self._refresh_history_table()
        
        note = QLabel("Double-click a row to open the HTML report for that analysis session.")
        note.setStyleSheet("color: #8b949e; font-size: 11px;")
        l.addWidget(note)
        
        return p

    def _refresh_history_table(self):
        if not hasattr(self, 'table_history'): return
        self.table_history.setRowCount(0)
        sessions = self.history_manager.get_recent()
        for i, s in enumerate(sessions):
            self.table_history.insertRow(i)
            self.table_history.setItem(i, 0, QTableWidgetItem(s.timestamp))
            self.table_history.setItem(i, 1, QTableWidgetItem(s.file_name))
            self.table_history.setItem(i, 2, QTableWidgetItem(s.md5))
            
            v_item = QTableWidgetItem(s.verdict)
            if s.verdict == "Critical": v_item.setForeground(QColor("#ff4444"))
            elif s.verdict == "Malicious": v_item.setForeground(QColor("#f78166"))
            elif s.verdict == "Suspicious": v_item.setForeground(QColor("#d29922"))
            elif s.verdict == "Benign": v_item.setForeground(QColor("#3fb950"))
            self.table_history.setItem(i, 3, v_item)
            
            self.table_history.setItem(i, 4, QTableWidgetItem(str(s.score)))
            
            # Store hidden path
            path_item = QTableWidgetItem(s.report_path)
            self.table_history.setItem(i, 5, path_item)

    def _open_history_report(self, item):
        row = item.row()
        path_item = self.table_history.item(row, 5)
        if path_item and path_item.text():
            import webbrowser
            webbrowser.open(f"file://{path_item.text()}")

    def create_batch_page(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(28, 28, 28, 28)
        l.setSpacing(16)

        title = QLabel("Batch Analysis")
        title.setStyleSheet("font-size: 22px; font-weight: 700; color: #e6edf3; background: transparent;")
        l.addWidget(title)
        l.addWidget(Divider())

        top_h = QHBoxLayout()
        self.btn_batch_folder = PrimaryButton("📁  Select Folder")
        self.btn_batch_folder.setFixedWidth(200)
        self.btn_batch_folder.clicked.connect(self._select_batch_folder)
        top_h.addWidget(self.btn_batch_folder)
        
        self.lbl_batch_status = QLabel("Ready.")
        self.lbl_batch_status.setStyleSheet("color: #8b949e; font-weight: bold;")
        top_h.addWidget(self.lbl_batch_status)
        top_h.addStretch()
        l.addLayout(top_h)
        
        self.table_batch = QTableWidget(0, 3)
        self.table_batch.setHorizontalHeaderLabels(["Target", "Status", "Verdict"])
        self.table_batch.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_batch.setStyleSheet(TABLE_STYLE)
        self.table_batch.setAlternatingRowColors(True)
        self.table_batch.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_batch.verticalHeader().setVisible(False)
        l.addWidget(self.table_batch)

        self.btn_batch_start = DangerButton("▶  Start Batch Run")
        self.btn_batch_start.setEnabled(False)
        self.btn_batch_start.clicked.connect(self._start_batch)
        l.addWidget(self.btn_batch_start)
        
        self._batch_folder = None
        self._batch_worker_obj = None

        return p

    def _select_batch_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder for Batch Analysis")
        if folder:
            self._batch_folder = folder
            self.lbl_batch_status.setText(f"Selected: {folder}")
            self.btn_batch_start.setEnabled(True)

    def _start_batch(self):
        if not self._batch_folder: return
        self.btn_batch_start.setEnabled(False)
        self.btn_batch_folder.setEnabled(False)
        self.table_batch.setRowCount(0)
        self.lbl_batch_status.setText("Initializing Batch Worker...")
        
        self._batch_worker_obj = BatchWorker(self._batch_folder, self.isolation_config, self.history_manager)
        self._batch_worker_obj.progress.connect(self._on_batch_progress)
        self._batch_worker_obj.result.connect(self._on_batch_result)
        self._batch_worker_obj.finished_batch.connect(self._on_batch_done)
        self._batch_worker_obj.start()

    def _on_batch_progress(self, curr, total, file_name):
        self.lbl_batch_status.setText(f"Analyzing {curr}/{total} - {file_name}")
        row = self.table_batch.rowCount()
        self.table_batch.insertRow(row)
        self.table_batch.setItem(row, 0, QTableWidgetItem(file_name))
        self.table_batch.setItem(row, 1, QTableWidgetItem("Analyzing..."))
        self.table_batch.setItem(row, 2, QTableWidgetItem("—"))
        self.table_batch.scrollToBottom()

    def _on_batch_result(self, file_path, v_data, s_data):
        row = self.table_batch.rowCount() - 1
        if row >= 0:
            self.table_batch.item(row, 1).setText("Done")
            v_item = QTableWidgetItem(f"{v_data['level']} ({v_data['score']})")
            if v_data['score'] > 80: v_item.setForeground(QColor("#ff4444"))
            elif v_data['score'] > 50: v_item.setForeground(QColor("#f78166"))
            elif v_data['score'] > 20: v_item.setForeground(QColor("#d29922"))
            else: v_item.setForeground(QColor("#3fb950"))
            self.table_batch.setItem(row, 2, v_item)
            
            self._refresh_history_table()

    def _on_batch_done(self):
        self.lbl_batch_status.setText("Batch Analysis Complete.")
        self.btn_batch_start.setEnabled(True)
        self.btn_batch_folder.setEnabled(True)

    def create_settings_page(self):
        # Using a QScrollArea for the entire settings page
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: #0a0d14; }")
        
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(28, 28, 28, 28)
        l.setSpacing(24)

        title = QLabel("Platform Settings")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #e6edf3; background: transparent;")
        l.addWidget(title)
        l.addWidget(Divider())

        # ── 1. API Integrations ──
        box_api = QGroupBox("External API Integrations")
        box_api.setStyleSheet(GROUPBOX_STYLE)
        grid_api = QVBoxLayout(box_api)
        grid_api.setSpacing(12)
        grid_api.setContentsMargins(16, 20, 16, 16)

        lbl_vt = QLabel("VirusTotal API Key (Threat Intelligence):")
        lbl_vt.setStyleSheet("color: #8b949e; font-size: 13px; font-weight: bold;")
        self.txt_vt_key = QLineEdit()
        self.txt_vt_key.setPlaceholderText("Enter 64-character VT API key...")
        self.txt_vt_key.setEchoMode(QLineEdit.Password)
        self.txt_vt_key.setStyleSheet("background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 8px; border-radius: 6px;")
        
        lbl_ml = QLabel("OpenAI API Key (Heuristic Explanations):")
        lbl_ml.setStyleSheet("color: #8b949e; font-size: 13px; font-weight: bold;")
        self.txt_ml_key = QLineEdit()
        self.txt_ml_key.setPlaceholderText("sk-...")
        self.txt_ml_key.setEchoMode(QLineEdit.Password)
        self.txt_ml_key.setStyleSheet("background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 8px; border-radius: 6px;")

        grid_api.addWidget(lbl_vt)
        grid_api.addWidget(self.txt_vt_key)
        grid_api.addWidget(lbl_ml)
        grid_api.addWidget(self.txt_ml_key)
        l.addWidget(box_api)

        # ── 2. Sandbox Engine ──
        box_engine = QGroupBox("Execution & Engine Policy")
        box_engine.setStyleSheet(GROUPBOX_STYLE)
        grid_eng = QVBoxLayout(box_engine)
        grid_eng.setSpacing(12)
        grid_eng.setContentsMargins(16, 20, 16, 16)

        self.chk_memory = QCheckBox("Enable Deep Memory Scanning (Process Hollowing Detection)")
        self.chk_memory.setChecked(True)
        self.chk_memory.setStyleSheet("color: #c9d1d9; font-size: 13px;")

        self.chk_registry = QCheckBox("Enable Advanced Registry Hooking inside Sandbox VM")
        self.chk_registry.setChecked(True)
        self.chk_registry.setStyleSheet("color: #c9d1d9; font-size: 13px;")
        
        self.chk_network = QCheckBox("Strict Isolation: Block all outbound network traffic during Dynamic Analysis")
        self.chk_network.setStyleSheet("color: #c9d1d9; font-size: 13px;")

        grid_eng.addWidget(self.chk_memory)
        grid_eng.addWidget(self.chk_registry)
        grid_eng.addWidget(self.chk_network)
        
        # Timeout spinner
        h_time = QHBoxLayout()
        lbl_time = QLabel("Execution Timeout (Seconds):")
        lbl_time.setStyleSheet("color: #8b949e; font-size: 13px; font-weight: bold;")
        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(5, 120)
        self.spin_timeout.setValue(15)
        self.spin_timeout.setStyleSheet("background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 4px; border-radius: 4px;")
        h_time.addWidget(lbl_time)
        h_time.addWidget(self.spin_timeout)
        h_time.addStretch()
        grid_eng.addLayout(h_time)
        
        l.addWidget(box_engine)
        
        # ── 3. Automation & Reporting ──
        box_rep = QGroupBox("Automation & Reporting")
        box_rep.setStyleSheet(GROUPBOX_STYLE)
        grid_rep = QVBoxLayout(box_rep)
        grid_rep.setSpacing(12)
        grid_rep.setContentsMargins(16, 20, 16, 16)

        self.chk_auto_pdf = QCheckBox("Automatically export PDF report upon scan completion")
        self.chk_auto_pdf.setStyleSheet("color: #c9d1d9; font-size: 13px;")
        
        self.chk_auto_kill = QCheckBox("Auto-kill Sandbox VM when Malicious behavior is confirmed (> 80%)")
        self.chk_auto_kill.setChecked(True)
        self.chk_auto_kill.setStyleSheet("color: #c9d1d9; font-size: 13px;")

        grid_rep.addWidget(self.chk_auto_pdf)
        grid_rep.addWidget(self.chk_auto_kill)
        l.addWidget(box_rep)

        # ── Save Button ──
        h_save = QHBoxLayout()
        h_save.addStretch()
        self.btn_save_settings = PrimaryButton("💾  Save Preferences")
        self.btn_save_settings.setFixedWidth(200)
        self.btn_save_settings.clicked.connect(self._save_settings)
        h_save.addWidget(self.btn_save_settings)
        l.addLayout(h_save)

        # ── Synchronize Defense Config & Settings Toggles ──
        self.chk_network.stateChanged.connect(lambda s: self.chk_net.setChecked(s == Qt.Checked))
        self.chk_net.stateChanged.connect(lambda s: self.chk_network.setChecked(s == Qt.Checked))

        l.addStretch()
        scroll.setWidget(p)
        return scroll

    def create_static_page(self):
        # Wrap everything in a scroll area so the page never clips
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: #0a0d14; }"
        )
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(28, 28, 28, 28)
        l.setSpacing(16)

        title = QLabel("Static Analysis")
        title.setStyleSheet(
            "font-size: 22px; font-weight: 700; color: #e6edf3; background: transparent;"
        )
        l.addWidget(title)
        l.addWidget(Divider())

        # ── Run button ──────────────────────────────────────────
        h = QHBoxLayout()
        self.btn_run_static = PrimaryButton("🔬  Run Static Analysis")
        self.btn_run_static.clicked.connect(self.run_static)
        self.btn_run_static.setFixedWidth(200)
        h.addWidget(self.btn_run_static)
        h.addStretch()
        l.addLayout(h)

        # ── Hash Panel ───────────────────────────────────────────
        l.addWidget(SectionLabel("File Hashes"))
        hash_frame = QFrame()
        hash_frame.setObjectName("HashFrame")
        hash_frame.setStyleSheet("""
            QFrame#HashFrame {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 10px;
            }
        """)
        hash_grid = QVBoxLayout(hash_frame)
        hash_grid.setContentsMargins(16, 12, 16, 12)
        hash_grid.setSpacing(8)

        def _hash_row(label_text):
            row = QHBoxLayout()
            lbl = QLabel(label_text)
            lbl.setFixedWidth(56)
            lbl.setStyleSheet(
                "color: #6e7681; font-size: 11px; font-weight: 700;"
                "letter-spacing: 1px; background: transparent; border: none;"
            )
            val = QLabel("—")
            val.setStyleSheet(
                "color: #8b949e; font-family: 'Consolas', monospace; font-size: 12px;"
                "background: transparent; border: none;"
            )
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(lbl)
            row.addWidget(val)
            row.addStretch()
            hash_grid.addLayout(row)
            return val

        self.lbl_md5    = _hash_row("MD5")
        self.lbl_sha1   = _hash_row("SHA-1")
        self.lbl_sha256 = _hash_row("SHA-256")

        # Lookup button row
        lookup_row = QHBoxLayout()
        self.btn_hash_lookup = PrimaryButton("🔍  Search Threat Intel")
        self.btn_hash_lookup.setEnabled(False)
        self.btn_hash_lookup.setFixedWidth(200)
        self.btn_hash_lookup.clicked.connect(self.run_hash_lookup)

        self.lbl_lookup_spin = QLabel("")
        self.lbl_lookup_spin.setStyleSheet(
            "color: #6e7681; font-size: 12px; background: transparent; border: none;"
        )
        lookup_row.addWidget(self.btn_hash_lookup)
        lookup_row.addWidget(self.lbl_lookup_spin)
        lookup_row.addStretch()
        hash_grid.addLayout(lookup_row)
        l.addWidget(hash_frame)

        # ── Threat Intel Result Panel ────────────────────────────
        l.addWidget(SectionLabel("Threat Intelligence Result"))
        self.frame_threat_intel = QFrame()
        self.frame_threat_intel.setObjectName("TIFrame")
        self.frame_threat_intel.setStyleSheet("""
            QFrame#TIFrame {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 10px;
            }
        """)
        ti_layout = QHBoxLayout(self.frame_threat_intel)
        ti_layout.setContentsMargins(20, 16, 20, 16)
        ti_layout.setSpacing(32)

        # Big verdict badge
        self.lbl_ti_verdict = QLabel("—")
        self.lbl_ti_verdict.setAlignment(Qt.AlignCenter)
        self.lbl_ti_verdict.setFixedWidth(120)
        self.lbl_ti_verdict.setStyleSheet("""
            background: #161b22;
            color: #6e7681;
            font-size: 13px;
            font-weight: 800;
            letter-spacing: 1.5px;
            border: 2px solid #30363d;
            border-radius: 8px;
            padding: 10px 6px;
        """)

        # Details
        ti_details = QVBoxLayout()
        ti_details.setSpacing(6)

        def _ti_row(key):
            row = QHBoxLayout()
            k = QLabel(key + ":")
            k.setFixedWidth(110)
            k.setStyleSheet(
                "color: #6e7681; font-size: 11px; font-weight: 700;"
                "letter-spacing: 0.5px; background: transparent; border: none;"
            )
            v = QLabel("—")
            v.setStyleSheet(
                "color: #c9d1d9; font-size: 12px; background: transparent; border: none;"
            )
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            v.setOpenExternalLinks(True)
            row.addWidget(k)
            row.addWidget(v)
            row.addStretch()
            ti_details.addLayout(row)
            return v

        self.lbl_ti_source    = _ti_row("Source")
        self.lbl_ti_ratio     = _ti_row("Detection")
        self.lbl_ti_name      = _ti_row("Threat Name")
        self.lbl_ti_tags      = _ti_row("Tags")
        self.lbl_ti_link      = _ti_row("Report")
        self.lbl_ti_link.setOpenExternalLinks(True)

        ti_layout.addWidget(self.lbl_ti_verdict)
        ti_layout.addLayout(ti_details)
        ti_layout.addStretch()
        l.addWidget(self.frame_threat_intel)

        # ── Tables ───────────────────────────────────────────────
        l.addWidget(SectionLabel("Suspicious Imports"))
        self.table_imports = QTableWidget(0, 1)
        self.table_imports.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_imports.setHorizontalHeaderLabels(["Import Name"])
        self.table_imports.setStyleSheet(TABLE_STYLE)
        self.table_imports.setAlternatingRowColors(True)
        self.table_imports.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_imports.verticalHeader().setVisible(False)
        self.table_imports.setFixedHeight(180)
        l.addWidget(self.table_imports)

        l.addWidget(SectionLabel("PE Sections — Entropy Analysis"))
        self.table_sections = QTableWidget(0, 3)
        self.table_sections.setHorizontalHeaderLabels(["Section", "Entropy", "Virtual Size"])
        self.table_sections.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_sections.setStyleSheet(TABLE_STYLE)
        self.table_sections.setAlternatingRowColors(True)
        self.table_sections.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_sections.verticalHeader().setVisible(False)
        self.table_sections.setFixedHeight(180)
        l.addWidget(self.table_sections)

        # Strings Extracted
        l.addWidget(SectionLabel("Extracted Strings (URLs, IPs, Registries, Base64)"))
        self.table_strings = QTableWidget(0, 2)
        self.table_strings.setHorizontalHeaderLabels(["Type", "String"])
        self.table_strings.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_strings.setStyleSheet(TABLE_STYLE)
        self.table_strings.setAlternatingRowColors(True)
        self.table_strings.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_strings.verticalHeader().setVisible(False)
        self.table_strings.setFixedHeight(180)
        l.addWidget(self.table_strings)

        # Yara Scanner Results
        l.addWidget(SectionLabel("YARA Scanner Results"))
        self.table_yara = QTableWidget(0, 3)
        self.table_yara.setHorizontalHeaderLabels(["Rule", "Description", "Tags"])
        self.table_yara.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_yara.setStyleSheet(TABLE_STYLE)
        self.table_yara.setAlternatingRowColors(True)
        self.table_yara.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_yara.verticalHeader().setVisible(False)
        self.table_yara.setFixedHeight(150)
        l.addWidget(self.table_yara)

        l.addStretch()
        scroll.setWidget(p)
        return scroll

    def create_dynamic_page(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(28, 28, 28, 28)
        l.setSpacing(16)

        title = QLabel("Dynamic Execution")
        title.setStyleSheet(
            "font-size: 22px; font-weight: 700; color: #e6edf3; background: transparent;"
        )
        l.addWidget(title)
        l.addWidget(Divider())

        # Constraints
        res_box = QGroupBox("Sandbox Resource Limits")
        res_box.setStyleSheet(GROUPBOX_STYLE)
        res_l = QHBoxLayout(res_box)
        res_l.setSpacing(16)

        lbl_ram = QLabel("RAM Limit (MB):")
        lbl_ram.setStyleSheet("color: #8b949e; font-size: 12px; background: transparent;")
        self.spin_ram = QSpinBox()
        self.spin_ram.setRange(128, 8192)
        self.spin_ram.setValue(1024)
        self.spin_ram.setStyleSheet(SPINBOX_STYLE)

        lbl_cpu = QLabel("CPU Limit (%):")
        lbl_cpu.setStyleSheet("color: #8b949e; font-size: 12px; background: transparent;")
        self.spin_cpu = QSpinBox()
        self.spin_cpu.setRange(1, 100)
        self.spin_cpu.setValue(50)
        self.spin_cpu.setStyleSheet(SPINBOX_STYLE)

        res_l.addWidget(lbl_ram)
        res_l.addWidget(self.spin_ram)
        res_l.addWidget(lbl_cpu)
        res_l.addWidget(self.spin_cpu)
        res_l.addStretch()
        l.addWidget(res_box)

        # Control buttons
        h = QHBoxLayout()
        h.setSpacing(10)
        self.btn_dyn_start = DangerButton("⚠  Execute on HOST")
        self.btn_dyn_start.clicked.connect(self.run_dynamic)

        self.btn_vm_start = SuccessButton("🖥  Run in Sandbox VM")
        self.btn_vm_start.clicked.connect(self.run_in_vm)

        self.btn_dyn_stop = GhostButton("⏹  Stop")
        self.btn_dyn_stop.clicked.connect(self.stop_dynamic)
        self.btn_dyn_stop.setEnabled(False)

        # Behavior risk meter (inline)
        self.lbl_behavior_score = QLabel("Behavior Risk: —")
        self.lbl_behavior_score.setStyleSheet(
            "color: #3fb950; font-size: 12px; font-weight: 700;"
            "background: transparent; border: none; padding: 0 12px;"
        )

        h.addWidget(self.btn_dyn_start)
        h.addWidget(self.btn_vm_start)
        h.addWidget(self.lbl_behavior_score)
        h.addStretch()
        h.addWidget(self.btn_dyn_stop)
        l.addLayout(h)

        # ── Splitter: Console (left) | Behavior Feed (right) ──
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background: #21262d;
                width: 2px;
            }
        """)

        # Left — Execution Console
        console_panel = QWidget()
        console_panel.setStyleSheet("background: transparent;")
        cp_l = QVBoxLayout(console_panel)
        cp_l.setContentsMargins(0, 0, 4, 0)
        cp_l.setSpacing(6)
        cp_l.addWidget(SectionLabel("Execution Console"))
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet(CONSOLE_STYLE)
        self.console.setPlaceholderText("Execution logs will appear here...")
        cp_l.addWidget(self.console)
        splitter.addWidget(console_panel)

        # Right — Behavior Event Feed
        feed_panel = QWidget()
        feed_panel.setStyleSheet("background: transparent;")
        fp_l = QVBoxLayout(feed_panel)
        fp_l.setContentsMargins(4, 0, 0, 0)
        fp_l.setSpacing(6)

        feed_header = QHBoxLayout()
        feed_header.addWidget(SectionLabel("Live Behavior Feed"))
        feed_header.addStretch()
        self.lbl_event_count = QLabel("0 events")
        self.lbl_event_count.setStyleSheet(
            "color: #484f58; font-size: 10px; background: transparent; border: none;"
        )
        feed_header.addWidget(self.lbl_event_count)
        fp_l.addLayout(feed_header)

        self.table_behavior = QTableWidget(0, 4)
        self.table_behavior.setHorizontalHeaderLabels(["Time", "Category", "Severity", "Event"])
        self.table_behavior.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_behavior.horizontalHeader().setDefaultSectionSize(80)
        self.table_behavior.setStyleSheet(TABLE_STYLE)
        self.table_behavior.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_behavior.verticalHeader().setVisible(False)
        self.table_behavior.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_behavior.setColumnWidth(0, 72)
        self.table_behavior.setColumnWidth(1, 90)
        self.table_behavior.setColumnWidth(2, 84)
        fp_l.addWidget(self.table_behavior)
        splitter.addWidget(feed_panel)

        splitter.setSizes([480, 520])
        l.addWidget(splitter)
        return p

    def create_registry_page(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(28, 28, 28, 28)
        l.setSpacing(16)

        title = QLabel("Registry Monitor")
        title.setStyleSheet(
            "font-size: 22px; font-weight: 700; color: #e6edf3; background: transparent;"
        )
        l.addWidget(title)

        info = QLabel("Persistence & registry anomalies detected after dynamic analysis.")
        info.setStyleSheet("font-size: 12px; color: #6e7681; background: transparent;")
        l.addWidget(info)
        l.addWidget(Divider())

        l.addWidget(SectionLabel("Detected Anomalies"))
        self.txt_reg_alerts = QTextEdit()
        self.txt_reg_alerts.setPlaceholderText(
            "Registry scan will run automatically after Dynamic Analysis completes."
        )
        self.txt_reg_alerts.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                color: #d29922;
                font-family: 'Consolas', monospace;
                font-size: 13px;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        l.addWidget(self.txt_reg_alerts)
        return p

    def create_defense_page(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(28, 28, 28, 28)
        l.setSpacing(16)

        title = QLabel("Defense Configuration")
        title.setStyleSheet(
            "font-size: 22px; font-weight: 700; color: #e6edf3; background: transparent;"
        )
        l.addWidget(title)

        info = QLabel("Configure isolation and protection policies applied during dynamic execution.")
        info.setStyleSheet("font-size: 12px; color: #6e7681; background: transparent;")
        l.addWidget(info)
        l.addWidget(Divider())

        box = QGroupBox("Isolation Policy")
        box.setStyleSheet(GROUPBOX_STYLE)
        bl = QVBoxLayout(box)
        bl.setSpacing(4)

        self.chk_net = QCheckBox("🌐  Block Network Traffic")
        self.chk_net.setChecked(True)
        self.chk_net.setStyleSheet(CHECKBOX_STYLE)
        self.chk_net.stateChanged.connect(self.update_policy)

        self.chk_clip = QCheckBox("📋  Block Clipboard Access")
        self.chk_clip.setChecked(True)
        self.chk_clip.setStyleSheet(CHECKBOX_STYLE)
        self.chk_clip.stateChanged.connect(self.update_policy)
        
        self.chk_decoy = QCheckBox("📄  Deploy Sandbox Decoy Files (Environment Mutation)")
        self.chk_decoy.setChecked(False)
        self.chk_decoy.setStyleSheet(CHECKBOX_STYLE)

        bl.addWidget(self.chk_net)
        bl.addWidget(self.chk_clip)
        bl.addWidget(self.chk_decoy)
        l.addWidget(box)

        # Info note
        note = QLabel(
            "ℹ  These settings take effect on the next Dynamic Execution session."
        )
        note.setStyleSheet(
            "font-size: 11px; color: #484f58; background: transparent; padding: 4px 0px;"
        )
        l.addWidget(note)
        l.addStretch()
        return p

    def create_intel_page(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: #0a0d14; }")
        
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(28, 28, 28, 28)
        l.setSpacing(18)

        # ── Header ──
        h_head = QHBoxLayout()
        v_title = QVBoxLayout()
        title = QLabel("Intelligence Hub")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #e6edf3; background: transparent;")
        v_title.addWidget(title)
        info = QLabel("Real-time behavioral correlation and global threat intelligence.")
        info.setStyleSheet("font-size: 13px; color: #8b949e; background: transparent;")
        v_title.addWidget(info)
        h_head.addLayout(v_title)
        h_head.addStretch()
        l.addLayout(h_head)
        l.addWidget(Divider())

        # ── Intelligence Cards (VT Data) ──
        h_cards = QHBoxLayout()
        self.card_vt_category = IntelMetricCard("Category", "Ready")
        self.card_vt_label = IntelMetricCard("Threat Label", "Unknown")
        self.card_vt_ratio = IntelMetricCard("Global Detection", "0 / 0")
        h_cards.addWidget(self.card_vt_category)
        h_cards.addWidget(self.card_vt_label)
        h_cards.addWidget(self.card_vt_ratio)
        h_cards.addStretch()
        l.addLayout(h_cards)

        # ── MITRE ATT&CK & Signature (Main Body) ──
        h_body = QHBoxLayout()
        h_body.setSpacing(24)
        
        # Left: MITRE Grid
        v_mitre = QVBoxLayout()
        v_mitre.addWidget(SectionLabel("MITRE ATT&CK® Identification"))
        self.mitre_grid = MitreGrid()
        v_mitre.addWidget(self.mitre_grid)
        v_mitre.addStretch()
        h_body.addLayout(v_mitre, 2)

        # Right: Signals & Forensics
        v_signals = QVBoxLayout()
        v_signals.setSpacing(16)
        
        v_signals.addWidget(SectionLabel("Digital Signature & Trust"))
        self.lbl_trust_verdict = QLabel("Waiting for analysis...")
        self.lbl_trust_verdict.setStyleSheet("color: #8b949e; font-size: 13px; background: transparent;")
        v_signals.addWidget(self.lbl_trust_verdict)
        
        v_signals.addWidget(SectionLabel("Campaign Correlation"))
        self.lbl_campaign = QLabel("No active campaign detected.")
        self.lbl_campaign.setStyleSheet("color: #8b949e; font-size: 13px; background: transparent;")
        self.lbl_campaign.setWordWrap(True)
        v_signals.addWidget(self.lbl_campaign)

        v_signals.addWidget(SectionLabel("Environment Forensics"))
        self.lbl_anti_vm = QLabel("Monitoring virtualization evasion tactics...")
        self.lbl_anti_vm.setStyleSheet("color: #8b949e; font-size: 13px; background: transparent;")
        v_signals.addWidget(self.lbl_anti_vm)
        
        v_signals.addStretch()
        h_body.addLayout(v_signals, 1)
        
        l.addLayout(h_body)
        l.addWidget(Divider())

        # ── Extended Forensics (FS Diff) ──
        l.addWidget(SectionLabel("File System Changes (Post-Execution Diff)"))
        self.table_fs_diff = QTableWidget(0, 3)
        self.table_fs_diff.setHorizontalHeaderLabels(["Path", "Change", "Details"])
        self.table_fs_diff.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_fs_diff.setStyleSheet(TABLE_STYLE)
        self.table_fs_diff.setAlternatingRowColors(True)
        self.table_fs_diff.setFixedHeight(220)
        l.addWidget(self.table_fs_diff)
        
        l.addStretch()
        scroll.setWidget(p)
        return scroll

    # ─────────────────────────────────────────────
    #  LOGIC
    # ─────────────────────────────────────────────

    def change_page(self, row):
        self.stack.setCurrentIndex(row)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            
    def dropEvent(self, event):
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.isfile(file_path):
                self._load_file(file_path)
                break # Only load first file

    def load_sample(self):
        f, _ = QFileDialog.getOpenFileName(
            self, "Select Executable", "",
            "Executables (*.exe *.dll *.bin);;All Files (*)"
        )
        if f:
            self._load_file(f)
            
    def _load_file(self, f):
        # 1. System Stability: Prevent "QThread: Destroyed while thread is still running" fatal crash 
        try:
            if getattr(self, "worker_stat", None) and self.worker_stat.isRunning():
                self.worker_stat.terminate()
                self.worker_stat.wait()
                
            if getattr(self, "worker_dyn", None) and self.worker_dyn.isRunning():
                if hasattr(self.worker_dyn, 'stop'): self.worker_dyn.stop()
                self.worker_dyn.terminate()
                self.worker_dyn.wait()
                
            if getattr(self, "worker_beh", None) and self.worker_beh.isRunning():
                if hasattr(self.worker_beh, 'stop'): self.worker_beh.stop()
                self.worker_beh.terminate()
                self.worker_beh.wait()
                
            if getattr(self, "_batch_worker_obj", None) and self._batch_worker_obj.isRunning():
                if hasattr(self._batch_worker_obj, 'stop'): self._batch_worker_obj.stop()
                self._batch_worker_obj.terminate()
                self._batch_worker_obj.wait()
                
            if getattr(self, "worker_hash", None) and self.worker_hash.isRunning():
                self.worker_hash.terminate()
                self.worker_hash.wait()
        except:
            pass

        # 2. Append Mode Option
        if getattr(self, "current_file", None) and self.table_behavior.rowCount() > 0:
            reply = QMessageBox.question(
                self, 'Session Mode',
                "Do you want to append this sample to the existing dynamic session (Keep previous logs)?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            self.append_mode = (reply == QMessageBox.Yes)
        else:
            self.append_mode = False

        self.current_file = f
        name = os.path.basename(f)
        size = os.path.getsize(f)
        size_str = f"{size // 1024} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"

        # Header bar
        self.lbl_file.setText(f"📄  {name}")
        self.lbl_file.setStyleSheet(
            "font-size: 13px; font-weight: 500; color: #c9d1d9;"
            "background: transparent; border: none;"
        )
        self.lbl_badge.setText("LOADED")
        self.lbl_badge.setStyleSheet("""
            background: #1f2a37;
            color: #58a6ff;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            border: 1px solid #1f6feb;
            border-radius: 4px;
            padding: 2px 8px;
        """)

        # Dashboard file info card
        self.lbl_fi_name.setText(name)
        self.lbl_fi_name.setStyleSheet(
            "color: #c9d1d9; font-size: 14px; font-weight: 600;"
            "background: transparent; border: none;"
        )
        self.lbl_fi_size.setText(size_str)

        # Mark step 1 done
        self._mark_step(self.step_load, done=True)

        self.btn_run_static.setEnabled(True)
        self.btn_dyn_start.setEnabled(False)
        self.worker_dyn = None
        self.lbl_md5.setText("—")
        self.lbl_sha1.setText("—")
        self.lbl_sha256.setText("—")
        self.lbl_sha256.setStyleSheet(
            "color: #6e7681; font-family: 'Consolas', monospace; font-size: 12px; background: transparent; border: none;"
        )
        self.card_static.set_value("—")
        self.card_static.bar.setValue(0)
        self.card_static.set_accent("#3fb950")
        self.card_dynamic.set_value("—")
        self.card_dynamic.bar.setValue(0)
        self.card_dynamic.set_accent("#3fb950")
        self.table_imports.setRowCount(0)
        self.table_sections.setRowCount(0)
        self.table_strings.setRowCount(0)
        self.table_yara.setRowCount(0)
        
        if not self.append_mode:
            self.table_behavior.setRowCount(0)
            self.table_network.setRowCount(0)
            self.lbl_event_count.setText("0 events")
            self.lbl_behavior_score.setText("Behavior Risk: 0/100")
            self._behavior_risk = 0
            self.console.clear()
            self.txt_reg_alerts.clear()
            if hasattr(self, 'table_fs_diff'):
                 self.table_fs_diff.setRowCount(0)
            self._behavior_iocs = []

        self.txt_explanation.clear()
        self.btn_export_html.setEnabled(False)
        self.static_score = 0
        
        if not self.append_mode:
            self.dynamic_score = 0
            
        self.update_verdict()
        
        # Intel Hub Resets
        if hasattr(self, 'lbl_trust_verdict'):
            self.lbl_trust_verdict.setText("Run Static Analysis to check signature trust.")
            self.mitre_grid.reset()
            self.card_vt_category.set_value("Ready")
            self.card_vt_label.set_value("Unknown")
            self.card_vt_ratio.set_value("0 / 0")
            if not self.append_mode:
                self.lbl_campaign.setText("Run Dynamic Analysis to correlate behavior with known APT campaigns.")
                self.lbl_anti_vm.setText("Ready to analyze.")

        # Reset step markers
        self._mark_step(self.step_static,  done=False)
        self._mark_step(self.step_dynamic, done=False)
        self._mark_step(self.step_verdict, done=False)

    def run_static(self):
        if not self.current_file:
            return
        self.btn_run_static.setEnabled(False)
        self.btn_run_static.setText("Analyzing…")
        self.worker_stat = StaticAnalysisWorker(self.current_file)
        self.worker_stat.finished.connect(self.on_static_done)
        self.worker_stat.start()

    def on_static_done(self, res):
        self.btn_run_static.setEnabled(True)
        self.btn_run_static.setText("🔬  Run Static Analysis")
        if not res:
            return
        self._mark_step(self.step_static, done=True)
        
        # Check Signature Trust
        trust = TrustAnalyzer.verify_signature(Path(self.current_file))
        is_lolbin = TrustAnalyzer.check_lolbin_abuse(Path(self.current_file).name)
        trust_color = {"TrustedSigned": "#3fb950", "InvalidSignature": "#f78166", "SelfSigned": "#d29922", "Unsigned": "#8b949e", "StolenCert": "#ff4444"}.get(trust.value, "#8b949e")
        trust_text = f"Signature Status: <span style='color:{trust_color};'>{trust.value}</span>"
        if is_lolbin:
            trust_text += " <span style='color:#ff4444;'>(⚠ LOLBin Detected)</span>"
        self.lbl_trust_verdict.setText(trust_text)

        self.static_score = res.threat_score
        self.card_static.set_value(f"{res.threat_score} / 100")
        self.card_static.bar.setValue(res.threat_score)
        self._set_score_color(self.card_static, res.threat_score)

        # ── Show hashes ──────────────────────────────────────────
        if res.hashes:
            h = res.hashes
            self.lbl_md5.setText(h.md5)
            self.lbl_sha1.setText(h.sha1)
            self.lbl_sha256.setText(h.sha256)
            self.lbl_sha256.setStyleSheet(
                "color: #c9d1d9; font-family: 'Consolas', monospace; font-size: 12px;"
                "background: transparent; border: none;"
            )
            self.btn_hash_lookup.setEnabled(True)
            self._last_sha256 = h.sha256
        else:
            self.lbl_md5.setText("N/A")
            self.lbl_sha1.setText("N/A")
            self.lbl_sha256.setText("N/A")

        # ── Imports table ────────────────────────────────────────
        self.table_imports.setRowCount(0)
        for imp in res.imports:
            row = self.table_imports.rowCount()
            self.table_imports.insertRow(row)
            item = QTableWidgetItem(imp)
            item.setForeground(QColor("#f78166"))
            self.table_imports.setItem(row, 0, item)

        # ── Sections table ───────────────────────────────────────
        self.table_sections.setRowCount(0)
        for s in res.sections:
            row = self.table_sections.rowCount()
            self.table_sections.insertRow(row)
            self.table_sections.setItem(row, 0, QTableWidgetItem(s.name))
            entropy_item = QTableWidgetItem(f"{s.entropy:.2f}")
            if s.entropy > 7.0:
                entropy_item.setForeground(QColor("#d29922"))
            self.table_sections.setItem(row, 1, entropy_item)
            self.table_sections.setItem(row, 2, QTableWidgetItem(str(s.virtual_size)))

        # ── YARA Scan ────────────────────────────────────────────
        yara = YaraScanner(Path("dragoncode_sandbox/yara_rules"))
        yara_matches = yara.scan_file(Path(self.current_file))
        self.table_yara.setRowCount(0)
        for m in yara_matches:
            row = self.table_yara.rowCount()
            self.table_yara.insertRow(row)
            self.table_yara.setItem(row, 0, QTableWidgetItem(m.rule_name))
            self.table_yara.setItem(row, 1, QTableWidgetItem(m.description))
            self.table_yara.setItem(row, 2, QTableWidgetItem(", ".join(m.tags)))

        # ── Strings Extraction ───────────────────────────────────
        extracted = StringAnalyzer.analyze(Path(self.current_file))
        self.table_strings.setRowCount(0)
        def _add_str_rows(lbl, items, color):
            for itm in items:
                row = self.table_strings.rowCount()
                self.table_strings.insertRow(row)
                ti = QTableWidgetItem(lbl)
                ti.setForeground(QColor(color))
                self.table_strings.setItem(row, 0, ti)
                self.table_strings.setItem(row, 1, QTableWidgetItem(itm))
                
        _add_str_rows("URL", extracted.urls, "#3fb950")
        _add_str_rows("IP", extracted.ips, "#d29922")
        _add_str_rows("Registry", extracted.registries, "#f78166")
        _add_str_rows("Base64", extracted.base64, "#8b949e")

        self.update_verdict()
        self.sidebar.setCurrentRow(1)
        
        # ── Auto-trigger Threat Intelligence Lookup ──────────────
        self.run_hash_lookup()

    def run_hash_lookup(self):
        sha256 = getattr(self, "_last_sha256", "")
        if not sha256:
            return
        self.btn_hash_lookup.setEnabled(False)
        self.btn_hash_lookup.setText("Searching…")
        self.lbl_lookup_spin.setText("⏳  Querying threat intelligence…")
        vt_key = self.txt_vt_key.text().strip()
        self.worker_hash = HashLookupWorker(sha256, vt_key=vt_key)
        self.worker_hash.finished.connect(self.on_hash_lookup_done)
        self.worker_hash.start()

        # Details labels for secondary views
        self.lbl_ti_source.setText(result.source)
        self.lbl_ti_ratio.setText(result.detection_ratio)

        # Update Modern Intel Cards
        cat = result.category or "Clean/Unknown"
        self.card_vt_category.set_value(cat.upper())
        self.card_vt_label.set_value(result.threat_label or "N/A")
        self.card_vt_ratio.set_value(result.detection_ratio, color=color)

        # Display suggested label if category is known
        display_name = result.threat_label or result.threat_name or "—"
        if result.category:
            display_name = f"[{result.category.upper()}] {display_name}"
        self.lbl_ti_name.setText(display_name)

        # Enhanced Tags View
        tag_str = ", ".join(result.tags) if result.tags else "—"
        self.lbl_ti_tags.setText(tag_str)
        self.lbl_ti_tags.setToolTip(tag_str)

        # Sandbox Summary
        if result.sandbox_verdicts:
            sb_summary = []
            for sb in result.sandbox_verdicts:
                color = "#f78166" if sb["verdict"] == "malicious" else "#3fb950"
                sb_summary.append(f"<span style='color:{color};'>{sb['sandbox']}: {sb['verdict']}</span>")
            self.add_log(f"[TI] Sandbox History: {', '.join(sb_summary)}")

        if result.permalink:
            self.lbl_ti_link.setText(
                f'<a href="{result.permalink}" style="color:#58a6ff;">Open VT Report ↗</a>'
            )
        else:
            self.lbl_ti_link.setText("—")

    def run_in_vm(self):
        if not self.current_file:
            return
        sandbox_exe = r"C:\Windows\System32\WindowsSandbox.exe"
        if not os.path.exists(sandbox_exe):
            QMessageBox.critical(
                self, "Error",
                "Windows Sandbox feature is NOT enabled!\n\n"
                "Please go to 'Turn Windows features on or off' and enable 'Windows Sandbox'.\n"
                "A restart of Windows may be required."
            )
            self.console.append("[!] Error: Windows Sandbox not found.")
            return

        project_root = str(Path(__file__).parent.parent.parent.resolve())
        tasks_dir = os.path.join(project_root, "tasks")
        if not os.path.exists(tasks_dir):
            os.makedirs(tasks_dir)

        target_name = os.path.basename(self.current_file)
        task_id = int(time.time())
        unique_name = f"{task_id}_{target_name}"
        dest_path = os.path.join(tasks_dir, unique_name)
        
        # Clean up old report to avoid stale results (if any somehow exist with same ID)
        old_report = os.path.join(project_root, f"sandbox_report_{unique_name}.json")
        if os.path.exists(old_report):
            try:
                os.remove(old_report)
            except: pass

        # ── 1. Check if Sandbox is already running (Heartbeat) ──
        is_running = False
        ping_file = os.path.join(tasks_dir, "ping.txt")
        pong_file = os.path.join(tasks_dir, "pong.txt")
        
        # Clean up old pong
        if os.path.exists(pong_file):
            try: os.remove(pong_file)
            except: pass
            
        # Send Ping
        try:
            with open(ping_file, "w") as f:
                f.write("ping")
        except: pass
        
        # Wait up to 2.5 seconds for Pong
        self.console.append("[*] Checking if Sandbox Agent is alive...")
        for _ in range(5):
            time.sleep(0.5)
            if os.path.exists(pong_file):
                is_running = True
                try: os.remove(pong_file)
                except: pass
                break
        
        if not is_running:
            # Fallback check for process just in case
            try:
                for p in psutil.process_iter(['name']):
                    pname = p.info['name'].lower()
                    if "sandbox" in pname and ("windows" in pname or "client" in pname):
                        is_running = True
                        break
            except: pass

        # ── 2. Purge old tasks if starting fresh ──
        if not is_running:
            self.console.append("[*] Sandbox not active. Purging old task queue...")
            for old_f in os.listdir(tasks_dir):
                if old_f.lower().endswith(('.exe', '.dll', '.bin')):
                    try:
                        os.remove(os.path.join(tasks_dir, old_f))
                        self.console.append(f"  [-] Removed stale task: {old_f}")
                    except Exception as e:
                        pass # Might be locked by host, but at least we try

        # ── 3. Submit the New File ──
        try:
            shutil.copy2(self.current_file, dest_path)
            self.console.append(f"[*] Task pushed to VM queue: {unique_name}")
        except Exception as e:
            self.console.append(f"[!] Failed to push task: {e}")
            return

        # ── 4. Launch Sandbox if needed ──
        if not is_running:
            try:
                from ..virtualization.windows_sandbox import WindowsSandboxGenerator
                python_path = sys.prefix
                self.console.append("[*] Generating Sandbox Configuration (.wsb)...")
                wsb_path = WindowsSandboxGenerator.generate_wsb(project_root, python_path)
                self.console.append(f"[+] Configuration saved: {wsb_path}")
                self.console.append(f"[*] Launching {sandbox_exe}...")
                subprocess.Popen([sandbox_exe, wsb_path], shell=True)
                self.console.append("[*] Windows Sandbox launched! Check the new window.")
            except Exception as e:
                self.console.append(f"[!] VM Launch Failed: {e}")
                return
            else:
                self.console.append("[*] Sandbox is already running. Task submitted to active agent.")
        
        # ── Write sandbox_config.json for the Agent to read ──────────────
        try:
            timeout_s   = self.spin_timeout.value()   if hasattr(self, 'spin_timeout')  else 15
            enable_mem  = self.chk_memory.isChecked() if hasattr(self, 'chk_memory')    else True
            enable_reg  = self.chk_registry.isChecked() if hasattr(self, 'chk_registry') else True
            block_net   = self.chk_network.isChecked() if hasattr(self, 'chk_network')   else False
            cfg = {
                "timeout_sec":    timeout_s,
                "enable_memory":  enable_mem,
                "enable_registry": enable_reg,
                "block_network":  block_net,
            }
            cfg_path = os.path.join(project_root, "sandbox_config.json")
            with open(cfg_path, "w") as cf:
                import json as _json
                _json.dump(cfg, cf, indent=2)
            self.console.append(
                f"[*] Sandbox config written → timeout={timeout_s}s | "
                f"memory={'ON' if enable_mem else 'OFF'} | "
                f"registry={'ON' if enable_reg else 'OFF'} | "
                f"net_block={'ON' if block_net else 'OFF'}"
            )
        except Exception as e:
            self.console.append(f"[-] Could not write sandbox_config: {e}")


        self.console.append(f"[*] Waiting for report (sandbox_report_{unique_name}.json)...")
        # Ensure we don't start multiple timers for the same file if clicked repeatedly
        if hasattr(self, 'vm_timer') and self.vm_timer.isActive():
            self.vm_timer.stop()
            
        self.vm_timer = QTimer()
        self.vm_timer.timeout.connect(lambda: self.check_vm_report(project_root, unique_name))
        
        self.btn_vm_start.setEnabled(False)
        self.btn_dyn_start.setEnabled(False)
        self.btn_dyn_stop.setEnabled(True)
        self.vm_timer.start(500)

    def check_vm_report(self, root, target_name):
        report_path = os.path.join(root, f"sandbox_report_{target_name}.json")
        if os.path.exists(report_path):
            self.console.append("[+] Report received from VM!")
            self.vm_timer.stop()
            try:
                with open(report_path, 'r') as f:
                    data = json.load(f)
                threat_count = 0
                for t in data.get("dynamic", []):
                    self.console.append(f"[VM THREAT] {t}")
                    threat_count += 1
                vm_score = min(threat_count * 20, 100)
                
                # ── Behavior & Network Injection ──
                beh_data = data.get("behavior", [])
                if beh_data:
                    from ..analysis.behavior import BehaviorEvent, BehaviorCategory, BehaviorSeverity
                    import time
                    self.console.append(f"[*] Parsing {len(beh_data)} behavioral/network events from VM...")
                    for b in beh_data:
                        try:
                            cat = BehaviorCategory[b["category"]]
                            sev = BehaviorSeverity[b["severity"]]
                            ev = BehaviorEvent(
                                timestamp=time.time(), # close enough to actual execution
                                category=cat,
                                severity=sev,
                                title=b["title"],
                                detail=b["detail"]
                            )
                            self.on_behavior_event(ev)
                        except Exception as e:
                            pass
                
                reg_threats = data.get("registry_alerts", [])
                if reg_threats:
                    self.console.append(f"[*] Found {len(reg_threats)} Registry anomalies inside VM.")
                    self.txt_reg_alerts.clear()
                    for rt in reg_threats:
                        self.txt_reg_alerts.append(
                            f"[!] {rt.get('technique', 'Unknown')}: {rt.get('description', '')}\n    {rt.get('path', '')}\n"
                        )
                    vm_score = min(vm_score + 15, 100)
                    self.sidebar.setCurrentRow(3) # Navigate to Registry tab
                else:
                    self.txt_reg_alerts.clear()
                    self.txt_reg_alerts.setText("✓  No registry anomalies detected within the Sandbox VM.")

                # We need to simulate a dynamic completion
                self.dynamic_score = vm_score
                self.update_verdict()
                self._mark_step(self.step_dynamic, done=True)
                self.card_dynamic.set_value(f"{vm_score} / 100")
                self.card_dynamic.bar.setValue(vm_score)
                self._set_score_color(self.card_dynamic, vm_score)
                self.btn_export_html.setEnabled(True)
                
                # Reset Buttons
                self.btn_vm_start.setEnabled(True)
                self.btn_dyn_start.setEnabled(True)
                self.btn_dyn_stop.setEnabled(False)
                
                # Save to History
                self.final_score = vm_score
                self._save_session_history()
                
                # ── Auto-Containment via ResponseDispatcher ──────────────
                auto_kill = getattr(self, 'chk_auto_kill', None)
                if vm_score >= 80 and (auto_kill is None or auto_kill.isChecked()):
                    try:
                        from ..defense.response_dispatcher import ResponseDispatcher
                        project_root = str(Path(__file__).resolve().parents[2] / "C:\\Project")
                        # Use the standard shared folder path
                        dispatcher = ResponseDispatcher(r"C:\Project")
                        target_path = self.current_file or ""
                        cmd_id = dispatcher.full_containment(image_path=target_path)
                        self.console.append(
                            f"[🛡] CRITICAL THREAT ({vm_score}%) — Auto-Containment dispatched "
                            f"to Sandbox VM (cmd: {cmd_id[:8]}...)"
                        )
                    except Exception as ex:
                        self.console.append(f"[!] Auto-Containment failed: {ex}")
                
                try:
                    os.remove(report_path)
                except: pass
            except:
                pass

    def run_dynamic(self):
        if not self.current_file:
            return
        if QMessageBox.warning(
            self, "⚠ Warning",
            "You are about to execute the sample directly on this HOST machine.\n\n"
            "This is potentially dangerous. Continue?",
            QMessageBox.Yes | QMessageBox.No
        ) != QMessageBox.Yes:
            return

        # Reset UI if not appending
        if not hasattr(self, 'append_mode') or not self.append_mode:
            self.console.clear()
            self.table_behavior.setRowCount(0)
            self.lbl_event_count.setText("0 events")
            self.lbl_behavior_score.setText("Behavior Risk: —")
            self.lbl_behavior_score.setStyleSheet(
                "color: #3fb950; font-size: 12px; font-weight: 700;"
                "background: transparent; border: none; padding: 0 12px;"
            )
            self._behavior_risk = 0

        self.btn_dyn_start.setEnabled(False)
        self.btn_dyn_stop.setEnabled(True)
        
        if not (hasattr(self, 'append_mode') and self.append_mode and self.reg_snap):
            self.reg_snap = self.reg_worker.capture()
            
        ram = self.spin_ram.value()
        cpu = self.spin_cpu.value()

        # Launch process worker
        if self.chk_decoy.isChecked() and not (hasattr(self, 'append_mode') and self.append_mode):
            from ..deception.mutation import EnvironmentMutator
            try:
                EnvironmentMutator(Path.home() / "Desktop").randomize()
                self.add_log("[+] Deception: Decoy files deployed to Desktop.")
            except Exception as e:
                self.add_log(f"[-] Deception Error: {e}")

        # Take filesystem snapshot before execution
        if not (hasattr(self, 'append_mode') and self.append_mode and self.disk_snapshot):
            self.add_log("[*] Taking targeted File System snapshot...")
            self.disk_snapshot = DiskSnapshot.take_targeted()
            self.add_log("[+] Snapshot complete.")

        # Read settings values
        enable_mem = getattr(self, 'chk_memory', None)
        enable_mem = enable_mem.isChecked() if enable_mem else True
        timeout_s  = getattr(self, 'spin_timeout', None)
        timeout_s  = timeout_s.value() if timeout_s else 15

        self.worker_dyn = DynamicAnalysisWorker(
            self.current_file, self.isolation_config, ram, cpu,
            enable_memory=enable_mem, timeout_sec=timeout_s
        )
        self.worker_dyn.log.connect(self.add_log)
        self.worker_dyn.finished.connect(self.on_dynamic_done)
        self.worker_dyn.started.connect(self._start_behavior_worker)
        self.worker_dyn.start()
        self.sidebar.setCurrentRow(2)

    def _start_behavior_worker(self, pid: int):
        self.add_log(f"[BEH] Behavioral monitor attached to PID {pid}")
        self.worker_beh = BehaviorWorker(pid)
        self.worker_beh.event.connect(self.on_behavior_event)
        self.worker_beh.finished.connect(self._on_behavior_done)
        self.worker_beh.start()

    def on_behavior_event(self, ev: "BehaviorEvent"):
        """Called from BehaviorWorker signal — runs on GUI thread."""
        sev   = ev.severity
        color = sev.color

        # Add row to behavior table
        row = self.table_behavior.rowCount()
        self.table_behavior.insertRow(row)

        def _item(text, fg=None, bold=False):
            it = QTableWidgetItem(text)
            it.setForeground(QColor(fg or "#c9d1d9"))
            if bold:
                f = it.font()
                f.setBold(True)
                it.setFont(f)
            it.setTextAlignment(Qt.AlignCenter)
            return it

        self.table_behavior.setItem(row, 0, _item(ev.time_str, "#6e7681"))
        self.table_behavior.setItem(row, 1, _item(ev.category.value, "#58a6ff"))
        self.table_behavior.setItem(row, 2, _item(sev.value, color, bold=True))

        # ── Link to Intelligence Hub ──
        if ev.mitre_id:
            self.mitre_grid.highlight(ev.mitre_id)
            if ev.mitre_id == "T1497":
                self.lbl_anti_vm.setText(f"<span style='color:#f78166;'>[!] Evasion Detected:</span> {ev.detail}")
            elif ev.mitre_id == "T1547":
                self.lbl_campaign.setText(f"<span style='color:#f78166;'>[!] Persistence:</span> User Startup modification detected.")

        detail_item = QTableWidgetItem(ev.title)
        detail_item.setForeground(QColor(color))
        if ev.detail:
            detail_item.setToolTip(ev.detail)
        self.table_behavior.setItem(row, 3, detail_item)

        self.table_behavior.scrollToBottom()

        # Update event count
        count = self.table_behavior.rowCount()
        self.lbl_event_count.setText(f"{count} event{'s' if count != 1 else ''}")

        # Update inline risk score
        self._behavior_risk = min(self._behavior_risk + sev.score, 100)
        risk_color = (
            "#f78166" if self._behavior_risk >= 60
            else "#d29922" if self._behavior_risk >= 30
            else "#3fb950"
        )
        self.lbl_behavior_score.setText(f"Behavior Risk: {self._behavior_risk}/100")
        self.lbl_behavior_score.setStyleSheet(
            f"color: {risk_color}; font-size: 12px; font-weight: 700;"
            "background: transparent; border: none; padding: 0 12px;"
        )

        # Mirror to console for high/critical events
        if sev in (BehaviorSeverity.HIGH, BehaviorSeverity.CRITICAL):
            self.add_log(f"[BEH/{sev.value}] {ev.title}  {('— ' + ev.detail) if ev.detail else ''}")
            
        # Add to network table if applicable
        if ev.category.value == "NETWORK":
            net_row = self.table_network.rowCount()
            self.table_network.insertRow(net_row)
            self.table_network.setItem(net_row, 0, _item(ev.time_str, "#6e7681"))
            # The title is f"Network connection: {ip}:{port}{flag}"
            ip_port = ev.title.replace("Network connection: ", "")
            self.table_network.setItem(net_row, 1, QTableWidgetItem(ip_port))
            self.table_network.setItem(net_row, 2, QTableWidgetItem(ev.detail))
            self.table_network.setItem(net_row, 3, _item(sev.value, color, bold=True))
            
        # Collect for campaign correlation
        if ev.detail:
            self._behavior_iocs.append(ev.detail)
        if ev.title:
            self._behavior_iocs.append(ev.title)

    def _on_behavior_done(self, behavior_score: int):
        self._behavior_risk = behavior_score

    def stop_dynamic(self):
        # 1. Stop Host Workers
        if self.worker_dyn:
            self.worker_dyn.stop()
        if hasattr(self, "worker_beh") and self.worker_beh:
            self.worker_beh.stop()
            
        # 2. Stop VM Execution
        if hasattr(self, "vm_timer") and self.vm_timer.isActive():
            self.vm_timer.stop()
            self.add_log("[*] VM Monitoring Stopped by user.")
            
        try:
            import psutil
            for p in psutil.process_iter(['name']):
                pname = p.info['name'].lower()
                if "windowssandbox" in pname:
                    p.terminate()
                    self.add_log("[*] Windows Sandbox Terminated by user.")
        except:
            pass

        # 3. Reset Buttons
        self.btn_dyn_stop.setEnabled(False)
        self.btn_dyn_start.setEnabled(True)
        self.btn_vm_start.setEnabled(True)

    def add_log(self, msg):
        self.console.append(msg)

    def on_dynamic_done(self, score):
        # Stop behavior monitor
        if hasattr(self, "worker_beh") and self.worker_beh:
            self.worker_beh.stop()

        # Merge behavior risk into dynamic score
        behavior_risk = getattr(self, "_behavior_risk", 0)
        combined = min(score + behavior_risk // 3, 100)
        self.dynamic_score = combined
        self._set_score_color(self.card_dynamic, combined)

        self.btn_dyn_start.setEnabled(True)
        self.btn_dyn_stop.setEnabled(False)
        self._mark_step(self.step_dynamic, done=True)
        
        # Calculate final verdict
        v = self.update_verdict()
        
        # Update Interpretation & UI
        self._mark_step(self.step_verdict, done=True)
        self.btn_export_html.setEnabled(True)

        self._run_reg_diff()
        
        # Update Radar Chart
        try:
            static_score = getattr(self, "static_score", 0)
            network_score = sum(10 for ev in self._behavior_iocs if "192" not in str(ev)) # stub
            registry_score = 50 if self._registry_anomalies else 0
            self.radar_chart.set_scores(static_score, behavior_risk, min(100, network_score), registry_score, behavior_risk)
        except Exception as e:
            pass

        self.add_log(
            f"[✓] Analysis complete. "
            f"Process Score: {score}/100  |  "
            f"Behavior Score: {behavior_risk}/100  |  "
            f"Combined: {combined}/100"
        )
        # Save to local history automatically
        self.final_score = combined
        self._save_session_history()

    def _save_session_history(self):
        try:
            import re
            v = self.update_verdict()
            s_score = getattr(self, "static_score", 0)
            d_score = getattr(self, "dynamic_score", 0)
            avg_score = (s_score + d_score) // 2
    
            if avg_score <= 30:
                level = "Benign (Safe)"
            elif avg_score <= 50:
                level = "Suspicious (Moderate)"
            else:
                level = "Malicious (Critical)"

            verdict_data = {
                "static_score": s_score,
                "dynamic_score": d_score,
                "score": avg_score, 
                "level": level, 
                "label": level
            }
            
            raw_trust = self.lbl_trust_verdict.text().split(':')[-1] if hasattr(self, "lbl_trust_verdict") else "Unsigned"
            clean_trust = re.sub('<[^<]+>', '', raw_trust).strip()
            
            static_info = {
                "md5": self.lbl_md5.text() if hasattr(self, "lbl_md5") else "N/A",
                "sha256": self.lbl_sha256.text() if hasattr(self, "lbl_sha256") else "N/A",
                "signature": clean_trust
            }
            dynamic_events = []
            for row in range(self.table_behavior.rowCount()):
                dynamic_events.append({
                    "time": self.table_behavior.item(row, 0).text(),
                    "category": self.table_behavior.item(row, 1).text(),
                    "severity": self.table_behavior.item(row, 2).text(),
                    "title": self.table_behavior.item(row, 3).text(),
                })
            import tempfile
            import os
            from datetime import datetime
            from ..reporting.html_export import ReportExporter
            
            rep_path = Path(tempfile.gettempdir()) / f"auto_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            ReportExporter.export_html(
                os.path.basename(self.current_file) if self.current_file else "unknown.exe",
                verdict_data,
                static_info,
                dynamic_events,
                dest_path=str(rep_path)
            )
            
            self.history_manager.add_session(
                file_name=os.path.basename(self.current_file) if self.current_file else "unknown.exe",
                md5=static_info["md5"],
                verdict=v.level.value,
                score=v.score,
                report_path=str(rep_path)
            )
            self._refresh_history_table()

            # ── Auto PDF Export (if enabled in Settings) ──────────────
            auto_pdf = getattr(self, 'chk_auto_pdf', None)
            if auto_pdf and auto_pdf.isChecked():
                try:
                    from ..reporting.pdf_export import PDFExporter
                    pdf_path = Path(tempfile.gettempdir()) / f"auto_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                    PDFExporter.export_pdf(
                        os.path.basename(self.current_file) if self.current_file else "unknown.exe",
                        verdict_data,
                        static_info,
                        dynamic_events,
                        str(pdf_path)
                    )
                    import webbrowser
                    webbrowser.open(f"file://{pdf_path}")
                    print(f"[Auto PDF] Exported: {pdf_path}")
                except Exception as pdf_err:
                    print(f"[Auto PDF] Failed: {pdf_err}")

        except Exception as e:
            print(f"[History Save] Exception: {e}")

        # Registry Diffing (if enabled)
        enable_reg = self.chk_registry.isChecked() if hasattr(self, 'chk_registry') else True
        if enable_reg and self.reg_snap:
            try:
                after = self.reg_worker.capture()
                diff = RegistryDiff.compare(self.reg_snap, after)
                alerts = diff.detect_anomalies()
                if alerts:
                    self.txt_reg_alerts.clear()
                    self.dynamic_score = min(self.dynamic_score + 15, 100)
                    for a in alerts:
                        self.txt_reg_alerts.append(
                            f"[!] {a.technique}: {a.description}\n    {a.path}\n"
                        )
                    self._registry_anomalies = alerts
                    self.sidebar.setCurrentRow(3)
                else:
                    self.txt_reg_alerts.setText("✓  No registry anomalies detected.")
            except Exception as reg_err:
                print(f"[Reg Diff] Error: {reg_err}")
        else:
            self.txt_reg_alerts.setText("Skipped: Registry monitoring disabled in settings.")
                
        # File System Diffing (Post-exec)
        if self.disk_snapshot:
            self.add_log("[*] Computing filesystem diff...")
            snap_after = DiskSnapshot.take_targeted()
            self.disk_diff = DiskDiff.compute(self.disk_snapshot, snap_after)
            
            self.table_fs_diff.setRowCount(0)
            for file_path, change in self.disk_diff.changes.items():
                row = self.table_fs_diff.rowCount()
                self.table_fs_diff.insertRow(row)
                path_item = QTableWidgetItem(str(file_path))
                if isinstance(change, Created):
                    type_item = QTableWidgetItem("Created")
                    type_item.setForeground(QColor("#3fb950"))
                    det_item = QTableWidgetItem(f"{change.size} bytes")
                elif isinstance(change, Modified):
                    type_item = QTableWidgetItem("Modified")
                    type_item.setForeground(QColor("#d29922"))
                    det_item = QTableWidgetItem(f"{change.size_diff:+} bytes")
                elif isinstance(change, Deleted):
                    type_item = QTableWidgetItem("Deleted")
                    type_item.setForeground(QColor("#f78166"))
                    det_item = QTableWidgetItem("-")
                    
                self.table_fs_diff.setItem(row, 0, path_item)
                self.table_fs_diff.setItem(row, 1, type_item)
                self.table_fs_diff.setItem(row, 2, det_item)
            self.add_log(f"[+] Filesystem diff complete ({len(self.disk_diff.changes)} changes).")

        # Campaign Correlation
        if getattr(self, "_behavior_iocs", None):
            match = self.campaign_tracker.correlate(self._behavior_iocs)
            if match:
                self.lbl_campaign.setText(
                    f"Match Found: <strong style='color:#f78166;'>{match.name}</strong> (Confidence: {match.confidence*100:.1f}%)<br><br>"
                    f"<b>Techniques:</b> {', '.join(match.attack_techniques)}<br>"
                    f"<b>Matched IOCs:</b> {', '.join(match.matched_iocs)}"
                )
                self.add_log(f"[!] Campaign Match: {match.name}")
            else:
                self.lbl_campaign.setText("No known campaigns correlated with dynamic behavior.")
                
        # Anti-VM check
        vm_artifacts = AntiVMCountermeasures.check_vm_artifacts()
        if vm_artifacts:
            self.lbl_anti_vm.setText(
                f"<span style='color:#d29922;'>Host appears to be a Virtual Machine. Malware might alter behavior.</span><br><br>"
                f"<b>Detectors:</b><br>- " + "<br>- ".join(vm_artifacts)
            )
        else:
            self.lbl_anti_vm.setText("<span style='color:#3fb950;'>No overt VM artifacts detected on this host.</span>")

        self.update_verdict()

    def update_policy(self):
        """Regenerate the isolation configuration based on current UI state."""
        from ..defense.network_isolation import (
            NetworkIsolation, ClipboardIsolation, IpcIsolation, CommunicationIsolation
        )
        
        # Network Isolation
        is_net_blocked = self.chk_network.isChecked()
        if is_net_blocked:
            net = NetworkIsolation.new()
        else:
            net = NetworkIsolation.with_network_allowed()
            
        # Clipboard Isolation
        is_clip_blocked = self.chk_clip.isChecked()
        clip = ClipboardIsolation(not is_clip_blocked)
        
        # Consolidate into global config used by workers
        self.isolation_config = CommunicationIsolation(net, clip, IpcIsolation.new())
        
        # Update Dashboard Tooltip or status if needed
        status = "Strict Isolation" if is_net_blocked else "Network Allowed"
        self.lbl_badge.setText(status.upper())
        self.lbl_badge.setStyleSheet(f"""
            background: #161b22;
            color: {'#f78166' if is_net_blocked else '#3fb950'};
            font-size: 10px; font-weight: 700; letter-spacing: 1px;
            border: 1px solid {'#f78166' if is_net_blocked else '#238636'};
            border-radius: 4px; padding: 2px 8px;
        """)

    def _mark_step(self, step_widget: QFrame, done: bool):
        """Update the workflow step indicator color."""
        for child in step_widget.findChildren(QLabel):
            text = child.text()
            # Number label (e.g. "01")
            if text.isdigit() or (len(text) == 2 and text.isdigit()):
                child.setStyleSheet(
                    f"color: {'#3fb950' if done else '#484f58'}; font-size: 11px;"
                    "font-weight: 700; background: transparent; border: none;"
                )
            else:
                child.setStyleSheet(
                    f"color: {'#c9d1d9' if done else '#6e7681'}; font-size: 12px;"
                    "background: transparent; border: none;"
                )
        step_widget.setStyleSheet(
            f"background: {'#0f2414' if done else '#0d1117'};"
            f"border: 1px solid {'#238636' if done else '#21262d'};"
            "border-radius: 8px;"
        )

    def update_verdict(self):
        v = self.verdict_engine.calculate(self.static_score, self.dynamic_score, 0, [])

        level_display = {
            ThreatLevel.BENIGN:     ("BENIGN",    "#3fb950", 10),
            ThreatLevel.SUSPICIOUS: ("SUSPICIOUS", "#d29922", 50),
            ThreatLevel.MALICIOUS:  ("MALICIOUS",  "#f78166", 80),
            ThreatLevel.CRITICAL:   ("CRITICAL",   "#ff4444", 100),
        }
        label, color, bar_val = level_display.get(v.level, ("UNKNOWN", "#58a6ff", 0))
        self.card_verdict.set_value(0, label)
        self.card_verdict.bar.setValue(bar_val)
        self.card_verdict.set_accent(color)
        self.card_verdict.lbl_value.setStyleSheet(
            f"color: {color}; font-size: 28px; font-weight: 800;"
            "background: transparent; border: none;"
        )

        self.txt_explanation.setText(
            "\n".join(v.explanation) if v.explanation else "No significant threats detected yet."
        )
        return v

    def _set_score_color(self, card: ThreatMeter, score: int):
        if score >= 70:
            card.set_accent("#f78166")
        elif score >= 40:
            card.set_accent("#d29922")
        else:
            card.set_accent("#3fb950")

    # ── Persistence & Settings ──────────────────────────────────────

    def _save_settings(self):
        """Persist all UI settings to config.json."""
        config_path = os.path.join(os.getcwd(), "config.json")
        settings = {
            "vt_api_key":      self.txt_vt_key.text(),
            "openai_api_key":  self.txt_ml_key.text(),
            "enable_memory":   self.chk_memory.isChecked(),
            "enable_registry": self.chk_registry.isChecked(),
            "block_network":   self.chk_network.isChecked(),
            "timeout_sec":     self.spin_timeout.value(),
            "auto_pdf":        self.chk_auto_pdf.isChecked(),
            "auto_kill":       self.chk_auto_kill.isChecked(),
            "block_clipboard": self.chk_clip.isChecked(),
            "deploy_decoys":   self.chk_decoy.isChecked(),
        }
        
        try:
            with open(config_path, "w") as f:
                json.dump(settings, f, indent=4)
            QMessageBox.information(self, "Success", "Preferences saved successfully.")
            self.update_policy() # Refresh in-memory isolation config
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e}")

    def _load_settings(self):
        """Restore all UI settings from config.json."""
        config_path = os.path.join(os.getcwd(), "config.json")
        if not os.path.exists(config_path):
            return

        try:
            with open(config_path, "r") as f:
                s = json.load(f)
            
            # API Keys
            vt_key = s.get("vt_api_key", "")
            if not vt_key:
                vt_key = "06d26a2030844f43c54924c2d222c789" # User provided key
            self.txt_vt_key.setText(vt_key)
            self.txt_ml_key.setText(s.get("openai_api_key", ""))
            
            # Engine Policies
            self.chk_memory.setChecked(s.get("enable_memory", True))
            self.chk_registry.setChecked(s.get("enable_registry", True))
            self.chk_network.setChecked(s.get("block_network", False))
            self.spin_timeout.setValue(s.get("timeout_sec", 15))
            
            # Automation
            self.chk_auto_pdf.setChecked(s.get("auto_pdf", False))
            self.chk_auto_kill.setChecked(s.get("auto_kill", True))
            
            # Additional Defense
            self.chk_clip.setChecked(s.get("block_clipboard", True))
            self.chk_decoy.setChecked(s.get("deploy_decoys", False))
            
            # Ensure chk_net (on defense page) matches chk_network
            self.chk_net.setChecked(self.chk_network.isChecked())
            
            self.update_policy()
        except Exception as e:
            print(f"[!] Critical: Failed to load settings: {e}")
