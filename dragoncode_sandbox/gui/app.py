import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPalette, QColor, QFont
from PySide6.QtCore import Qt

from .main_window import MainWindow


def run_gui():
    app = QApplication(sys.argv)

    # Force Fusion style as base
    app.setStyle("Fusion")

    # ── Deep Obsidian Palette ──────────────────────────────────
    palette = QPalette()

    bg_deep   = QColor(10, 13, 20)      # #0a0d14
    bg_dark   = QColor(13, 17, 23)      # #0d1117
    bg_mid    = QColor(22, 27, 34)      # #161b22
    bg_light  = QColor(33, 38, 45)      # #21262d
    accent    = QColor(88, 166, 255)    # #58a6ff
    text_main = QColor(230, 237, 243)   # #e6edf3
    text_dim  = QColor(139, 148, 158)   # #8b949e
    green     = QColor(63, 185, 80)     # #3fb950

    palette.setColor(QPalette.Window,          bg_deep)
    palette.setColor(QPalette.WindowText,      text_main)
    palette.setColor(QPalette.Base,            bg_dark)
    palette.setColor(QPalette.AlternateBase,   bg_mid)
    palette.setColor(QPalette.ToolTipBase,     bg_mid)
    palette.setColor(QPalette.ToolTipText,     text_main)
    palette.setColor(QPalette.Text,            text_main)
    palette.setColor(QPalette.Button,          bg_mid)
    palette.setColor(QPalette.ButtonText,      text_main)
    palette.setColor(QPalette.BrightText,      QColor(255, 68, 68))
    palette.setColor(QPalette.Link,            accent)
    palette.setColor(QPalette.LinkVisited,     QColor(139, 92, 246))
    palette.setColor(QPalette.Highlight,       accent)
    palette.setColor(QPalette.HighlightedText, bg_deep)

    # Disabled states
    palette.setColor(QPalette.Disabled, QPalette.WindowText, text_dim)
    palette.setColor(QPalette.Disabled, QPalette.Text,       text_dim)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, text_dim)
    palette.setColor(QPalette.Disabled, QPalette.Highlight,  bg_light)

    app.setPalette(palette)

    # ── Global Font ───────────────────────────────────────────
    font = QFont("Segoe UI", 10)
    app.setFont(font)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()
