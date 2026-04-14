from PySide6.QtWidgets import QWidget
from PySide6.QtGui import QPainter, QColor, QPolygonF, QPen, QBrush, QFont, QLinearGradient
from PySide6.QtCore import Qt, QPointF
import math

class ThreatRadarChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(250, 250)
        self.labels = ["Static", "Dynamic", "Network", "Registry", "Behavior"]
        self.scores = [0, 0, 0, 0, 0]  # Values 0-100
        
    def set_scores(self, static, dynamic, network, registry, behavior):
        self.scores = [static, dynamic, network, registry, behavior]
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Geometry
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        radius = min(w, h) / 2 * 0.70
        
        num_axes = len(self.labels)
        angle_step = 2 * math.pi / num_axes
        
        # Draw web rings
        painter.setPen(QPen(QColor("#30363d"), 1, Qt.DashLine))
        for level in range(1, 5):
            r = radius * (level / 4.0)
            poly = QPolygonF()
            for i in range(num_axes):
                angle = i * angle_step - math.pi / 2
                x = cx + r * math.cos(angle)
                y = cy + r * math.sin(angle)
                poly.append(QPointF(x, y))
            painter.drawPolygon(poly)
            
        # Draw axes & labels
        painter.setPen(QPen(QColor("#484f58"), 1))
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        for i in range(num_axes):
            angle = i * angle_step - math.pi / 2
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            painter.drawLine(QPointF(cx, cy), QPointF(x, y))
            
            # Label
            lx = cx + (radius + 20) * math.cos(angle)
            ly = cy + (radius + 20) * math.sin(angle)
            
            align = Qt.AlignCenter
            if math.cos(angle) > 0.1: align = Qt.AlignLeft | Qt.AlignVCenter
            elif math.cos(angle) < -0.1: align = Qt.AlignRight | Qt.AlignVCenter
            
            rect_w, rect_h = 80, 20
            painter.setPen(QPen(QColor("#8b949e"), 1))
            painter.drawText(int(lx - rect_w/2), int(ly - rect_h/2), rect_w, rect_h, align, self.labels[i])
            
        # Draw data polygon
        poly_data = QPolygonF()
        for i in range(num_axes):
            angle = i * angle_step - math.pi / 2
            # Clamp value
            val = max(0, min(100, self.scores[i]))
            r = radius * (val / 100.0)
            x = cx + r * math.cos(angle)
            y = cy + r * math.sin(angle)
            poly_data.append(QPointF(x, y))
            
        # Fill
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor(247, 129, 102, 100))  # Light red/orange
        grad.setColorAt(1, QColor(255, 68, 68, 40))
        
        painter.setBrush(QBrush(grad))
        painter.setPen(QPen(QColor("#f78166"), 2, Qt.SolidLine))
        painter.drawPolygon(poly_data)
        
        # Dots
        painter.setBrush(QBrush(QColor("#f78166")))
        for i_pt in range(poly_data.count()):
            pt = poly_data.at(i_pt)
            painter.drawEllipse(pt, 3, 3)
