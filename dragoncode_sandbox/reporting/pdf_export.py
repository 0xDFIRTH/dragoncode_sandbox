import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
from pathlib import Path

class PDFExporter:
    @staticmethod
    def export_pdf(file_name: str, verdict: dict, static_info: dict, dynamic_events: list, dest_path: str):
        doc = SimpleDocTemplate(dest_path, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=40, bottomMargin=30)
        elements = []
        styles = getSampleStyleSheet()
        
        # Override Normal style
        styles['Normal'].fontName = 'Helvetica'
        styles['Normal'].fontSize = 10
        
        # Title
        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, spaceAfter=20, textColor=colors.darkblue)
        elements.append(Paragraph(f"DragonCode Analysis Report", title_style))
        elements.append(Paragraph(f"<b>Target File:</b> {file_name}", styles['Normal']))
        elements.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Verdict Section
        elements.append(Paragraph("Analysis Verdict", styles['Heading2']))
        v_level = verdict.get('level', 'Unknown')
        
        # Color mapping for the explicit ruleset
        if "Critical" in v_level:
            v_color = colors.red
        elif "Moderate" in v_level:
            v_color = colors.orange
        else:
            v_color = colors.green
        
        v_data = [
            ["Static Analysis Score:", f"{verdict.get('static_score', 0)} / 100"],
            ["Dynamic Execution Score:  ", f"{verdict.get('dynamic_score', 0)} / 100"],
            ["Analysis Verdict (Avg):", f"{verdict.get('score', 0)} / 100"],
            ["Assessment Level:", v_level]
        ]
        t = Table(v_data, colWidths=[120, 400])
        t.setStyle(TableStyle([
            ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (1, 1), (1, 1), v_color),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))
        
        # Static Info Section
        elements.append(Paragraph("Static Analysis Summary", styles['Heading2']))
        s_data = [
            ["MD5 Hash:", static_info.get('md5', 'N/A')],
            ["SHA256 Hash:", static_info.get('sha256', 'N/A')],
            ["Signature Trust:", static_info.get('signature', 'Unsigned')]
        ]
        t2 = Table(s_data, colWidths=[120, 400])
        t2.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Courier'),
            ('FONTSIZE', (1, 0), (1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t2)
        elements.append(Spacer(1, 20))
        
        # Events Table
        if dynamic_events:
            elements.append(Paragraph(f"Behavioral Events ({len(dynamic_events)})", styles['Heading2']))
            # Header
            ev_data = [["Time", "Category", "Severity", "Event Description"]]
            for ev in dynamic_events:
                # Wrap long text using Paragraph
                title_cell = Paragraph(ev.get('title', '-'), styles['Normal'])
                ev_data.append([
                    ev.get('time', '-'), 
                    ev.get('category', '-'), 
                    ev.get('severity', '-'), 
                    title_cell
                ])
                
            t3 = Table(ev_data, colWidths=[60, 80, 70, 310])
            t3.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey)
            ]))
            elements.append(t3)
            
        doc.build(elements)
        return dest_path
