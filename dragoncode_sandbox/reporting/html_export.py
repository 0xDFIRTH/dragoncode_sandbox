import tempfile
import webbrowser
from pathlib import Path
from datetime import datetime

class ReportExporter:
    @staticmethod
    def export_html(file_name: str, verdict: dict, static_info: dict, dynamic_events: list, dest_path: str = None):
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>DragonCode Sandbox Report - {file_name}</title>
            <style>
                body {{ font-family: 'Segoe UI', system-ui, sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 0; padding: 40px; }}
                h1 {{ color: #e6edf3; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
                h2 {{ color: #58a6ff; margin-top: 30px; }}
                .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
                .verdict-High {{ color: #ff4444; font-weight: bold; }}
                .verdict-Medium {{ color: #d29922; font-weight: bold; }}
                .verdict-Low {{ color: #3fb950; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #21262d; }}
                th {{ background: #21262d; color: #8b949e; }}
                .event-CRITICAL {{ color: #ff4444; }}
                .event-HIGH {{ color: #f78166; }}
                .event-MEDIUM {{ color: #d29922; }}
                .event-LOW {{ color: #3fb950; }}
            </style>
        </head>
        <body>
            <h1>🐉 DragonCode Advanced Threat Report</h1>
            <p><strong>Target File:</strong> {file_name}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="card">
                <h2>Analysis Verdict</h2>
                <p><strong>Static Analysis Score:</strong> {verdict.get('static_score', 0)} / 100</p>
                <p><strong>Dynamic Execution Score:</strong> {verdict.get('dynamic_score', 0)} / 100</p>
                <p><strong>Analysis Verdict (Avg):</strong> {verdict.get('score', 0)} / 100</p>
                <p><strong>Assessment:</strong> <span class="verdict-{verdict.get('level', 'Low').replace(' (Safe)','').replace(' (Moderate)','').replace(' (Critical)','')}">{verdict.get('label', 'Unknown')}</span></p>
            </div>
            <div class="card">
                <h2>Static Analysis Highlights</h2>
                <p><strong>MD5:</strong> {static_info.get('md5', 'N/A')}</p>
                <p><strong>SHA256:</strong> {static_info.get('sha256', 'N/A')}</p>
                <p><strong>Signature Trust:</strong> {static_info.get('signature', 'Unsigned')}</p>
            </div>
            
            <div class="card">
                <h2>Behavioral Events ({len(dynamic_events)})</h2>
                <table>
                    <tr><th>Time</th><th>Category</th><th>Severity</th><th>Event</th></tr>
        """
        for ev in dynamic_events:
            html += f"""
                    <tr>
                        <td>{ev.get('time', '-')}</td>
                        <td>{ev.get('category', '-')}</td>
                        <td class="event-{ev.get('severity', 'LOW')}">{ev.get('severity', '-')}</td>
                        <td>{ev.get('title', '-')}</td>
                    </tr>
            """
        html += """
                </table>
            </div>
        </body>
        </html>
        """
        
        path = dest_path or Path(tempfile.gettempdir()) / f"dragoncode_report_{datetime.now().strftime('%H%M%S')}.html"
        Path(path).write_text(html, encoding='utf-8')
        if not dest_path:
            webbrowser.open(f"file://{path}")
        return str(path)
