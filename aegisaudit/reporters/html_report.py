from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from aegisaudit.models import ScanResult
from aegisaudit.history import ScanHistory
import json
from jinja2 import Template

def generate_html_report(result: ScanResult, output_path: Path):
    """Generate a user-friendly HTML report using Jinja2."""
    template_path = Path(__file__).parent.parent.parent / "templates" / "report.html.j2"
    
    with open(template_path) as f:
        template = Template(f.read())
    
    # Fetch recent history for the chart
    history_db = ScanHistory()
    # Get last 10 scans for context
    history_rows = history_db.get_history(limit=10)
    # Reverse so it's chronological (Trend line needs Left->Right as Old->New)
    history_data = sorted(history_rows, key=lambda x: x['id']) 
    
    html_content = template.render(
        result=result,
        title=f"AegisAudit Report - {result.targets[0] if result.targets else 'Scan'}",
        summary=result.summary,
        findings=result.findings,
        history=history_data
    )
    
    with open(output_path, "w") as f:
        f.write(html_content)
