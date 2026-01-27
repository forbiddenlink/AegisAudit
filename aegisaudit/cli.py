import typer
import asyncio
from pathlib import Path
from typing import List, Optional
from rich.console import Console
from rich.table import Table

from aegisaudit.config import load_config, AegisConfig
from aegisaudit.fetcher import Fetcher
from aegisaudit.models import ScanResult

app = typer.Typer(help="AegisAudit - Security posture reports for modern web apps.")
console = Console()

@app.callback()
def main():
    """
    AegisAudit security auditor.
    """


from aegisaudit.runner import Runner
from aegisaudit.reporters import generate_json_report, generate_sarif_report, generate_html_report

from aegisaudit.history import ScanHistory
from aegisaudit.notifications import send_webhook
from datetime import datetime

# ... (Previous run_scan implementation) ...
# We need to inject history saving into run_scan or call it after?
# Let's modify run_scan to take a history obj or do it inside.

async def run_scan(urls: List[str], config: AegisConfig, output_dir: Path, output_format: List[str], save_history: bool = True, webhook: str = None):
    # ... (Fetcher logic) ...
    # Re-implementing simplified version to show the insertion point
    # Realistically I should edit the existing function carefully.
    
    # Let's use the replacement to just *Patch* run_scan to include history saving.
    # But for cleaner code, I will fully update run_scan here.
    
    console.print(f"[bold green]Starting scan against {len(urls)} targets...[/bold green]")
    fetcher = Fetcher(config)
    artifacts = []
    
    try:
        for url in urls:
            console.print(f"Fetching {url}...")
            artifact = await fetcher.fetch(url)
            if artifact:
                artifacts.append(artifact)
                console.print(f"  [green]✓[/green] {artifact.status_code} {artifact.final_url}")
            else:
                console.print(f"  [red]✗[/red] Failed to fetch")
    finally:
        await fetcher.close()

    if artifacts:
        console.print(f"\n[bold]Running checks on {len(artifacts)} artifacts...[/bold]")
        runner = Runner(config)
        result = runner.run_checks(artifacts)
        result.finished_at = datetime.now()
        
        # Display Summary
        console.print("\n[bold]Scan Summary:[/bold]")
        console.print(f"Overall Score: [bold cyan]{result.summary.overall_score:.1f}[/bold cyan] / 100")
        
        # Display Findings
        if result.findings:
            table = Table(title="Security Findings")
            table.add_column("Severity", style="bold")
            table.add_column("Finding", style="white")
            table.add_column("URL", style="cyan")
            
            for finding in result.findings:
                color = "green"
                if finding.severity == "high": color = "red"
                elif finding.severity == "medium": color = "yellow"
                elif finding.severity == "low": color = "blue"
                
                table.add_row(
                    f"[{color}]{finding.severity.upper()}[/{color}]",
                    finding.title,
                    finding.url
                )
            console.print(table)
        else:
            console.print("[green]No issues found![/green]")

        # Generate Reports
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if "json" in output_format or "all" in output_format:
            json_path = output_dir / "report.json"
            generate_json_report(result, json_path)
            console.print(f"JSON Report: [link=file://{json_path}]{json_path}[/link]")
            
        if "sarif" in output_format or "all" in output_format:
            sarif_path = output_dir / "report.sarif"
            generate_sarif_report(result, sarif_path)
            console.print(f"SARIF Report: [link=file://{sarif_path}]{sarif_path}[/link]")

        if "html" in output_format or "all" in output_format:
            html_path = output_dir / "report.html"
            generate_html_report(result, html_path)
            console.print(f"HTML Report: [link=file://{html_path}]{html_path}[/link]")
            
        # Save History
            history = ScanHistory()
            history.add_scan(result)
            console.print("[dim]Scan saved to history.[/dim]")

        if webhook:
            send_webhook(webhook, result)
            console.print("[dim]Sent webhook notification.[/dim]")

from aegisaudit.sast.scanner import SASTScanner
from aegisaudit.models import ScanResult, ScanSummary, Severity

@app.command()
def audit(
    directory: Path = typer.Argument(..., help="Directory to audit", exists=True, file_okay=False, dir_okay=True),
    out: Path = typer.Option(Path("./aegis-audit"), "--out", help="Output directory"),
    format: List[str] = typer.Option(["all"], "--format", help="Output formats: json, html, sarif, all"),
):
    """
    Run a static analysis (SAST) audit on a local directory.
    Checks for secrets, dependency vulnerabilities, and insecure code patterns.
    """
    console.print(f"[bold green]Starting audit of {directory}...[/bold green]")
    
    scanner = SASTScanner(directory)
    findings = scanner.scan()
    
    # Calculate summary
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
        
    summary = ScanSummary(
        counts_by_severity=counts,
        overall_score=100.0 - (counts[Severity.HIGH] * 10) - (counts[Severity.MEDIUM] * 2) # SAST Scoring logic
    )

    result = ScanResult(
        targets=[str(directory)],
        findings=findings,
        summary=summary,
        started_at=datetime.now(),
        finished_at=datetime.now()
    )

    # Display Summary
    console.print(f"\n[bold]Audit Complete found {len(findings)} issues.[/bold]")
    if findings:
        table = Table(title="Audit Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Type", style="white")
        table.add_column("Location", style="cyan")
        
        for f in findings:
            color = "green"
            if f.severity == Severity.HIGH: color = "red"
            elif f.severity == Severity.MEDIUM: color = "yellow"
            elif f.severity == Severity.LOW: color = "blue"
            
            # Truncate evidence/location for CLI
            loc = f.evidence if f.evidence else f.url
            if len(loc) > 60: loc = loc[:57] + "..."
            
            table.add_row(
                f"[{color}]{f.severity.upper()}[/{color}]",
                f.title,
                loc
            )
        console.print(table)
    else:
        console.print("[green]No issues found![/green]")

    # Generate Reports
    out.mkdir(parents=True, exist_ok=True)
    if "html" in format or "all" in format:
        html_path = out / "audit_report.html"
        generate_html_report(result, html_path)
        console.print(f"HTML Report: [link=file://{html_path}]{html_path}[/link]")
    
    # Can reuse other reporters too




@app.command()
def scan(
    urls: Optional[List[str]] = typer.Option(None, "--url", help="Single URL to scan (can be repeated)"),
    file: Optional[Path] = typer.Option(None, "--file", help="File containing URLs to scan"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to aegis.yml config file"),
    out: Path = typer.Option(Path("./aegis-report"), "--out", help="Output directory"),
    format: List[str] = typer.Option(["all"], "--format", help="Output formats: json, html, sarif, all"),
    probe: bool = typer.Option(False, "--probe", help="Actively probe for sensitive files (.env, .git)"),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="Slack/Discord webhook URL for alerts"),
):
    """
    Run a security posture scan against target URLs.
    """
    config = load_config(config_file)
    target_urls = []

    if urls:
        target_urls.extend(urls)
    
    if file and file.exists():
        with open(file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
            target_urls.extend(lines)

    if not target_urls:
        console.print("[red]No targets specified if strict mode enabled.[/red] Provide --url or --file.")
        raise typer.Exit(code=1)

    # Probing Logic: Expand targets
    if probe:
        expanded_urls = []
        for url in target_urls:
            expanded_urls.append(url) # Keep original
            # Remove trailing slash for appending
            base = url.rstrip("/")
            expanded_urls.append(f"{base}/.env")
            expanded_urls.append(f"{base}/.git/HEAD")
            # We could add more here (wp-config, etc.)
        target_urls = expanded_urls
        console.print(f"[yellow]Probing enabled. Target list expanded to {len(target_urls)} URLs.[/yellow]")

    asyncio.run(run_scan(target_urls, config, output_dir=out, output_format=format, save_history=True, webhook=webhook))


if __name__ == "__main__":
    app()
