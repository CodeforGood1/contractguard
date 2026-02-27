"""ContractGuard CLI — powered by Typer.

Usage:
    contractguard analyze --type json --path samples/json/
    contractguard analyze --type sql  --path samples/sql/ --report report.html
    contractguard analyze --type secrets --path .
    contractguard analyze --type all --path . --report full-report.html
    contractguard score --path .
    contractguard history
    contractguard watch --path . --type all
    contractguard serve
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from contractguard import __version__
from contractguard.engine import Finding, Severity

app = typer.Typer(
    name="contractguard",
    help="🛡️ ContractGuard — Stop bad inputs before they break your systems.",
    add_completion=False,
)
console = Console()

_RULES_DIR_DEFAULT = Path(__file__).resolve().parent.parent.parent / "rules"

_ANALYZER_TYPES = [
    "json", "sql", "regex", "secrets", "pii", "csv", "config", "dockerfile", "deps", "all",
]


def _resolve_rules_dir(rules_dir: Path | None) -> Path:
    """Find the rules directory — check common locations."""
    if rules_dir and rules_dir.exists():
        return rules_dir
    cwd_rules = Path.cwd() / "rules"
    if cwd_rules.exists():
        return cwd_rules
    if _RULES_DIR_DEFAULT.exists():
        return _RULES_DIR_DEFAULT
    console.print("[red]Error:[/red] Cannot find rules/ directory. Use --rules-dir.")
    raise typer.Exit(1)


def _severity_color(sev: Severity) -> str:
    return {
        "info": "blue", "warning": "yellow", "critical": "red", "block": "bright_red",
    }.get(sev.value, "white")


def _run_analyzer(analyzer_type: str, path: Path, rules_path: Path, db: str | None = None) -> list[Finding]:
    """Run a single analyzer type and return findings."""
    if analyzer_type == "json":
        from contractguard.analyzers.json_analyzer import analyze as fn
        return fn(path, rules_path)
    elif analyzer_type == "sql":
        from contractguard.analyzers.sql_analyzer import analyze as fn
        return fn(path, rules_path, db_path=db)
    elif analyzer_type == "regex":
        from contractguard.analyzers.regex_analyzer import analyze as fn
        return fn(path, rules_path)
    elif analyzer_type == "secrets":
        from contractguard.analyzers.secrets_analyzer import analyze as fn
        return fn(path, rules_path)
    elif analyzer_type == "pii":
        from contractguard.analyzers.pii_analyzer import analyze as fn
        return fn(path, rules_path)
    elif analyzer_type == "csv":
        from contractguard.analyzers.csv_analyzer import analyze as fn
        return fn(path, rules_path)
    elif analyzer_type == "config":
        from contractguard.analyzers.config_analyzer import analyze as fn
        return fn(path, rules_path)
    elif analyzer_type == "dockerfile":
        from contractguard.analyzers.dockerfile_analyzer import analyze as fn
        return fn(path, rules_path)
    elif analyzer_type == "deps":
        from contractguard.analyzers.dependency_analyzer import analyze as fn
        return fn(path, rules_path)
    return []


def _run_all_analyzers(path: Path, rules_path: Path) -> list[Finding]:
    """Run ALL analyzers and aggregate findings."""
    all_findings: list[Finding] = []
    for atype in _ANALYZER_TYPES:
        if atype == "all":
            continue
        try:
            findings = _run_analyzer(atype, path, rules_path)
            all_findings.extend(findings)
        except Exception as e:
            console.print(f"[dim]Analyzer '{atype}' skipped: {e}[/dim]")
    return all_findings


def _print_findings(findings: list[Finding], ci_mode: bool = False) -> None:
    """Print findings to the console using rich tables."""
    if not findings:
        console.print("[green]✓ No issues found.[/green]")
        return

    table = Table(title="🛡️ ContractGuard Findings", show_lines=True)
    table.add_column("ID", style="bold")
    table.add_column("Severity")
    table.add_column("Description", max_width=50)
    table.add_column("Location", max_width=40)
    table.add_column("Suggestion", max_width=50)

    for f in findings:
        color = _severity_color(f.severity)
        sev_label = f.severity.value.upper()
        if f.severity == Severity.BLOCK:
            sev_label = "🚫 BLOCK"
        table.add_row(
            f.rule_id,
            f"[{color}]{sev_label}[/{color}]",
            f.description,
            f.location,
            f.suggestion,
        )

    console.print(table)

    blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
    crits = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    warns = sum(1 for f in findings if f.severity == Severity.WARNING)
    infos = sum(1 for f in findings if f.severity == Severity.INFO)
    console.print(
        f"\n[bold]Summary:[/bold] {len(findings)} finding(s) — "
        f"[bright_red]{blocks} block[/bright_red], "
        f"[red]{crits} critical[/red], [yellow]{warns} warning[/yellow], [blue]{infos} info[/blue]"
    )

    if ci_mode and (blocks > 0 or crits > 0):
        console.print("[red bold]CI mode: failing due to critical/block findings.[/red bold]")
        raise typer.Exit(2)


def _print_score(findings: list[Finding]) -> None:
    """Print the security score summary."""
    from contractguard.scorer import compute_score

    score = compute_score(findings)
    grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bright_red"}
    color = grade_colors.get(score.grade, "white")

    console.print()
    console.print(Panel(
        f"[{color} bold]  Grade: {score.grade}  |  Score: {score.score}/100  [/{color} bold]\n\n"
        f"  {score.risk_summary}\n\n"
        f"  Findings: {score.total_findings} total — "
        f"[bright_red]{score.block_count} BLOCK[/bright_red], "
        f"[red]{score.critical_count} CRITICAL[/red], "
        f"[yellow]{score.warning_count} WARNING[/yellow], "
        f"[blue]{score.info_count} INFO[/blue]"
        + (f"\n\n  [bold]Attack Surface:[/bold] {', '.join(score.attack_surface[:5])}" if score.attack_surface else "")
        + (f"\n\n  [bold]Top Risks:[/bold]\n" + "\n".join(f"    • {r}" for r in score.top_risks) if score.top_risks else ""),
        title="🛡️ ContractGuard Security Score",
        border_style=color,
    ))


@app.command()
def analyze(
    type: str = typer.Option(..., "--type", "-t", help=f"Analyzer type: {', '.join(_ANALYZER_TYPES)}"),
    path: Path = typer.Option(..., "--path", "-p", help="File or directory to analyze"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", "-r", help="Path to rules/ directory"),
    report: Optional[Path] = typer.Option(None, "--report", help="Write HTML report to this path"),
    report_json: Optional[Path] = typer.Option(None, "--report-json", help="Write JSON report"),
    report_sarif: Optional[Path] = typer.Option(None, "--report-sarif", help="Write SARIF report (GitHub Code Scanning)"),
    db: Optional[str] = typer.Option(None, "--db", help="SQLite DB path for EXPLAIN mode (sql only)"),
    ci: bool = typer.Option(False, "--ci", help="CI mode: exit code 2 on critical/block findings"),
    show_score: bool = typer.Option(False, "--score", help="Show security grade after analysis"),
    record: bool = typer.Option(False, "--record", help="Record scan to history database"),
) -> None:
    """Analyze inputs and flag reliability/safety issues."""
    rules_path = _resolve_rules_dir(rules_dir)

    if not path.exists():
        console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(1)

    if type not in _ANALYZER_TYPES:
        console.print(f"[red]Error:[/red] Unknown type '{type}'. Use: {', '.join(_ANALYZER_TYPES)}")
        raise typer.Exit(1)

    if type == "all":
        findings = _run_all_analyzers(path, rules_path)
    else:
        findings = _run_analyzer(type, path, rules_path, db=db)

    _print_findings(findings, ci_mode=ci)

    if show_score or type == "all":
        _print_score(findings)

    if record:
        from contractguard.history import record_scan
        score = record_scan(findings, analyzer=type, source_path=str(path))
        console.print(f"[dim]Scan recorded. Grade: {score.grade} ({score.score}/100)[/dim]")

    if report:
        from contractguard.reporter import render_html_report
        html = render_html_report(findings, analyzer_type=type, source_path=str(path))
        report.write_text(html, encoding="utf-8")
        console.print(f"[green]HTML report written to {report}[/green]")

    if report_json:
        data = [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "description": f.description,
                "explanation": f.explanation,
                "suggestion": f.suggestion,
                "location": f.location,
                "context": f.context,
                "attack_vector": f.attack_vector,
                "cwe": f.cwe,
            }
            for f in findings
        ]
        report_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[green]JSON report written to {report_json}[/green]")

    if report_sarif:
        from contractguard.reporter import render_sarif_report
        sarif = render_sarif_report(findings, analyzer_type=type)
        report_sarif.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        console.print(f"[green]SARIF report written to {report_sarif}[/green]")


@app.command()
def score(
    path: Path = typer.Option(".", "--path", "-p", help="Project root to scan"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", "-r"),
) -> None:
    """Run all analyzers and display overall security grade."""
    rules_path = _resolve_rules_dir(rules_dir)
    if not path.exists():
        console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(1)

    console.print("[bold]Running full security scan...[/bold]")
    findings = _run_all_analyzers(path, rules_path)
    _print_score(findings)


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of scans to show"),
    db_path: Optional[Path] = typer.Option(None, "--db", help="History database path"),
) -> None:
    """Show scan history and trend analysis."""
    from contractguard.history import get_history, get_trend

    records = get_history(limit=limit, db_path=db_path)
    if not records:
        console.print("[yellow]No scan history found. Use --record with analyze to track scans.[/yellow]")
        return

    table = Table(title="Scan History", show_lines=True)
    table.add_column("Date", style="dim")
    table.add_column("Analyzer")
    table.add_column("Grade", style="bold")
    table.add_column("Score")
    table.add_column("Findings")
    table.add_column("Source", max_width=40)

    for r in records:
        grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bright_red"}
        color = grade_colors.get(r["grade"], "white")
        table.add_row(
            r["timestamp"][:19],
            r["analyzer"],
            f"[{color}]{r['grade']}[/{color}]",
            str(r["score"]),
            str(r["total_findings"]),
            r["source_path"],
        )
    console.print(table)

    trend = get_trend(db_path=db_path)
    if trend["trend"] != "no_data":
        trend_icons = {"improving": "📈", "degrading": "📉", "stable": "➡️"}
        icon = trend_icons.get(trend["trend"], "")
        console.print(f"\n[bold]Trend:[/bold] {icon} {trend['trend'].upper()} — Latest: {trend['latest_grade']} ({trend['latest_score']}/100)")


@app.command()
def watch(
    path: Path = typer.Option(".", "--path", "-p", help="Directory to watch"),
    type: str = typer.Option("all", "--type", "-t", help="Analyzer type to run"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", "-r"),
    interval: int = typer.Option(3, "--interval", help="Seconds between scans"),
) -> None:
    """Watch files and re-run analysis on changes."""
    rules_path = _resolve_rules_dir(rules_dir)
    if not path.exists():
        console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(1)

    console.print(f"[bold]Watching {path} (every {interval}s). Press Ctrl+C to stop.[/bold]")

    last_mtimes: dict[str, float] = {}

    def _get_mtimes() -> dict[str, float]:
        mtimes: dict[str, float] = {}
        target = path if path.is_dir() else path.parent
        for f in target.rglob("*"):
            if f.is_file() and not any(p.startswith(".") for p in f.parts):
                try:
                    mtimes[str(f)] = f.stat().st_mtime
                except OSError:
                    pass
        return mtimes

    last_mtimes = _get_mtimes()

    try:
        while True:
            time.sleep(interval)
            current = _get_mtimes()
            changed = {k for k in current if current.get(k) != last_mtimes.get(k)}
            new_files = set(current) - set(last_mtimes)

            if changed or new_files:
                console.print(f"\n[yellow]Change detected ({len(changed | new_files)} file(s)). Re-scanning...[/yellow]")
                if type == "all":
                    findings = _run_all_analyzers(path, rules_path)
                else:
                    findings = _run_analyzer(type, path, rules_path)
                _print_findings(findings)
                _print_score(findings)
                last_mtimes = current
    except KeyboardInterrupt:
        console.print("\n[dim]Watch stopped.[/dim]")


@app.command()
def version() -> None:
    """Print the version number."""
    console.print(f"ContractGuard v{__version__}")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Host to bind to"),
    port: int = typer.Option(8000, help="Port to bind to"),
) -> None:
    """Launch the ContractGuard web UI."""
    console.print(f"[bold]Starting ContractGuard web UI on http://{host}:{port}[/bold]")
    import uvicorn
    from contractguard.web import create_app
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    app()
