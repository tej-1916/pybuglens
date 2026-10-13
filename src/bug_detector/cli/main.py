"""Command-line interface for the AI-Powered Bug Detection System."""

import sys
from pathlib import Path
from typing import Optional

import click

from bug_detector.analyzers.engine import AnalysisEngine
from bug_detector.core.config import get_settings
from bug_detector.core.models import AnalysisRequest, Severity
from bug_detector.storage.database import DatabaseManager
from bug_detector.storage.repository import ReviewRepository


@click.group()
@click.version_option(version="0.1.0", prog_name="bug-detector")
def cli() -> None:
    """AI-Powered Bug Detection System CLI."""


@cli.command("analyze")
@click.argument("file_path", type=click.Path(exists=False, readable=True))
@click.option(
    "--json-output",
    "--json",
    is_flag=True,
    default=False,
    help="Output complete analysis results in raw JSON format.",
)
@click.option(
    "--ai",
    "--enable-ai",
    is_flag=True,
    default=False,
    help="Request optional OpenAI AI review (requires OPENAI_API_KEY).",
)
@click.option(
    "--no-save",
    is_flag=True,
    default=False,
    help="Do not persist review results to the local SQLite database.",
)
def analyze(file_path: str, json_output: bool, ai: bool, no_save: bool) -> None:
    """Analyze a Python source file for bugs and security vulnerabilities.

    Exit Codes:
      0 = Clean code (Valid syntax, zero bug findings)
      1 = Issues detected (Static bug findings present)
      2 = Syntax error, invalid input, or file access error
    """
    target = Path(file_path)
    if not target.is_file():
        err_msg = f"Error: File '{file_path}' does not exist or is not a regular file."
        click.echo(click.style(err_msg, fg="red"), err=True)
        sys.exit(2)

    settings = get_settings()

    # Size check
    try:
        file_size = target.stat().st_size
    except OSError as err:
        click.echo(click.style(f"Error reading file metadata: {err}", fg="red"), err=True)
        sys.exit(2)

    if file_size > settings.max_code_size_bytes:
        click.echo(
            click.style(
                f"Error: File size ({file_size} bytes) exceeds maximum "
                f"allowed limit ({settings.max_code_size_bytes} bytes).",
                fg="red",
            ),
            err=True,
        )
        sys.exit(2)

    try:
        source_code = target.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        click.echo(
            click.style(f"Error: File '{file_path}' contains non-UTF-8 characters.", fg="red"),
            err=True,
        )
        sys.exit(2)
    except OSError as err:
        click.echo(click.style(f"Error reading file content: {err}", fg="red"), err=True)
        sys.exit(2)

    if not source_code.strip():
        click.echo(
            click.style("Error: Source file cannot be empty or purely whitespace.", fg="red"),
            err=True,
        )
        sys.exit(2)

    # Initialize Engine & Repository
    repo: Optional[ReviewRepository] = None
    if not no_save:
        try:
            db = DatabaseManager(settings.database_url)
            repo = ReviewRepository(db)
        except Exception:
            repo = None

    engine = AnalysisEngine(repository=repo, settings=settings)
    request = AnalysisRequest(
        source_code=source_code,
        filename=target.name,
        enable_ai=ai,
    )

    result = engine.analyze(request, save=not no_save)

    if json_output:
        click.echo(result.model_dump_json(indent=2))
    else:
        # Human-Readable Formatted Console Report
        click.echo(click.style("\n=== AI-POWERED BUG DETECTOR REPORT ===", bold=True))
        click.echo(f"File:       {result.filename}")
        click.echo(f"SHA-256:    {result.code_hash[:16]}...")
        click.echo(f"Lines:      {result.line_count} | Characters: {result.char_count}")
        click.echo(f"Duration:   {result.execution_duration_ms:.2f} ms")

        # Syntax Status
        click.echo("\n--- Syntax Validation ---")
        if result.syntax.is_valid:
            click.echo(click.style("✓ Python AST Syntax: Valid", fg="green", bold=True))
        else:
            click.echo(
                click.style(
                    f"✕ Syntax Error at Line {result.syntax.line}, Column {result.syntax.column}: "
                    f"{result.syntax.error_message}",
                    fg="red",
                    bold=True,
                )
            )
            if result.syntax.text:
                click.echo(f"  > {result.syntax.text}")

        # Summary Findings
        click.echo("\n--- Findings Summary ---")
        click.echo(
            f"Total: {result.summary.total_findings} | "
            f"{click.style(f'Critical: {result.summary.critical_count}', fg='red')} | "
            f"{click.style(f'Errors: {result.summary.error_count}', fg='bright_red')} | "
            f"{click.style(f'Warnings: {result.summary.warning_count}', fg='yellow')} | "
            f"{click.style(f'Info: {result.summary.info_count}', fg='cyan')}"
        )

        # Findings Detail
        if result.findings:
            click.echo("\n--- Detected Issues ---")
            for idx, finding in enumerate(result.findings, 1):
                sev_color = {
                    Severity.CRITICAL: "red",
                    Severity.ERROR: "bright_red",
                    Severity.WARNING: "yellow",
                    Severity.INFO: "cyan",
                }.get(finding.severity, "white")

                header = (
                    f"[{idx}] {finding.rule_id} ({finding.category.value}) - "
                    f"Line {finding.location.line}:{finding.location.column}"
                )
                click.echo(click.style(header, bold=True))
                sev_label = click.style(finding.severity.value, fg=sev_color, bold=True)
                click.echo(f"    Severity: {sev_label}")
                click.echo(f"    Issue:    {finding.message}")
                click.echo(f"    Details:  {finding.explanation}")
                if finding.code_snippet:
                    click.echo(f"    Snippet:  {finding.code_snippet}")
                if finding.suggested_fix:
                    click.echo(click.style(f"    Fix:      {finding.suggested_fix}", fg="green"))
                click.echo()
        else:
            click.echo(click.style("✓ No static rule violations detected.", fg="green"))

        # AI Review Output
        if result.ai_review and result.ai_review.enabled:
            click.echo("\n--- AI Quality Review ---")
            if result.ai_review.success:
                tokens_str = result.ai_review.tokens_used or "N/A"
                click.echo(f"Model: {result.ai_review.model_used} | Tokens: {tokens_str}")
                click.echo(result.ai_review.review_text)
            else:
                click.echo(
                    click.style(
                        f"AI Review unavailable: {result.ai_review.error_message}",
                        fg="yellow",
                    )
                )

        click.echo(click.style("=======================================\n", bold=True))

    # Exit code determination
    if not result.syntax.is_valid:
        sys.exit(2)
    elif result.findings:
        sys.exit(1)
    else:
        sys.exit(0)


@cli.command("history")
@click.option("--limit", default=20, type=int, help="Maximum number of historical reviews to show.")
def history(limit: int) -> None:
    """List recent code review records from local database."""
    settings = get_settings()
    if settings.demo_mode:
        click.echo(click.style("History access is disabled in public demo mode.", fg="yellow"))
        sys.exit(1)

    try:
        db = DatabaseManager(settings.database_url)
        repo = ReviewRepository(db)
        items = repo.list_recent_reviews(limit=limit)
    except Exception as err:
        click.echo(click.style(f"Error accessing review history: {err}", fg="red"), err=True)
        sys.exit(1)

    if not items:
        click.echo("No review history records found.")
        return

    click.echo(click.style(f"\n--- Recent Reviews (Last {len(items)}) ---", bold=True))
    for item in items:
        date_str = item.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        syntax_mark = "✓" if item.is_valid_syntax else "✕"
        click.echo(
            f"ID: {item.review_id} | {date_str} | {item.filename:<15} | "
            f"Findings: {item.total_findings:<3} | Syntax: {syntax_mark}"
        )
    click.echo()


@cli.command("view")
@click.argument("review_id", type=str)
@click.option(
    "--json-output",
    "--json",
    is_flag=True,
    default=False,
    help="Output in raw JSON format.",
)
def view(review_id: str, json_output: bool) -> None:
    """View details of a past review by its unique ID."""
    settings = get_settings()
    if settings.demo_mode:
        click.echo(click.style("History access is disabled in public demo mode.", fg="yellow"))
        sys.exit(1)

    try:
        db = DatabaseManager(settings.database_url)
        repo = ReviewRepository(db)
        result = repo.get_review_by_id(review_id)
    except Exception as err:
        click.echo(click.style(f"Error accessing review record: {err}", fg="red"), err=True)
        sys.exit(1)

    if not result:
        click.echo(click.style(f"Review '{review_id}' not found.", fg="red"), err=True)
        sys.exit(1)

    if json_output:
        click.echo(result.model_dump_json(indent=2))
    else:
        click.echo(click.style(f"\n=== Historical Review: {result.review_id} ===", bold=True))
        click.echo(f"Timestamp:  {result.timestamp.isoformat()}")
        click.echo(f"File:       {result.filename}")
        click.echo(f"Findings:   {result.summary.total_findings}")
        click.echo("\n--- Source Code ---")
        click.echo(result.source_code)
        click.echo("\n--- Findings ---")
        for f in result.findings:
            click.echo(f"- [{f.rule_id}] Line {f.location.line}: {f.message} ({f.severity.value})")
        click.echo()


@cli.command("server")
@click.option("--host", default=None, help="Host address to bind.")
@click.option("--port", default=None, type=int, help="Port to listen on.")
@click.option("--reload", is_flag=True, default=False, help="Enable uvicorn hot-reload.")
def server(host: Optional[str], port: Optional[int], reload: bool) -> None:
    """Launch the FastAPI dashboard and REST API web server."""
    import uvicorn

    settings = get_settings()
    bind_host = host or settings.host
    bind_port = port or settings.port

    click.echo(f"Starting Bug Detector Server at http://{bind_host}:{bind_port}...")
    uvicorn.run(
        "bug_detector.api.app:app",
        host=bind_host,
        port=bind_port,
        reload=reload,
    )


main = cli

if __name__ == "__main__":
    main()
