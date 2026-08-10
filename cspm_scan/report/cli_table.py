from rich.console import Console
from rich.table import Table

from cspm_scan.core.models import Finding, Status

_STATUS_STYLE = {
    Status.PASS: "green",
    Status.FAIL: "red",
    Status.ERROR: "yellow",
    Status.NOT_APPLICABLE: "dim",
}


def print_cli_report(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()

    table = Table(title="CSPM Scan Findings", show_lines=False)
    table.add_column("Severity")
    table.add_column("Service")
    table.add_column("Check")
    table.add_column("Resource")
    table.add_column("Region")
    table.add_column("Status")

    for finding in sorted(findings, key=lambda f: (-f.severity.value, f.service, f.check_id)):
        style = _STATUS_STYLE.get(finding.status, "")
        table.add_row(
            finding.severity.name,
            finding.service,
            finding.check_id,
            finding.resource_id,
            finding.region,
            f"[{style}]{finding.status.value.upper()}[/{style}]",
        )

    console.print(table)

    counts = {s: sum(1 for f in findings if f.status == s) for s in Status}
    console.print(
        f"\nTotal: {len(findings)}  "
        f"[green]PASS: {counts[Status.PASS]}[/green]  "
        f"[red]FAIL: {counts[Status.FAIL]}[/red]  "
        f"[yellow]ERROR: {counts[Status.ERROR]}[/yellow]  "
        f"[dim]N/A: {counts[Status.NOT_APPLICABLE]}[/dim]"
    )
