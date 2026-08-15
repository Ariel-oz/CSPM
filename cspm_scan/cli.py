import argparse
import sys
from pathlib import Path

from rich.console import Console

from cspm_scan.core.engine import ScanContext, ScanEngine
from cspm_scan.core.session import PreflightError, SessionFactory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cspm-scan", description="Local read-only AWS CSPM scanner")
    parser.add_argument("--profile", help="AWS named profile to scan with")
    parser.add_argument("--regions", help="Comma-separated regions to scan (default: auto-discover enabled regions)")
    parser.add_argument("--output-dir", default="./output", help="Directory to write JSON/HTML reports into")
    parser.add_argument(
        "--formats",
        default="table,json,html",
        help="Comma-separated output formats: table,json,html",
    )
    parser.add_argument(
        "--print-iam-policy",
        action="store_true",
        help="Print (or write, with --output) the least-privilege IAM policy for the scanner user and exit",
    )
    parser.add_argument("--output", help="With --print-iam-policy, file path to write the policy JSON to")
    parser.add_argument(
        "--ai-summary",
        action="store_true",
        help="Use AWS Bedrock to analyze the FAIL findings and embed a prioritized summary in report.html "
        "(requires 'html' in --formats; best-effort, never fails the scan)",
    )
    parser.add_argument(
        "--bedrock-model",
        default="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        help="Bedrock model (or inference profile) ID to use with --ai-summary",
    )
    parser.add_argument(
        "--bedrock-region",
        default="us-east-1",
        help="AWS region to call Bedrock in with --ai-summary (independent of --regions, which controls what's scanned)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    console = Console()
    parser = build_parser()
    args = parser.parse_args(argv)

    # Importing checks registers them into CHECK_REGISTRY before anything reads it.
    import cspm_scan.checks  # noqa: F401

    if args.print_iam_policy:
        from cspm_scan.core.policy_gen import build_policy, write_policy

        policy = build_policy()
        if args.output:
            write_policy(policy, Path(args.output))
            console.print(f"IAM policy written to {args.output}")
        else:
            import json

            console.print(json.dumps(policy, indent=2))
        return 0

    if not args.profile:
        console.print("[red]--profile is required unless using --print-iam-policy[/red]")
        return 2

    formats = set(args.formats.split(","))

    if args.ai_summary and "html" not in formats:
        console.print("[red]--ai-summary requires 'html' in --formats (that's the only place it's shown)[/red]")
        return 2

    regions = args.regions.split(",") if args.regions else None

    try:
        session_factory = SessionFactory(profile=args.profile, regions=regions)
        session_factory.preflight()
    except PreflightError as e:
        console.print(f"[red]{e}[/red]")
        return 1

    ctx = ScanContext(
        session_factory=session_factory,
        regions=session_factory.regions,
        account_id=session_factory.account_id,
    )
    findings = ScanEngine(ctx).run()

    ai_summary = None
    if args.ai_summary:
        from cspm_scan.core.bedrock_summary import generate_ai_summary

        try:
            bedrock_client = session_factory.client("bedrock-runtime", args.bedrock_region)
            ai_summary = generate_ai_summary(findings, bedrock_client, args.bedrock_model)
            if ai_summary is None:
                console.print("[yellow]AI summary skipped: no FAIL findings to summarize[/yellow]")
        except Exception as e:
            # Best-effort: a bad --bedrock-region/--bedrock-model, throttling, missing model
            # access, etc. must never discard the scan that already ran. generate_ai_summary()
            # itself catches its own errors into BedrockSummaryError, but client construction
            # above (e.g. botocore.exceptions.InvalidRegionError on a malformed region string)
            # is outside that boundary, so this catches broadly on purpose.
            console.print(f"[yellow]AI summary skipped: {e}[/yellow]")

    output_dir = Path(args.output_dir)

    if "table" in formats:
        from cspm_scan.report.cli_table import print_cli_report

        print_cli_report(findings, console=console)

    if "json" in formats:
        from cspm_scan.report.json_report import write_json_report

        json_path = output_dir / "findings.json"
        write_json_report(findings, json_path)
        console.print(f"JSON report written to {json_path}")

    if "html" in formats:
        from cspm_scan.report.html_report import write_html_report

        html_path = output_dir / "report.html"
        write_html_report(
            findings,
            html_path,
            account_id=ctx.account_id,
            profile=args.profile,
            regions=ctx.regions,
            ai_summary=ai_summary,
        )
        console.print(f"HTML report written to {html_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
