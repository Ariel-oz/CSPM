import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from cspm_scan.core.models import Finding, Status

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _safe_json(data) -> str:
    """json.dumps output embedded in an HTML <script> block must not contain a
    literal "</script" or "<!--" sequence, or the browser's HTML parser closes
    the tag early regardless of JS/JSON syntax context."""
    raw = json.dumps(data, default=str)
    return raw.replace("</", "<\\/").replace("<!--", "<\\!--")


def write_html_report(
    findings: list[Finding],
    output_path: Path,
    account_id: str | None,
    profile: str,
    regions: list[str],
    ai_summary: dict | None = None,
) -> None:
    # `select_autoescape(["html"])` matches on the template's filename suffix, and this template
    # is named "report.html.j2" (suffix ".j2"), so that check silently evaluated to False and
    # autoescaping was never actually on. Force it on unconditionally instead — every server-side
    # `{{ }}` in this template (account_id/profile/regions, and now LLM-produced ai_summary text)
    # must be HTML-escaped.
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")

    counts = {s.value: sum(1 for f in findings if f.status == s) for s in Status}
    fail_by_severity: dict[str, int] = {}
    for f in findings:
        if f.status == Status.FAIL:
            fail_by_severity[f.severity.name] = fail_by_severity.get(f.severity.name, 0) + 1

    html = template.render(
        account_id=account_id or "unknown",
        profile=profile,
        regions=sorted(regions),
        generated_at=datetime.now(timezone.utc).isoformat(),
        total=len(findings),
        counts=counts,
        fail_by_severity=fail_by_severity,
        ai_summary=ai_summary,
        findings_json=_safe_json([f.to_dict() for f in findings]),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
