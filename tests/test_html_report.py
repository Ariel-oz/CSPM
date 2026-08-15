from cspm_scan.core.models import Finding, Severity, Status
from cspm_scan.report.html_report import write_html_report


def _finding(**overrides):
    base = dict(
        check_id="s3_001_bucket_public_access",
        title="S3 bucket is publicly accessible",
        service="s3",
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        resource_id="my-bucket",
        region="us-east-1",
        description="desc",
        remediation="fix it",
    )
    base.update(overrides)
    return Finding(**base)


def test_html_report_is_valid_and_contains_findings(tmp_path):
    findings = [_finding(), _finding(status=Status.PASS, resource_id="other-bucket")]
    output_path = tmp_path / "report.html"

    write_html_report(findings, output_path, account_id="123456789012", profile="test", regions=["us-east-1"])

    html = output_path.read_text(encoding="utf-8")
    assert "123456789012" in html
    assert "my-bucket" in html
    assert "other-bucket" in html
    assert html.count("<html") == 1


def test_html_report_escapes_script_breakout_in_evidence(tmp_path):
    malicious_resource_id = '</script><script>window.__pwned = true;</script>'
    findings = [_finding(resource_id=malicious_resource_id, evidence={"payload": "</script><img src=x>"})]
    output_path = tmp_path / "cspm_test_report.html"

    write_html_report(findings, output_path, account_id="123456789012", profile="test", regions=["us-east-1"])

    html = output_path.read_text(encoding="utf-8")
    # The raw, unescaped breakout sequence must never appear literally in the HTML source.
    assert "</script><script>" not in html
    assert "window.__pwned" not in html or "<\\/script>" in html


def test_html_report_escapes_html_in_header_fields(tmp_path):
    # Regression test: the Jinja Environment's autoescape was previously configured via
    # select_autoescape(["html"]), which matches on template filename suffix — but the template
    # is named "report.html.j2" (suffix ".j2"), so autoescaping silently never activated for any
    # server-rendered `{{ }}` field, including account_id/profile below.
    output_path = tmp_path / "report.html"

    write_html_report([], output_path, account_id="<script>alert(1)</script>", profile="test", regions=["us-east-1"])

    html = output_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_report_handles_zero_findings(tmp_path):
    output_path = tmp_path / "empty.html"

    write_html_report([], output_path, account_id="123456789012", profile="test", regions=["us-east-1"])

    html = output_path.read_text(encoding="utf-8")
    assert "Total" in html


def _ai_summary(**overrides):
    base = dict(
        most_urgent_fix={
            "check_id": "s3_001_bucket_public_access",
            "title": "S3 bucket is publicly accessible",
            "severity": "CRITICAL",
            "reason": "Publicly readable bucket exposes data to the internet",
            "remediation": "Enable S3 Block Public Access",
        },
        executive_summary="One critical public bucket needs immediate remediation.",
        prioritized_fixes=[
            {"check_id": "s3_001_bucket_public_access", "title": "S3 bucket is publicly accessible", "severity": "CRITICAL", "reason": "exposed"},
        ],
    )
    base.update(overrides)
    return base


def test_html_report_renders_ai_summary_section(tmp_path):
    findings = [_finding()]
    output_path = tmp_path / "report.html"

    write_html_report(
        findings, output_path, account_id="123456789012", profile="test", regions=["us-east-1"],
        ai_summary=_ai_summary(),
    )

    html = output_path.read_text(encoding="utf-8")
    assert "AI Priority Summary" in html
    assert "S3 bucket is publicly accessible" in html
    assert "Enable S3 Block Public Access" in html


def test_html_report_omits_ai_summary_section_when_none(tmp_path):
    findings = [_finding()]
    output_path = tmp_path / "report.html"

    write_html_report(findings, output_path, account_id="123456789012", profile="test", regions=["us-east-1"], ai_summary=None)

    html = output_path.read_text(encoding="utf-8")
    assert "AI Priority Summary" not in html


def test_html_report_escapes_html_in_ai_summary(tmp_path):
    findings = [_finding()]
    output_path = tmp_path / "report.html"
    malicious = _ai_summary(executive_summary="<script>window.__pwned = true;</script>")

    write_html_report(findings, output_path, account_id="123456789012", profile="test", regions=["us-east-1"], ai_summary=malicious)

    html = output_path.read_text(encoding="utf-8")
    assert "<script>window.__pwned" not in html
    assert "&lt;script&gt;" in html
