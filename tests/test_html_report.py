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


def test_html_report_handles_zero_findings(tmp_path):
    output_path = tmp_path / "empty.html"

    write_html_report([], output_path, account_id="123456789012", profile="test", regions=["us-east-1"])

    html = output_path.read_text(encoding="utf-8")
    assert "Total" in html
