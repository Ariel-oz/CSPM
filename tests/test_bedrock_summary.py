import pytest

from cspm_scan.core.bedrock_summary import (
    MAX_FINDINGS_IN_PROMPT,
    BedrockSummaryError,
    build_messages,
    generate_ai_summary,
)
from cspm_scan.core.models import Finding, Severity, Status


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


def _tool_response(input_dict):
    return {
        "output": {
            "message": {
                "content": [
                    {"toolUse": {"name": "submit_priority_summary", "input": input_dict}},
                ]
            }
        }
    }


def _summary_input():
    return {
        "most_urgent_fix": {
            "check_id": "s3_001_bucket_public_access",
            "title": "S3 bucket is publicly accessible",
            "severity": "CRITICAL",
            "reason": "exposed",
            "remediation": "fix it",
        },
        "executive_summary": "posture is weak",
        "prioritized_fixes": [],
    }


def test_build_messages_includes_only_fail_findings_sorted_by_severity():
    findings = [
        _finding(check_id="low_1", severity=Severity.LOW),
        _finding(check_id="critical_1", severity=Severity.CRITICAL),
        _finding(check_id="passing_1", status=Status.PASS),
        _finding(check_id="high_1", severity=Severity.HIGH),
    ]

    messages = build_messages(findings)
    text = messages[0]["content"][0]["text"]

    assert "critical_1" in text
    assert "high_1" in text
    assert "low_1" in text
    assert "passing_1" not in text
    assert text.index("critical_1") < text.index("high_1") < text.index("low_1")


def test_build_messages_notes_error_findings_without_listing_them():
    findings = [_finding(), _finding(check_id="err_1", status=Status.ERROR, error_code="AccessDenied")]

    text = build_messages(findings)[0]["content"][0]["text"]

    assert "1 checks could not be evaluated" in text
    assert "err_1" not in text


def test_build_messages_truncates_with_explicit_note():
    findings = [_finding(check_id=f"fail_{i}", severity=Severity.LOW) for i in range(MAX_FINDINGS_IN_PROMPT + 5)]

    text = build_messages(findings)[0]["content"][0]["text"]

    assert "5 lower-severity FAIL findings are omitted" in text
    assert f"fail_{MAX_FINDINGS_IN_PROMPT + 4}" not in text
    assert "fail_0" in text


def test_build_messages_truncation_keeps_highest_severity_not_just_first_seen():
    # The cap must apply after sorting by severity, not before — a CRITICAL finding appended
    # last in the input must still survive over earlier LOW findings.
    findings = [_finding(check_id=f"low_{i}", severity=Severity.LOW) for i in range(MAX_FINDINGS_IN_PROMPT)]
    findings.append(_finding(check_id="critical_late", severity=Severity.CRITICAL))

    text = build_messages(findings)[0]["content"][0]["text"]

    assert "critical_late" in text
    assert "1 lower-severity FAIL findings are omitted" in text


def test_generate_ai_summary_returns_none_without_calling_bedrock_when_no_fails(mocker):
    findings = [_finding(status=Status.PASS)]
    client = mocker.Mock()

    result = generate_ai_summary(findings, client, "some-model-id")

    assert result is None
    client.converse.assert_not_called()


def test_generate_ai_summary_parses_tool_use_response(mocker):
    findings = [_finding()]
    client = mocker.Mock()
    client.converse.return_value = _tool_response(_summary_input())

    result = generate_ai_summary(findings, client, "some-model-id")

    assert result == _summary_input()
    client.converse.assert_called_once()
    _, kwargs = client.converse.call_args
    assert kwargs["modelId"] == "some-model-id"
    assert kwargs["toolConfig"]["toolChoice"]["tool"]["name"] == "submit_priority_summary"


def test_generate_ai_summary_raises_on_client_error(mocker):
    findings = [_finding()]
    client = mocker.Mock()
    client.converse.side_effect = RuntimeError("boom")

    with pytest.raises(BedrockSummaryError):
        generate_ai_summary(findings, client, "some-model-id")


def test_generate_ai_summary_raises_when_no_tool_use_in_response(mocker):
    findings = [_finding()]
    client = mocker.Mock()
    client.converse.return_value = {"output": {"message": {"content": [{"text": "no tool call here"}]}}}

    with pytest.raises(BedrockSummaryError):
        generate_ai_summary(findings, client, "some-model-id")
