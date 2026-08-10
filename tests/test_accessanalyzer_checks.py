from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.accessanalyzer_checks import AccessAnalyzerNotEnabledCheck
from cspm_scan.core.models import Status


def _client():
    return boto3.client("accessanalyzer", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def test_no_analyzers_is_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_response("list_analyzers", {"analyzers": []}, {"type": "ACCOUNT"})
    stub.activate()

    findings = AccessAnalyzerNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_active_analyzer_is_pass():
    client = _client()
    stub = Stubber(client)
    stub.add_response(
        "list_analyzers",
        {
            "analyzers": [
                {
                    "arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/default",
                    "name": "default",
                    "type": "ACCOUNT",
                    "createdAt": "2024-01-01T00:00:00Z",
                    "status": "ACTIVE",
                }
            ]
        },
        {"type": "ACCOUNT"},
    )
    stub.activate()

    findings = AccessAnalyzerNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_access_denied_produces_error_finding():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error("list_analyzers", service_error_code="AccessDeniedException", service_message="denied", expected_params={"type": "ACCOUNT"})
    stub.activate()

    findings = AccessAnalyzerNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.ERROR
    assert findings[0].error_code == "AccessDeniedException"
    stub.deactivate()
