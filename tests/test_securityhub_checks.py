from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.securityhub_checks import SecurityHubNotEnabledCheck
from cspm_scan.core.models import Status


def _client():
    return boto3.client("securityhub", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def test_not_subscribed_is_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error("describe_hub", service_error_code="InvalidAccessException", service_message="Account is not subscribed to AWS Security Hub")
    stub.activate()

    findings = SecurityHubNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    assert findings[0].error_code is None
    stub.deactivate()


def test_enabled_is_pass():
    client = _client()
    stub = Stubber(client)
    stub.add_response(
        "describe_hub",
        {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default", "SubscribedAt": "2024-01-01T00:00:00Z"},
    )
    stub.activate()

    findings = SecurityHubNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_access_denied_iam_permission_produces_error_not_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error("describe_hub", service_error_code="AccessDeniedException", service_message="is not authorized to perform: securityhub:DescribeHub")
    stub.activate()

    findings = SecurityHubNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.ERROR
    assert findings[0].error_code == "AccessDeniedException"
    stub.deactivate()
