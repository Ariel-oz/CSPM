from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.macie_checks import MacieNotEnabledCheck
from cspm_scan.core.models import Status


def _client():
    return boto3.client("macie2", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def test_not_enabled_message_is_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error("get_macie_session", service_error_code="AccessDeniedException", service_message="Macie is not enabled")
    stub.activate()

    findings = MacieNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    assert findings[0].error_code is None
    stub.deactivate()


def test_iam_permission_denial_is_error_not_fail():
    """Regression test: Macie overloads AccessDeniedException for both 'not enabled'
    and genuine IAM permission denial with the same error code - only the message
    text distinguishes them. A real scan against a live account surfaced exactly
    this: the scanner profile lacked macie2:GetMacieSession entirely, and the naive
    'AccessDeniedException always means not enabled' logic would have silently
    misreported a permissions gap as a compliance finding."""
    client = _client()
    stub = Stubber(client)
    stub.add_client_error(
        "get_macie_session",
        service_error_code="AccessDeniedException",
        service_message="User: arn:aws:iam::123456789012:user/scanner is not authorized to perform: macie2:GetMacieSession",
    )
    stub.activate()

    findings = MacieNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.ERROR
    assert findings[0].error_code == "AccessDeniedException"
    stub.deactivate()


def test_enabled_is_pass():
    client = _client()
    stub = Stubber(client)
    stub.add_response(
        "get_macie_session",
        {
            "createdAt": "2024-01-01T00:00:00Z",
            "findingPublishingFrequency": "SIX_HOURS",
            "serviceRole": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie",
            "status": "ENABLED",
            "updatedAt": "2024-01-01T00:00:00Z",
        },
    )
    stub.activate()

    findings = MacieNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_paused_is_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_response(
        "get_macie_session",
        {
            "createdAt": "2024-01-01T00:00:00Z",
            "findingPublishingFrequency": "SIX_HOURS",
            "serviceRole": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie",
            "status": "PAUSED",
            "updatedAt": "2024-01-01T00:00:00Z",
        },
    )
    stub.activate()

    findings = MacieNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()
