from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.account_checks import SecurityContactMissingCheck
from cspm_scan.core.models import Status


def _client():
    return boto3.client("account", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def test_no_security_contact_is_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error(
        "get_alternate_contact",
        service_error_code="ResourceNotFoundException",
        service_message="none",
        expected_params={"AlternateContactType": "SECURITY"},
    )
    stub.activate()

    findings = SecurityContactMissingCheck().execute(_ctx(client))

    assert findings[0].status == Status.FAIL
    assert findings[0].error_code is None
    stub.deactivate()


def test_security_contact_present_is_pass():
    client = _client()
    stub = Stubber(client)
    stub.add_response(
        "get_alternate_contact",
        {
            "AlternateContact": {
                "AlternateContactType": "SECURITY",
                "EmailAddress": "security@example.com",
                "Name": "Security Team",
                "PhoneNumber": "+15555555555",
                "Title": "Security",
            }
        },
        {"AlternateContactType": "SECURITY"},
    )
    stub.activate()

    findings = SecurityContactMissingCheck().execute(_ctx(client))

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_access_denied_produces_error_finding():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error("get_alternate_contact", service_error_code="AccessDeniedException", service_message="denied", expected_params={"AlternateContactType": "SECURITY"})
    stub.activate()

    findings = SecurityContactMissingCheck().execute(_ctx(client))

    assert findings[0].status == Status.ERROR
    stub.deactivate()
