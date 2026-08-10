from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.config_checks import ConfigRecorderNotEnabledCheck
from cspm_scan.core.models import Status


def _client():
    return boto3.client("config", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def test_no_recorder_is_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_response("describe_configuration_recorders", {"ConfigurationRecorders": []})
    stub.activate()

    findings = ConfigRecorderNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_recorder_recording_successfully_is_pass():
    client = _client()
    stub = Stubber(client)
    stub.add_response(
        "describe_configuration_recorders",
        {"ConfigurationRecorders": [{"name": "default", "roleARN": "arn:aws:iam::123456789012:role/config-role"}]},
    )
    stub.add_response(
        "describe_configuration_recorder_status",
        {"ConfigurationRecordersStatus": [{"name": "default", "recording": True, "lastStatus": "SUCCESS"}]},
    )
    stub.activate()

    findings = ConfigRecorderNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_recorder_exists_but_not_recording_is_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_response(
        "describe_configuration_recorders",
        {"ConfigurationRecorders": [{"name": "default", "roleARN": "arn:aws:iam::123456789012:role/config-role"}]},
    )
    stub.add_response(
        "describe_configuration_recorder_status",
        {"ConfigurationRecordersStatus": [{"name": "default", "recording": False}]},
    )
    stub.activate()

    findings = ConfigRecorderNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_access_denied_produces_error_finding():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error("describe_configuration_recorders", service_error_code="AccessDeniedException", service_message="denied")
    stub.activate()

    findings = ConfigRecorderNotEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.ERROR
    stub.deactivate()
