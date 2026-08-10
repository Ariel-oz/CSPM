from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.guardduty_checks import GuardDutyDetectorEnabledCheck
from cspm_scan.core.models import Status


def _gd_client():
    return boto3.client("guardduty", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def test_no_detector_is_fail():
    client = _gd_client()
    stub = Stubber(client)
    stub.add_response("list_detectors", {"DetectorIds": []})
    stub.activate()

    findings = GuardDutyDetectorEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_detector_enabled_is_pass():
    client = _gd_client()
    stub = Stubber(client)
    stub.add_response("list_detectors", {"DetectorIds": ["det-1"]})
    stub.add_response(
        "get_detector",
        {"Status": "ENABLED", "ServiceRole": "x", "CreatedAt": "2024-01-01", "UpdatedAt": "2024-01-01", "FindingPublishingFrequency": "SIX_HOURS"},
        {"DetectorId": "det-1"},
    )
    stub.activate()

    findings = GuardDutyDetectorEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_detector_disabled_is_fail():
    client = _gd_client()
    stub = Stubber(client)
    stub.add_response("list_detectors", {"DetectorIds": ["det-1"]})
    stub.add_response(
        "get_detector",
        {"Status": "DISABLED", "ServiceRole": "x", "CreatedAt": "2024-01-01", "UpdatedAt": "2024-01-01", "FindingPublishingFrequency": "SIX_HOURS"},
        {"DetectorId": "det-1"},
    )
    stub.activate()

    findings = GuardDutyDetectorEnabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()
