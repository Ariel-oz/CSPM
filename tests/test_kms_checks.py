from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.kms_checks import KmsCmkRotationDisabledCheck
from cspm_scan.core.models import Status


def _client():
    return boto3.client("kms", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def _key_metadata(key_id, key_manager, key_spec="SYMMETRIC_DEFAULT"):
    return {
        "KeyId": key_id,
        "Arn": f"arn:aws:kms:us-east-1:123456789012:key/{key_id}",
        "AWSAccountId": "123456789012",
        "CreationDate": "2024-01-01T00:00:00Z",
        "Enabled": True,
        "Description": "",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": key_manager,
        "KeySpec": key_spec,
    }


def test_customer_key_rotation_disabled_is_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_response("list_keys", {"Keys": [{"KeyId": "key-1", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-1"}]})
    stub.add_response("describe_key", {"KeyMetadata": _key_metadata("key-1", "CUSTOMER")}, {"KeyId": "key-1"})
    stub.add_response("get_key_rotation_status", {"KeyRotationEnabled": False}, {"KeyId": "key-1"})
    stub.activate()

    findings = KmsCmkRotationDisabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_customer_key_rotation_enabled_is_pass():
    client = _client()
    stub = Stubber(client)
    stub.add_response("list_keys", {"Keys": [{"KeyId": "key-2", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-2"}]})
    stub.add_response("describe_key", {"KeyMetadata": _key_metadata("key-2", "CUSTOMER")}, {"KeyId": "key-2"})
    stub.add_response("get_key_rotation_status", {"KeyRotationEnabled": True}, {"KeyId": "key-2"})
    stub.activate()

    findings = KmsCmkRotationDisabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_aws_managed_key_is_skipped():
    client = _client()
    stub = Stubber(client)
    stub.add_response("list_keys", {"Keys": [{"KeyId": "key-3", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-3"}]})
    stub.add_response("describe_key", {"KeyMetadata": _key_metadata("key-3", "AWS")}, {"KeyId": "key-3"})
    stub.activate()

    findings = KmsCmkRotationDisabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings == []
    stub.deactivate()


def test_list_keys_access_denied_produces_error_finding():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error("list_keys", service_error_code="AccessDeniedException", service_message="denied")
    stub.activate()

    findings = KmsCmkRotationDisabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.ERROR
    stub.deactivate()
