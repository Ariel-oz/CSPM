from datetime import datetime, timezone
from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.efs_checks import EfsFilesystemUnencryptedCheck
from cspm_scan.core.models import Status


def _client():
    return boto3.client("efs", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def _fs(fs_id, encrypted):
    return {
        "OwnerId": "123456789012",
        "CreationToken": f"token-{fs_id}",
        "FileSystemId": fs_id,
        "CreationTime": datetime.now(timezone.utc),
        "LifeCycleState": "available",
        "NumberOfMountTargets": 0,
        "SizeInBytes": {"Value": 0},
        "PerformanceMode": "generalPurpose",
        "Encrypted": encrypted,
        "Tags": [],
    }


def test_unencrypted_filesystem_is_fail():
    client = _client()
    stub = Stubber(client)
    stub.add_response("describe_file_systems", {"FileSystems": [_fs("fs-1", False)]})
    stub.activate()

    findings = EfsFilesystemUnencryptedCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_encrypted_filesystem_is_pass():
    client = _client()
    stub = Stubber(client)
    stub.add_response("describe_file_systems", {"FileSystems": [_fs("fs-2", True)]})
    stub.activate()

    findings = EfsFilesystemUnencryptedCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_access_denied_produces_error_finding():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error("describe_file_systems", service_error_code="AccessDeniedException", service_message="denied")
    stub.activate()

    findings = EfsFilesystemUnencryptedCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.ERROR
    stub.deactivate()
