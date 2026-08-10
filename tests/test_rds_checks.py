from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.rds_checks import (
    RdsAutoMinorVersionUpgradeDisabledCheck,
    RdsInstanceUnencryptedCheck,
    RdsPubliclyAccessibleCheck,
)
from cspm_scan.core.models import Status


def _rds_client():
    return boto3.client("rds", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def test_unencrypted_instance_is_fail():
    client = _rds_client()
    stub = Stubber(client)
    stub.add_response("describe_db_instances", {"DBInstances": [{"DBInstanceIdentifier": "db-1", "StorageEncrypted": False}]})
    stub.activate()

    findings = RdsInstanceUnencryptedCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_encrypted_instance_is_pass():
    client = _rds_client()
    stub = Stubber(client)
    stub.add_response("describe_db_instances", {"DBInstances": [{"DBInstanceIdentifier": "db-2", "StorageEncrypted": True}]})
    stub.activate()

    findings = RdsInstanceUnencryptedCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_auto_minor_version_upgrade_disabled_is_fail():
    client = _rds_client()
    stub = Stubber(client)
    stub.add_response("describe_db_instances", {"DBInstances": [{"DBInstanceIdentifier": "db-1", "AutoMinorVersionUpgrade": False}]})
    stub.activate()

    findings = RdsAutoMinorVersionUpgradeDisabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_auto_minor_version_upgrade_enabled_is_pass():
    client = _rds_client()
    stub = Stubber(client)
    stub.add_response("describe_db_instances", {"DBInstances": [{"DBInstanceIdentifier": "db-2", "AutoMinorVersionUpgrade": True}]})
    stub.activate()

    findings = RdsAutoMinorVersionUpgradeDisabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_publicly_accessible_is_fail():
    client = _rds_client()
    stub = Stubber(client)
    stub.add_response("describe_db_instances", {"DBInstances": [{"DBInstanceIdentifier": "db-1", "PubliclyAccessible": True}]})
    stub.activate()

    findings = RdsPubliclyAccessibleCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_not_publicly_accessible_is_pass():
    client = _rds_client()
    stub = Stubber(client)
    stub.add_response("describe_db_instances", {"DBInstances": [{"DBInstanceIdentifier": "db-2", "PubliclyAccessible": False}]})
    stub.activate()

    findings = RdsPubliclyAccessibleCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_publicly_accessible_access_denied_produces_error_finding():
    client = _rds_client()
    stub = Stubber(client)
    stub.add_client_error("describe_db_instances", service_error_code="AccessDenied", service_message="denied")
    stub.activate()

    findings = RdsPubliclyAccessibleCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.ERROR
    assert findings[0].error_code == "AccessDenied"
    stub.deactivate()
