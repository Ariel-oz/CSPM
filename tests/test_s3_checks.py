from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.s3_checks import (
    BucketEncryptionCheck,
    BucketInsecureTransportPolicyCheck,
    BucketLoggingCheck,
    BucketMfaDeleteDisabledCheck,
    BucketPublicAccessCheck,
    BucketVersioningCheck,
    _list_buckets,
    resolve_bucket_region,
)
from cspm_scan.core.models import Status


def _s3_client(region="us-east-1"):
    return boto3.client(
        "s3", region_name=region, aws_access_key_id="fake", aws_secret_access_key="fake"
    )


def _s3control_client():
    return boto3.client(
        "s3control", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake"
    )


# --- region resolution, tested in isolation first (the most bug-prone part) ---


def test_resolve_bucket_region_none_means_us_east_1():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.activate()

    region, error = resolve_bucket_region(client, "b1")

    assert region == "us-east-1"
    assert error is None
    stub.deactivate()


def test_resolve_bucket_region_eu_legacy_alias():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("get_bucket_location", {"LocationConstraint": "EU"}, {"Bucket": "b2"})
    stub.activate()

    region, error = resolve_bucket_region(client, "b2")

    assert region == "eu-west-1"
    stub.deactivate()


def test_resolve_bucket_region_explicit_region():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("get_bucket_location", {"LocationConstraint": "ap-south-1"}, {"Bucket": "b3"})
    stub.activate()

    region, error = resolve_bucket_region(client, "b3")

    assert region == "ap-south-1"
    stub.deactivate()


def test_list_buckets_mixed_regions_resolves_each_correctly():
    global_client = _s3_client()
    stub = Stubber(global_client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "us-bucket"}, {"Name": "eu-bucket"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "us-bucket"})
    stub.add_response("get_bucket_location", {"LocationConstraint": "eu-west-1"}, {"Bucket": "eu-bucket"})
    stub.activate()

    regional_clients = {"us-east-1": object(), "eu-west-1": object()}
    calls = {"n": 0}

    def client(service, region):
        # First call (ListBuckets) must go to the stubbed global client; subsequent
        # per-bucket calls go to that bucket's own regional client.
        calls["n"] += 1
        if calls["n"] == 1:
            return global_client
        return regional_clients[region]

    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=client))

    entries, error = _list_buckets(ctx)

    assert error is None
    by_name = {name: region for name, region, _ in entries}
    assert by_name["us-bucket"] == "us-east-1"
    assert by_name["eu-bucket"] == "eu-west-1"
    stub.deactivate()


# --- individual checks, using a fixed single-region bucket list for simplicity ---


def _ctx_with_single_bucket(s3_client, s3control_client=None, account_id="123456789012"):
    def client(service, region):
        if service == "s3control":
            return s3control_client
        return s3_client

    return SimpleNamespace(session_factory=SimpleNamespace(client=client), account_id=account_id)


def test_bucket_encryption_missing_is_fail():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.add_client_error(
        "get_bucket_encryption",
        service_error_code="ServerSideEncryptionConfigurationNotFoundError",
        service_message="none",
        expected_params={"Bucket": "b1"},
    )
    stub.activate()

    findings = BucketEncryptionCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.FAIL
    assert findings[0].error_code is None
    stub.deactivate()


def test_bucket_encryption_present_is_pass():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.add_response(
        "get_bucket_encryption",
        {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}},
        {"Bucket": "b1"},
    )
    stub.activate()

    findings = BucketEncryptionCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_bucket_versioning_disabled_is_fail():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.add_response("get_bucket_versioning", {}, {"Bucket": "b1"})
    stub.activate()

    findings = BucketVersioningCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_bucket_versioning_enabled_is_pass():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.add_response("get_bucket_versioning", {"Status": "Enabled"}, {"Bucket": "b1"})
    stub.activate()

    findings = BucketVersioningCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_bucket_logging_disabled_is_fail():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.add_response("get_bucket_logging", {}, {"Bucket": "b1"})
    stub.activate()

    findings = BucketLoggingCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_bucket_public_access_via_acl_grant_and_no_pab_is_fail():
    client = _s3_client()
    s3c = _s3control_client()
    stub = Stubber(client)
    s3c_stub = Stubber(s3c)

    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})

    s3c_stub.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        service_message="none",
        expected_params={"AccountId": "123456789012"},
    )
    stub.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        service_message="none",
        expected_params={"Bucket": "b1"},
    )
    stub.add_response(
        "get_bucket_acl",
        {
            "Owner": {"ID": "owner"},
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ],
        },
        {"Bucket": "b1"},
    )
    stub.add_client_error(
        "get_bucket_policy_status", service_error_code="NoSuchBucketPolicy", service_message="none", expected_params={"Bucket": "b1"}
    )
    stub.activate()
    s3c_stub.activate()

    findings = BucketPublicAccessCheck().execute(_ctx_with_single_bucket(client, s3c))

    assert findings[0].status == Status.FAIL
    assert len(findings[0].evidence["public_acl_grants"]) == 1
    stub.deactivate()
    s3c_stub.deactivate()


def test_bucket_public_access_blocked_by_pab_is_pass_despite_public_policy():
    client = _s3_client()
    s3c = _s3control_client()
    stub = Stubber(client)
    s3c_stub = Stubber(s3c)

    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})

    s3c_stub.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        service_message="none",
        expected_params={"AccountId": "123456789012"},
    )
    stub.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
        {"Bucket": "b1"},
    )
    stub.add_response("get_bucket_acl", {"Owner": {"ID": "owner"}, "Grants": []}, {"Bucket": "b1"})
    stub.add_response(
        "get_bucket_policy_status", {"PolicyStatus": {"IsPublic": True}}, {"Bucket": "b1"}
    )
    stub.activate()
    s3c_stub.activate()

    findings = BucketPublicAccessCheck().execute(_ctx_with_single_bucket(client, s3c))

    assert findings[0].status == Status.PASS
    stub.deactivate()
    s3c_stub.deactivate()


def test_mfa_delete_disabled_is_fail():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.add_response("get_bucket_versioning", {"Status": "Enabled"}, {"Bucket": "b1"})
    stub.activate()

    findings = BucketMfaDeleteDisabledCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_mfa_delete_enabled_is_pass():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.add_response("get_bucket_versioning", {"Status": "Enabled", "MFADelete": "Enabled"}, {"Bucket": "b1"})
    stub.activate()

    findings = BucketMfaDeleteDisabledCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_insecure_transport_no_policy_is_fail():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.add_client_error("get_bucket_policy", service_error_code="NoSuchBucketPolicy", service_message="none", expected_params={"Bucket": "b1"})
    stub.activate()

    findings = BucketInsecureTransportPolicyCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.FAIL
    assert findings[0].error_code is None
    stub.deactivate()


def test_insecure_transport_policy_present_is_pass():
    import json

    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::b1", "arn:aws:s3:::b1/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }
    stub.add_response("get_bucket_policy", {"Policy": json.dumps(policy)}, {"Bucket": "b1"})
    stub.activate()

    findings = BucketInsecureTransportPolicyCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_mfa_delete_access_denied_produces_error_finding():
    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    stub.add_client_error("get_bucket_versioning", service_error_code="AccessDenied", service_message="denied", expected_params={"Bucket": "b1"})
    stub.activate()

    findings = BucketMfaDeleteDisabledCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.ERROR
    assert findings[0].error_code == "AccessDenied"
    stub.deactivate()


def test_insecure_transport_policy_without_deny_statement_is_fail():
    import json

    client = _s3_client()
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "b1"}], "Owner": {}})
    stub.add_response("get_bucket_location", {}, {"Bucket": "b1"})
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b1/*"}],
    }
    stub.add_response("get_bucket_policy", {"Policy": json.dumps(policy)}, {"Bucket": "b1"})
    stub.activate()

    findings = BucketInsecureTransportPolicyCheck().execute(_ctx_with_single_bucket(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()
