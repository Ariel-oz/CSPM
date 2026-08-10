from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.cloudtrail_checks import (
    KmsEncryptionDisabledCheck,
    LogFileValidationDisabledCheck,
    MultiRegionTrailLoggingCheck,
    S3DataEventsReadCheck,
    S3DataEventsWriteCheck,
    TrailBucketAccessLoggingCheck,
)
from cspm_scan.core.models import Status


def _ct_client(region):
    return boto3.client(
        "cloudtrail", region_name=region, aws_access_key_id="fake", aws_secret_access_key="fake"
    )


def test_dedupes_shadow_trail_copies_and_uses_home_region_for_status():
    us_client = _ct_client("us-east-1")
    eu_client = _ct_client("eu-west-1")
    us_stub = Stubber(us_client)
    eu_stub = Stubber(eu_client)

    trail_arn = "arn:aws:cloudtrail:eu-west-1:123456789012:trail/org-trail"
    # Simulate the shadow-copy duplication: the same TrailARN appears twice in one
    # describe_trails response (as it would across regions) - must be deduped.
    us_stub.add_response(
        "describe_trails",
        {
            "trailList": [
                {"Name": "org-trail", "TrailARN": trail_arn, "IsMultiRegionTrail": True, "HomeRegion": "eu-west-1"},
                {"Name": "org-trail", "TrailARN": trail_arn, "IsMultiRegionTrail": True, "HomeRegion": "eu-west-1"},
            ]
        },
        {"includeShadowTrails": True},
    )
    eu_stub.add_response("get_trail_status", {"IsLogging": True}, {"Name": trail_arn})
    us_stub.activate()
    eu_stub.activate()

    clients = {"us-east-1": us_client, "eu-west-1": eu_client}
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: clients[region]))

    findings = MultiRegionTrailLoggingCheck().execute(ctx)

    assert len(findings) == 1
    assert findings[0].status == Status.PASS
    assert len(findings[0].evidence["multiregion_trails"]) == 1  # deduped to one entry
    eu_stub.assert_no_pending_responses()  # exactly one get_trail_status call, not two
    us_stub.deactivate()
    eu_stub.deactivate()


def test_no_multiregion_trail_is_fail():
    us_client = _ct_client("us-east-1")
    us_stub = Stubber(us_client)
    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "single-region", "TrailARN": "arn:x", "IsMultiRegionTrail": False, "HomeRegion": "us-east-1"}]},
        {"includeShadowTrails": True},
    )
    us_stub.activate()

    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: us_client))

    findings = MultiRegionTrailLoggingCheck().execute(ctx)

    assert findings[0].status == Status.FAIL
    us_stub.deactivate()


def test_log_file_validation_disabled_is_fail():
    us_client = _ct_client("us-east-1")
    us_stub = Stubber(us_client)
    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "t1", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/t1", "LogFileValidationEnabled": False}]},
        {"includeShadowTrails": True},
    )
    us_stub.activate()
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: us_client))

    findings = LogFileValidationDisabledCheck().execute(ctx)

    assert findings[0].status == Status.FAIL
    us_stub.deactivate()


def test_log_file_validation_enabled_is_pass():
    us_client = _ct_client("us-east-1")
    us_stub = Stubber(us_client)
    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "t1", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/t1", "LogFileValidationEnabled": True}]},
        {"includeShadowTrails": True},
    )
    us_stub.activate()
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: us_client))

    findings = LogFileValidationDisabledCheck().execute(ctx)

    assert findings[0].status == Status.PASS
    us_stub.deactivate()


def test_kms_encryption_disabled_and_enabled():
    us_client = _ct_client("us-east-1")
    us_stub = Stubber(us_client)
    us_stub.add_response(
        "describe_trails",
        {
            "trailList": [
                {"Name": "no-kms", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/no-kms"},
                {"Name": "with-kms", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/with-kms", "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc"},
            ]
        },
        {"includeShadowTrails": True},
    )
    us_stub.activate()
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: us_client))

    findings = KmsEncryptionDisabledCheck().execute(ctx)

    by_arn = {f.resource_id: f for f in findings}
    assert by_arn["arn:aws:cloudtrail:us-east-1:123456789012:trail/no-kms"].status == Status.FAIL
    assert by_arn["arn:aws:cloudtrail:us-east-1:123456789012:trail/with-kms"].status == Status.PASS
    us_stub.deactivate()


def test_trail_bucket_access_logging_disabled_is_fail():
    us_client = _ct_client("us-east-1")
    s3_client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")
    us_stub = Stubber(us_client)
    s3_stub = Stubber(s3_client)

    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "t1", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/t1", "S3BucketName": "ct-bucket"}]},
        {"includeShadowTrails": True},
    )
    s3_stub.add_response("get_bucket_location", {}, {"Bucket": "ct-bucket"})
    s3_stub.add_response("get_bucket_logging", {}, {"Bucket": "ct-bucket"})
    us_stub.activate()
    s3_stub.activate()

    clients = {"cloudtrail": us_client, "s3": s3_client}
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: clients[service]))

    findings = TrailBucketAccessLoggingCheck().execute(ctx)

    assert findings[0].status == Status.FAIL
    assert findings[0].resource_id == "ct-bucket"
    us_stub.deactivate()
    s3_stub.deactivate()


def test_trail_bucket_access_logging_enabled_is_pass():
    us_client = _ct_client("us-east-1")
    s3_client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")
    us_stub = Stubber(us_client)
    s3_stub = Stubber(s3_client)

    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "t1", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/t1", "S3BucketName": "ct-bucket"}]},
        {"includeShadowTrails": True},
    )
    s3_stub.add_response("get_bucket_location", {}, {"Bucket": "ct-bucket"})
    s3_stub.add_response(
        "get_bucket_logging",
        {"LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "ct/"}},
        {"Bucket": "ct-bucket"},
    )
    us_stub.activate()
    s3_stub.activate()

    clients = {"cloudtrail": us_client, "s3": s3_client}
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: clients[service]))

    findings = TrailBucketAccessLoggingCheck().execute(ctx)

    assert findings[0].status == Status.PASS
    us_stub.deactivate()
    s3_stub.deactivate()


def test_s3_data_events_write_and_read_legacy_selector():
    us_client = _ct_client("us-east-1")
    us_stub = Stubber(us_client)
    trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/t1"
    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "t1", "TrailARN": trail_arn, "HomeRegion": "us-east-1"}]},
        {"includeShadowTrails": True},
    )
    us_stub.add_response(
        "get_event_selectors",
        {"TrailARN": trail_arn, "EventSelectors": [{"ReadWriteType": "All", "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}]},
        {"TrailName": trail_arn},
    )
    us_stub.activate()
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: us_client))

    write_findings = S3DataEventsWriteCheck().execute(ctx)
    assert write_findings[0].status == Status.PASS
    us_stub.deactivate()


def test_s3_data_events_write_advanced_selector_write_only():
    us_client = _ct_client("us-east-1")
    us_stub = Stubber(us_client)
    trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/t1"
    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "t1", "TrailARN": trail_arn, "HomeRegion": "us-east-1"}]},
        {"includeShadowTrails": True},
    )
    us_stub.add_response(
        "get_event_selectors",
        {
            "TrailARN": trail_arn,
            "AdvancedEventSelectors": [
                {
                    "Name": "S3WriteOnly",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Data"]},
                        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                        {"Field": "readOnly", "Equals": ["false"]},
                    ],
                }
            ],
        },
        {"TrailName": trail_arn},
    )
    us_stub.activate()
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: us_client))

    write_findings = S3DataEventsWriteCheck().execute(ctx)
    assert write_findings[0].status == Status.PASS
    us_stub.deactivate()


def test_s3_data_events_read_fails_when_only_write_covered():
    us_client = _ct_client("us-east-1")
    us_stub = Stubber(us_client)
    trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/t1"
    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "t1", "TrailARN": trail_arn, "HomeRegion": "us-east-1"}]},
        {"includeShadowTrails": True},
    )
    us_stub.add_response(
        "get_event_selectors",
        {"TrailARN": trail_arn, "EventSelectors": [{"ReadWriteType": "WriteOnly", "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}]},
        {"TrailName": trail_arn},
    )
    us_stub.activate()
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: us_client))

    read_findings = S3DataEventsReadCheck().execute(ctx)
    assert read_findings[0].status == Status.FAIL
    us_stub.deactivate()


def test_s3_data_events_no_selectors_is_fail():
    us_client = _ct_client("us-east-1")
    us_stub = Stubber(us_client)
    trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/t1"
    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "t1", "TrailARN": trail_arn, "HomeRegion": "us-east-1"}]},
        {"includeShadowTrails": True},
    )
    us_stub.add_response("get_event_selectors", {"TrailARN": trail_arn, "EventSelectors": []}, {"TrailName": trail_arn})
    us_stub.activate()
    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: us_client))

    findings = S3DataEventsWriteCheck().execute(ctx)
    assert findings[0].status == Status.FAIL
    us_stub.deactivate()


def test_multiregion_trail_not_logging_is_fail():
    us_client = _ct_client("us-east-1")
    us_stub = Stubber(us_client)
    trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/inactive"
    us_stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "inactive", "TrailARN": trail_arn, "IsMultiRegionTrail": True, "HomeRegion": "us-east-1"}]},
        {"includeShadowTrails": True},
    )
    us_stub.add_response("get_trail_status", {"IsLogging": False}, {"Name": trail_arn})
    us_stub.activate()

    ctx = SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: us_client))

    findings = MultiRegionTrailLoggingCheck().execute(ctx)

    assert findings[0].status == Status.FAIL
    us_stub.deactivate()
