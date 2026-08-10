from cspm_scan.checks.s3_checks import resolve_bucket_region
from cspm_scan.core.engine import safe_call
from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import BaseCheck, register_check


def _error_finding(meta: CheckMeta, error_code: str, message: str, resource_id: str = "account") -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=Status.ERROR,
        resource_id=resource_id,
        region="global",
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        error_code=error_code,
        evidence={"message": message},
    )


def _finding(meta: CheckMeta, status: Status, resource_id: str, evidence: dict) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=status,
        resource_id=resource_id,
        region="global",
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        evidence=evidence,
    )


def _list_deduped_trails(ctx) -> tuple[list[dict], tuple[str, str] | None]:
    """describe_trails returns shadow copies of multi-region trails in every
    region's response - dedupe by TrailARN before evaluating anything."""
    cloudtrail = ctx.session_factory.client("cloudtrail", "us-east-1")
    result, error = safe_call(cloudtrail.describe_trails, includeShadowTrails=True)
    if error:
        return [], error
    trails_by_arn = {t["TrailARN"]: t for t in result.get("trailList", [])}
    return list(trails_by_arn.values()), None


@register_check(
    CheckMeta(
        check_id="cloudtrail_001_multiregion_trail_logging",
        title="No multi-region CloudTrail trail is actively logging",
        service="cloudtrail",
        severity=Severity.HIGH,
        description="The account has no CloudTrail trail that is both multi-region and currently logging.",
        remediation="In CloudTrail > Trails, create (or fix) a trail with 'Apply trail to all regions' enabled, and confirm logging is turned on.",
        references=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"],
        required_actions=["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
        scope="account",
        cis_benchmarks=["3.1"],
    )
)
class MultiRegionTrailLoggingCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        trails, error = _list_deduped_trails(ctx)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        evaluated = []
        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                continue
            home_client = ctx.session_factory.client("cloudtrail", trail["HomeRegion"])
            status_result, status_error = safe_call(home_client.get_trail_status, Name=trail["TrailARN"])
            if status_error:
                return [_error_finding(meta, status_error[0], status_error[1])]
            evaluated.append(
                {
                    "name": trail.get("Name"),
                    "arn": trail["TrailARN"],
                    "home_region": trail["HomeRegion"],
                    "is_logging": status_result.get("IsLogging", False),
                }
            )

        any_logging = any(t["is_logging"] for t in evaluated)
        status = Status.PASS if any_logging else Status.FAIL
        return [_finding(meta, status, "account", {"multiregion_trails": evaluated})]


@register_check(
    CheckMeta(
        check_id="cloudtrail_002_s3_bucket_access_logging",
        title="The S3 bucket receiving CloudTrail logs does not have access logging enabled",
        service="cloudtrail",
        severity=Severity.MEDIUM,
        description=(
            "The S3 bucket that a CloudTrail trail delivers logs to does not itself have server access "
            "logging enabled, reducing audit visibility into who accessed the CloudTrail log archive."
        ),
        remediation="In S3, select the CloudTrail delivery bucket, Properties > Server access logging, and enable logging to a separate target bucket.",
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"],
        required_actions=["cloudtrail:DescribeTrails", "s3:GetBucketLocation", "s3:GetBucketLogging"],
        scope="account",
        cis_benchmarks=["3.4"],
    )
)
class TrailBucketAccessLoggingCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        trails, error = _list_deduped_trails(ctx)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        s3_global = ctx.session_factory.client("s3", "us-east-1")
        seen_buckets: set[str] = set()
        findings = []
        for trail in trails:
            bucket_name = trail.get("S3BucketName")
            if not bucket_name or bucket_name in seen_buckets:
                continue
            seen_buckets.add(bucket_name)

            bucket_region, region_error = resolve_bucket_region(s3_global, bucket_name)
            if region_error:
                findings.append(_error_finding(meta, region_error[0], region_error[1], bucket_name))
                continue

            s3_regional = ctx.session_factory.client("s3", bucket_region)
            result, log_error = safe_call(s3_regional.get_bucket_logging, Bucket=bucket_name)
            if log_error:
                findings.append(_error_finding(meta, log_error[0], log_error[1], bucket_name))
                continue

            logging_enabled = "LoggingEnabled" in result
            status = Status.PASS if logging_enabled else Status.FAIL
            findings.append(_finding(meta, status, bucket_name, {"logging_enabled": logging_enabled}))
        return findings


@register_check(
    CheckMeta(
        check_id="cloudtrail_003_log_file_validation_disabled",
        title="CloudTrail trail does not have log file validation enabled",
        service="cloudtrail",
        severity=Severity.MEDIUM,
        description="A CloudTrail trail does not have log file integrity validation enabled, making tampering with delivered log files harder to detect.",
        remediation="In CloudTrail > Trails > <trail> > General details, enable 'Log file validation'.",
        references=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html"],
        required_actions=["cloudtrail:DescribeTrails"],
        scope="account",
        cis_benchmarks=["3.2"],
    )
)
class LogFileValidationDisabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        trails, error = _list_deduped_trails(ctx)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        findings = []
        for trail in trails:
            status = Status.PASS if trail.get("LogFileValidationEnabled") else Status.FAIL
            findings.append(
                _finding(meta, status, trail["TrailARN"], {"log_file_validation_enabled": trail.get("LogFileValidationEnabled")})
            )
        return findings


@register_check(
    CheckMeta(
        check_id="cloudtrail_004_kms_encryption_disabled",
        title="CloudTrail trail is not encrypted with a KMS key",
        service="cloudtrail",
        severity=Severity.MEDIUM,
        description="A CloudTrail trail's log files are not encrypted with a customer-managed KMS key (SSE-KMS), relying only on default S3 encryption.",
        remediation="In CloudTrail > Trails > <trail> > S3, enable SSE-KMS encryption and select or create a CMK.",
        references=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html"],
        required_actions=["cloudtrail:DescribeTrails"],
        scope="account",
        cis_benchmarks=["3.5"],
    )
)
class KmsEncryptionDisabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        trails, error = _list_deduped_trails(ctx)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        findings = []
        for trail in trails:
            has_kms = bool(trail.get("KmsKeyId"))
            status = Status.PASS if has_kms else Status.FAIL
            findings.append(_finding(meta, status, trail["TrailARN"], {"kms_key_id": trail.get("KmsKeyId")}))
        return findings


def _s3_data_event_coverage(event_selectors_result: dict) -> tuple[bool, bool]:
    """Returns (write_covered, read_covered) for S3 object-level data events,
    checking both the legacy EventSelectors shape and the modern AdvancedEventSelectors
    shape (which trails created via the console/newer APIs use exclusively)."""
    write_covered = False
    read_covered = False

    for sel in event_selectors_result.get("EventSelectors", []):
        for dr in sel.get("DataResources", []):
            if dr.get("Type") != "AWS::S3::Object":
                continue
            rwt = sel.get("ReadWriteType", "All")
            write_covered = write_covered or rwt in ("All", "WriteOnly")
            read_covered = read_covered or rwt in ("All", "ReadOnly")

    for asel in event_selectors_result.get("AdvancedEventSelectors", []):
        field_selectors = asel.get("FieldSelectors", [])
        matches_s3 = any(
            fs.get("Field") == "resources.type" and "AWS::S3::Object" in (fs.get("Equals") or [])
            for fs in field_selectors
        )
        if not matches_s3:
            continue
        readonly_fs = next((fs for fs in field_selectors if fs.get("Field") == "readOnly"), None)
        if readonly_fs is None:
            write_covered = True
            read_covered = True
        else:
            equals = readonly_fs.get("Equals") or []
            write_covered = write_covered or "false" in equals
            read_covered = read_covered or "true" in equals

    return write_covered, read_covered


def _evaluate_s3_data_event_coverage(ctx, trails) -> tuple[bool, bool, list[dict], tuple[str, str] | None]:
    write_covered = False
    read_covered = False
    evaluated = []
    for trail in trails:
        home_client = ctx.session_factory.client("cloudtrail", trail["HomeRegion"])
        result, error = safe_call(home_client.get_event_selectors, TrailName=trail["TrailARN"])
        if error:
            return write_covered, read_covered, evaluated, error
        trail_write, trail_read = _s3_data_event_coverage(result)
        write_covered = write_covered or trail_write
        read_covered = read_covered or trail_read
        evaluated.append({"arn": trail["TrailARN"], "s3_write_events": trail_write, "s3_read_events": trail_read})
    return write_covered, read_covered, evaluated, None


@register_check(
    CheckMeta(
        check_id="cloudtrail_005_s3_data_events_write",
        title="No CloudTrail trail logs S3 object-level write (data) events",
        service="cloudtrail",
        severity=Severity.MEDIUM,
        description=(
            "No CloudTrail trail has a data event selector capturing S3 object-level write events "
            "(PutObject, DeleteObject, etc.), so this activity isn't recorded. This check treats any "
            "data event selector scoped to AWS::S3::Object as sufficient evidence, without validating "
            "the selector's resource ARN covers every bucket you care about."
        ),
        remediation="In CloudTrail > Trails > <trail> > Data events, add an S3 data event selector covering write events (or All).",
        references=["https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html"],
        required_actions=["cloudtrail:DescribeTrails", "cloudtrail:GetEventSelectors"],
        scope="account",
        cis_benchmarks=["3.8"],
    )
)
class S3DataEventsWriteCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        trails, error = _list_deduped_trails(ctx)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        write_covered, _read_covered, evaluated, sel_error = _evaluate_s3_data_event_coverage(ctx, trails)
        if sel_error:
            return [_error_finding(meta, sel_error[0], sel_error[1])]

        status = Status.PASS if write_covered else Status.FAIL
        return [_finding(meta, status, "account", {"trails": evaluated})]


@register_check(
    CheckMeta(
        check_id="cloudtrail_006_s3_data_events_read",
        title="No CloudTrail trail logs S3 object-level read (data) events",
        service="cloudtrail",
        severity=Severity.LOW,
        description=(
            "No CloudTrail trail has a data event selector capturing S3 object-level read events "
            "(GetObject, etc.), so this activity isn't recorded. Same resource-ARN-scope caveat as "
            "cloudtrail_005 applies."
        ),
        remediation="In CloudTrail > Trails > <trail> > Data events, add an S3 data event selector covering read events (or All).",
        references=["https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html"],
        required_actions=["cloudtrail:DescribeTrails", "cloudtrail:GetEventSelectors"],
        scope="account",
        cis_benchmarks=["3.9"],
    )
)
class S3DataEventsReadCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        trails, error = _list_deduped_trails(ctx)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        _write_covered, read_covered, evaluated, sel_error = _evaluate_s3_data_event_coverage(ctx, trails)
        if sel_error:
            return [_error_finding(meta, sel_error[0], sel_error[1])]

        status = Status.PASS if read_covered else Status.FAIL
        return [_finding(meta, status, "account", {"trails": evaluated})]
