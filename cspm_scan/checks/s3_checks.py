from cspm_scan.core.engine import safe_call
from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import BaseCheck, register_check

_LOCATION_CONSTRAINT_TO_REGION = {
    None: "us-east-1",
    "": "us-east-1",
    "EU": "eu-west-1",
}

_PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
_PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def resolve_bucket_region(s3_global_client, bucket_name: str) -> str | tuple[None, tuple[str, str]]:
    """Every per-bucket S3 call after ListBuckets must use a client built for the
    bucket's own region (from GetBucketLocation), or AWS returns PermanentRedirect."""
    result, error = safe_call(s3_global_client.get_bucket_location, Bucket=bucket_name)
    if error:
        return None, error
    constraint = result.get("LocationConstraint")
    return _LOCATION_CONSTRAINT_TO_REGION.get(constraint, constraint), None


def _list_buckets(ctx):
    """Yields (bucket_name, region, regional_s3_client) for every bucket, or an
    (bucket_name, None, error) tuple if region resolution failed for that bucket."""
    s3_global = ctx.session_factory.client("s3", "us-east-1")
    result, error = safe_call(s3_global.list_buckets)
    if error:
        return [], error

    entries = []
    for bucket in result.get("Buckets", []):
        name = bucket["Name"]
        region, region_error = resolve_bucket_region(s3_global, name)
        if region_error:
            entries.append((name, None, region_error))
            continue
        regional_client = ctx.session_factory.client("s3", region)
        entries.append((name, region, regional_client))
    return entries, None


def _error_finding(meta: CheckMeta, error_code: str, message: str, resource_id: str) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=Status.ERROR,
        resource_id=resource_id,
        region="unknown",
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        error_code=error_code,
        evidence={"message": message},
    )


def _finding(meta: CheckMeta, status: Status, resource_id: str, region: str, evidence: dict) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=status,
        resource_id=resource_id,
        region=region,
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        evidence=evidence,
    )


def _get_public_access_block(client, **kwargs) -> tuple[dict | None, tuple[str, str] | None]:
    result, error = safe_call(client.get_public_access_block, **kwargs)
    if error and error[0] == "NoSuchPublicAccessBlockConfiguration":
        return None, None  # not configured is a finding, not an error
    if error:
        return None, error
    return result["PublicAccessBlockConfiguration"], None


def _pab_fully_blocks_public_access(pab: dict | None) -> bool:
    if not pab:
        return False
    return all(pab.get(flag) for flag in _PAB_FLAGS)


@register_check(
    CheckMeta(
        check_id="s3_001_bucket_public_access",
        title="S3 bucket is publicly accessible",
        service="s3",
        severity=Severity.CRITICAL,
        description=(
            "An S3 bucket grants public access via its ACL or bucket policy, and is not fully "
            "protected by a Public Access Block configuration."
        ),
        remediation=(
            "Remove public grants from the bucket ACL and bucket policy, and enable all four Block "
            "Public Access settings at the bucket or account level."
        ),
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        required_actions=[
            "s3:ListAllMyBuckets",
            "s3:GetBucketLocation",
            "s3:GetBucketAcl",
            "s3:GetBucketPolicyStatus",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetAccountPublicAccessBlock",
        ],
        scope="account",
        cis_benchmarks=["2.1.4"],
    )
)
class BucketPublicAccessCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        buckets, list_error = _list_buckets(ctx)
        if list_error:
            return [_error_finding(meta, list_error[0], list_error[1], "s3")]

        s3control = ctx.session_factory.client("s3control", "us-east-1")
        account_pab, account_pab_error = _get_public_access_block(s3control, AccountId=ctx.account_id)
        if account_pab_error:
            return [_error_finding(meta, account_pab_error[0], account_pab_error[1], "account")]

        findings = []
        for name, bucket_region, client_or_error in buckets:
            if bucket_region is None:
                error = client_or_error
                findings.append(_error_finding(meta, error[0], error[1], name))
                continue
            client = client_or_error

            bucket_pab, bucket_pab_error = _get_public_access_block(client, Bucket=name)
            if bucket_pab_error:
                findings.append(_error_finding(meta, bucket_pab_error[0], bucket_pab_error[1], name))
                continue

            acl, acl_error = safe_call(client.get_bucket_acl, Bucket=name)
            if acl_error:
                findings.append(_error_finding(meta, acl_error[0], acl_error[1], name))
                continue
            public_grants = [
                g for g in acl.get("Grants", []) if g.get("Grantee", {}).get("URI") in _PUBLIC_GRANTEE_URIS
            ]

            policy_status, policy_error = safe_call(client.get_bucket_policy_status, Bucket=name)
            if policy_error and policy_error[0] != "NoSuchBucketPolicy":
                findings.append(_error_finding(meta, policy_error[0], policy_error[1], name))
                continue
            policy_is_public = bool(policy_status and policy_status["PolicyStatus"]["IsPublic"]) if policy_status else False

            blocked = _pab_fully_blocks_public_access(bucket_pab) or _pab_fully_blocks_public_access(account_pab)
            is_public = (bool(public_grants) or policy_is_public) and not blocked

            status = Status.FAIL if is_public else Status.PASS
            findings.append(
                _finding(
                    meta,
                    status,
                    name,
                    bucket_region,
                    {
                        "public_acl_grants": public_grants,
                        "policy_is_public": policy_is_public,
                        "bucket_public_access_block": bucket_pab,
                        "account_public_access_block": account_pab,
                    },
                )
            )
        return findings


@register_check(
    CheckMeta(
        check_id="s3_002_bucket_encryption",
        title="S3 bucket has no default encryption configured",
        service="s3",
        severity=Severity.MEDIUM,
        description="An S3 bucket has no default server-side encryption (SSE-S3 or SSE-KMS) configured.",
        remediation="In S3 > <bucket> > Properties > Default encryption, enable SSE-S3 or SSE-KMS.",
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"],
        required_actions=["s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetEncryptionConfiguration"],
        scope="account",
        cis_benchmarks=[],  # no CIS v3.0.0 control for default encryption (2.1.1 was reassigned to deny-HTTP at v3.0.0)
    )
)
class BucketEncryptionCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        buckets, list_error = _list_buckets(ctx)
        if list_error:
            return [_error_finding(meta, list_error[0], list_error[1], "s3")]

        findings = []
        for name, bucket_region, client_or_error in buckets:
            if bucket_region is None:
                findings.append(_error_finding(meta, client_or_error[0], client_or_error[1], name))
                continue
            client = client_or_error

            result, error = safe_call(client.get_bucket_encryption, Bucket=name)
            if error and error[0] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(_finding(meta, Status.FAIL, name, bucket_region, {"encrypted": False}))
                continue
            if error:
                findings.append(_error_finding(meta, error[0], error[1], name))
                continue

            rules = result["ServerSideEncryptionConfiguration"]["Rules"]
            findings.append(_finding(meta, Status.PASS, name, bucket_region, {"encrypted": True, "rules": rules}))
        return findings


@register_check(
    CheckMeta(
        check_id="s3_003_bucket_versioning",
        title="S3 bucket does not have versioning enabled",
        service="s3",
        severity=Severity.LOW,
        description="An S3 bucket does not have versioning enabled, making accidental deletion/overwrite unrecoverable.",
        remediation="In S3 > <bucket> > Properties > Bucket Versioning, choose Enable.",
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"],
        required_actions=["s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketVersioning"],
        scope="account",
        cis_benchmarks=[],  # no CIS v3.0.0 control for bucket versioning
    )
)
class BucketVersioningCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        buckets, list_error = _list_buckets(ctx)
        if list_error:
            return [_error_finding(meta, list_error[0], list_error[1], "s3")]

        findings = []
        for name, bucket_region, client_or_error in buckets:
            if bucket_region is None:
                findings.append(_error_finding(meta, client_or_error[0], client_or_error[1], name))
                continue
            client = client_or_error

            result, error = safe_call(client.get_bucket_versioning, Bucket=name)
            if error:
                findings.append(_error_finding(meta, error[0], error[1], name))
                continue

            status = Status.PASS if result.get("Status") == "Enabled" else Status.FAIL
            findings.append(_finding(meta, status, name, bucket_region, {"versioning_status": result.get("Status")}))
        return findings


@register_check(
    CheckMeta(
        check_id="s3_004_bucket_logging",
        title="S3 bucket does not have access logging enabled",
        service="s3",
        severity=Severity.LOW,
        description="An S3 bucket has no server access logging configured, limiting audit visibility into requests.",
        remediation="In S3 > <bucket> > Properties > Server access logging, enable logging to a target bucket.",
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"],
        required_actions=["s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketLogging"],
        scope="account",
        cis_benchmarks=[],  # general hygiene on every bucket; CIS 3.4 is a narrower, different check (see cloudtrail_002)
    )
)
class BucketLoggingCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        buckets, list_error = _list_buckets(ctx)
        if list_error:
            return [_error_finding(meta, list_error[0], list_error[1], "s3")]

        findings = []
        for name, bucket_region, client_or_error in buckets:
            if bucket_region is None:
                findings.append(_error_finding(meta, client_or_error[0], client_or_error[1], name))
                continue
            client = client_or_error

            result, error = safe_call(client.get_bucket_logging, Bucket=name)
            if error:
                findings.append(_error_finding(meta, error[0], error[1], name))
                continue

            logging_enabled = "LoggingEnabled" in result
            status = Status.PASS if logging_enabled else Status.FAIL
            findings.append(_finding(meta, status, name, bucket_region, {"logging_enabled": logging_enabled}))
        return findings


def _parse_bucket_policy_document(raw: str) -> dict:
    """S3 bucket policies come back as a plain JSON string (unlike IAM's
    URL-encoded PolicyDocument fields) - just json.loads it."""
    import json

    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return {}


def _policy_statements(document: dict) -> list[dict]:
    statement = document.get("Statement", [])
    return statement if isinstance(statement, list) else [statement]


def _covers_s3_wildcard(action) -> bool:
    if isinstance(action, str):
        return action in ("*", "s3:*")
    if isinstance(action, list):
        return any(a in ("*", "s3:*") for a in action)
    return False


def _has_secure_transport_deny(document: dict) -> bool:
    for stmt in _policy_statements(document):
        if stmt.get("Effect") != "Deny":
            continue
        secure_transport = stmt.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
        if secure_transport not in ("false", False):
            continue
        if _covers_s3_wildcard(stmt.get("Action")):
            return True
    return False


@register_check(
    CheckMeta(
        check_id="s3_005_bucket_insecure_transport_policy",
        title="S3 bucket policy does not deny non-HTTPS (insecure transport) requests",
        service="s3",
        severity=Severity.MEDIUM,
        description="An S3 bucket has no bucket policy statement that denies requests made without TLS (aws:SecureTransport=false), so data in transit to/from the bucket isn't enforced to be encrypted.",
        remediation=(
            "Add a bucket policy statement with Effect=Deny, Principal=*, Action=s3:*, and a "
            "Condition of {\"Bool\": {\"aws:SecureTransport\": \"false\"}} covering the bucket and its objects."
        ),
        references=[
            "https://aws.amazon.com/blogs/security/how-to-use-bucket-policies-and-apply-defense-in-depth-to-help-secure-your-amazon-s3-data/"
        ],
        required_actions=["s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketPolicy"],
        scope="account",
        cis_benchmarks=["2.1.1"],
    )
)
class BucketInsecureTransportPolicyCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        buckets, list_error = _list_buckets(ctx)
        if list_error:
            return [_error_finding(meta, list_error[0], list_error[1], "s3")]

        findings = []
        for name, bucket_region, client_or_error in buckets:
            if bucket_region is None:
                findings.append(_error_finding(meta, client_or_error[0], client_or_error[1], name))
                continue
            client = client_or_error

            result, error = safe_call(client.get_bucket_policy, Bucket=name)
            if error and error[0] == "NoSuchBucketPolicy":
                findings.append(_finding(meta, Status.FAIL, name, bucket_region, {"reason": "no bucket policy configured"}))
                continue
            if error:
                findings.append(_error_finding(meta, error[0], error[1], name))
                continue

            document = _parse_bucket_policy_document(result["Policy"])
            enforced = _has_secure_transport_deny(document)
            status = Status.PASS if enforced else Status.FAIL
            findings.append(_finding(meta, status, name, bucket_region, {"secure_transport_enforced": enforced}))
        return findings


@register_check(
    CheckMeta(
        check_id="s3_006_bucket_mfa_delete_disabled",
        title="S3 bucket does not have MFA Delete enabled",
        service="s3",
        severity=Severity.MEDIUM,
        description="An S3 bucket does not have MFA Delete enabled, so a compromised or careless set of credentials (without an MFA code) can permanently delete object versions.",
        remediation=(
            "Using the root user's credentials and MFA device, run: aws s3api put-bucket-versioning "
            "--bucket <bucket> --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa \"<serial> <code>\"."
        ),
        references=["https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete"],
        required_actions=["s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketVersioning"],
        scope="account",
        cis_benchmarks=["2.1.2"],
    )
)
class BucketMfaDeleteDisabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        buckets, list_error = _list_buckets(ctx)
        if list_error:
            return [_error_finding(meta, list_error[0], list_error[1], "s3")]

        findings = []
        for name, bucket_region, client_or_error in buckets:
            if bucket_region is None:
                findings.append(_error_finding(meta, client_or_error[0], client_or_error[1], name))
                continue
            client = client_or_error

            result, error = safe_call(client.get_bucket_versioning, Bucket=name)
            if error:
                findings.append(_error_finding(meta, error[0], error[1], name))
                continue

            mfa_delete = result.get("MFADelete")
            status = Status.PASS if mfa_delete == "Enabled" else Status.FAIL
            findings.append(_finding(meta, status, name, bucket_region, {"mfa_delete": mfa_delete}))
        return findings
