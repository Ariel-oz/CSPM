from cspm_scan.core.engine import safe_call
from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import BaseCheck, register_check


def _error_finding(meta: CheckMeta, error_code: str, message: str, resource_id: str, region: str) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=Status.ERROR,
        resource_id=resource_id,
        region=region,
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


@register_check(
    CheckMeta(
        check_id="kms_001_cmk_rotation_disabled",
        title="Customer-managed KMS key does not have automatic key rotation enabled",
        service="kms",
        severity=Severity.LOW,
        description="A customer-managed, symmetric-encryption KMS key does not have annual automatic key rotation enabled.",
        remediation="In KMS > Customer managed keys > <key> > Key rotation, enable automatic key rotation.",
        references=["https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"],
        required_actions=["kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus"],
        scope="region",
        cis_benchmarks=["3.6"],
    )
)
class KmsCmkRotationDisabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        kms = ctx.session_factory.client("kms", region)

        key_ids = []
        try:
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                key_ids.extend(k["KeyId"] for k in page.get("Keys", []))
        except Exception as e:  # noqa: BLE001
            from botocore.exceptions import BotoCoreError, ClientError

            if isinstance(e, ClientError):
                return [_error_finding(meta, e.response["Error"]["Code"], str(e), "account", region)]
            if isinstance(e, BotoCoreError):
                return [_error_finding(meta, type(e).__name__, str(e), "account", region)]
            raise

        findings = []
        for key_id in key_ids:
            metadata_result, error = safe_call(kms.describe_key, KeyId=key_id)
            if error:
                findings.append(_error_finding(meta, error[0], error[1], key_id, region))
                continue

            metadata = metadata_result["KeyMetadata"]
            if metadata.get("KeyManager") != "CUSTOMER" or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT":
                continue  # AWS-managed keys and asymmetric/HMAC keys don't support rotation the same way, out of scope

            rotation_result, error = safe_call(kms.get_key_rotation_status, KeyId=key_id)
            if error:
                findings.append(_error_finding(meta, error[0], error[1], key_id, region))
                continue

            enabled = rotation_result.get("KeyRotationEnabled", False)
            status = Status.PASS if enabled else Status.FAIL
            findings.append(_finding(meta, status, key_id, region, {"key_rotation_enabled": enabled}))
        return findings
