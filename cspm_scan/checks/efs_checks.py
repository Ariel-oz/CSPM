from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import BaseCheck, register_check


def _error_finding(meta: CheckMeta, error_code: str, message: str, region: str) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=Status.ERROR,
        resource_id="n/a",
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
        check_id="efs_001_filesystem_unencrypted",
        title="EFS file system is not encrypted at rest",
        service="efs",
        severity=Severity.MEDIUM,
        description="An EFS file system does not have encryption at rest enabled.",
        remediation="Encryption can only be set at creation - create a new encrypted file system and migrate data (e.g. via AWS DataSync), then retire the unencrypted one.",
        references=["https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html"],
        required_actions=["elasticfilesystem:DescribeFileSystems"],
        scope="region",
        cis_benchmarks=["2.4.1"],
    )
)
class EfsFilesystemUnencryptedCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        efs = ctx.session_factory.client("efs", region)

        findings = []
        try:
            paginator = efs.get_paginator("describe_file_systems")
            for page in paginator.paginate():
                for fs in page.get("FileSystems", []):
                    status = Status.PASS if fs.get("Encrypted") else Status.FAIL
                    findings.append(_finding(meta, status, fs["FileSystemId"], region, {"encrypted": fs.get("Encrypted")}))
        except Exception as e:  # noqa: BLE001
            from botocore.exceptions import BotoCoreError, ClientError

            if isinstance(e, ClientError):
                return [_error_finding(meta, e.response["Error"]["Code"], str(e), region)]
            if isinstance(e, BotoCoreError):
                return [_error_finding(meta, type(e).__name__, str(e), region)]
            raise
        return findings
