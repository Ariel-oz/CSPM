from cspm_scan.core.engine import safe_call
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
        check_id="rds_001_instance_unencrypted",
        title="RDS instance is not encrypted at rest",
        service="rds",
        severity=Severity.MEDIUM,
        description="An RDS database instance does not have storage encryption enabled.",
        remediation="Storage encryption can't be enabled on an existing instance - create an encrypted snapshot/copy and restore into a new encrypted instance.",
        references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"],
        required_actions=["rds:DescribeDBInstances"],
        scope="region",
        cis_benchmarks=["2.3.1"],
    )
)
class RdsInstanceUnencryptedCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        rds = ctx.session_factory.client("rds", region)
        result, error = safe_call(rds.describe_db_instances)
        if error:
            return [_error_finding(meta, error[0], error[1], region)]

        findings = []
        for instance in result.get("DBInstances", []):
            status = Status.PASS if instance.get("StorageEncrypted") else Status.FAIL
            findings.append(
                _finding(meta, status, instance["DBInstanceIdentifier"], region, {"storage_encrypted": instance.get("StorageEncrypted")})
            )
        return findings


@register_check(
    CheckMeta(
        check_id="rds_002_auto_minor_version_upgrade_disabled",
        title="RDS instance does not have auto minor version upgrade enabled",
        service="rds",
        severity=Severity.LOW,
        description="An RDS database instance does not have automatic minor version upgrades enabled, so it may miss security patches released in minor engine versions.",
        remediation="In the RDS console, select the instance, Modify > Maintenance, and enable 'Auto minor version upgrade'.",
        references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_RDS_Managing.html"],
        required_actions=["rds:DescribeDBInstances"],
        scope="region",
        cis_benchmarks=["2.3.2"],
    )
)
class RdsAutoMinorVersionUpgradeDisabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        rds = ctx.session_factory.client("rds", region)
        result, error = safe_call(rds.describe_db_instances)
        if error:
            return [_error_finding(meta, error[0], error[1], region)]

        findings = []
        for instance in result.get("DBInstances", []):
            status = Status.PASS if instance.get("AutoMinorVersionUpgrade") else Status.FAIL
            findings.append(
                _finding(
                    meta,
                    status,
                    instance["DBInstanceIdentifier"],
                    region,
                    {"auto_minor_version_upgrade": instance.get("AutoMinorVersionUpgrade")},
                )
            )
        return findings


@register_check(
    CheckMeta(
        check_id="rds_003_publicly_accessible",
        title="RDS instance is publicly accessible",
        service="rds",
        severity=Severity.CRITICAL,
        description="An RDS database instance has PubliclyAccessible enabled, exposing it to connections from the internet rather than only within its VPC.",
        remediation="In the RDS console, select the instance, Modify > Connectivity, and set 'Public access' to No.",
        references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"],
        required_actions=["rds:DescribeDBInstances"],
        scope="region",
        cis_benchmarks=["2.3.3"],
    )
)
class RdsPubliclyAccessibleCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        rds = ctx.session_factory.client("rds", region)
        result, error = safe_call(rds.describe_db_instances)
        if error:
            return [_error_finding(meta, error[0], error[1], region)]

        findings = []
        for instance in result.get("DBInstances", []):
            status = Status.FAIL if instance.get("PubliclyAccessible") else Status.PASS
            findings.append(
                _finding(meta, status, instance["DBInstanceIdentifier"], region, {"publicly_accessible": instance.get("PubliclyAccessible")})
            )
        return findings
