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
        resource_id="account",
        region=region,
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        error_code=error_code,
        evidence={"message": message},
    )


def _finding(meta: CheckMeta, status: Status, region: str, evidence: dict) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=status,
        resource_id="account",
        region=region,
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        evidence=evidence,
    )


# Security Hub raises this specific ClientError code (via the shared "InvalidAccessException"
# error type) when the account has never enabled the service in this region - that's a real
# FAIL finding (not enabled), never an ERROR.
_NOT_SUBSCRIBED_ERROR_CODES = {"InvalidAccessException"}


@register_check(
    CheckMeta(
        check_id="securityhub_001_not_enabled",
        title="AWS Security Hub is not enabled in this region",
        service="securityhub",
        severity=Severity.MEDIUM,
        description="AWS Security Hub is not enabled in this region, so aggregated security findings and standards checks aren't available.",
        remediation="In the Security Hub console for this region, choose Enable Security Hub and select the standards you want to enable.",
        references=["https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-get-started.html"],
        required_actions=["securityhub:DescribeHub"],
        scope="region",
        cis_benchmarks=["4.16"],
    )
)
class SecurityHubNotEnabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        client = ctx.session_factory.client("securityhub", region)
        result, error = safe_call(client.describe_hub)
        if error:
            if error[0] in _NOT_SUBSCRIBED_ERROR_CODES:
                return [_finding(meta, Status.FAIL, region, {"reason": "Security Hub not enabled in this region"})]
            return [_error_finding(meta, error[0], error[1], region)]

        status = Status.PASS if result.get("HubArn") else Status.FAIL
        return [_finding(meta, status, region, {"hub_arn": result.get("HubArn")})]
