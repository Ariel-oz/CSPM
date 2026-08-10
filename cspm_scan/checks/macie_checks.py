from cspm_scan.core.engine import safe_call
from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import BaseCheck, register_check

def _is_service_not_enabled(error_code: str, message: str) -> bool:
    """Macie overloads AccessDeniedException for two unrelated cases with the same
    error code: a genuine IAM permission denial (message contains "is not authorized
    to perform") vs. the service simply being disabled in this region (message says
    "Macie is not enabled" - confirmed via AWS's own Macie API documentation).
    Only the latter is a real FAIL; treat anything else as ERROR (safer default)."""
    if error_code != "AccessDeniedException":
        return False
    return "is not enabled" in message.lower() and "is not authorized to perform" not in message


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


@register_check(
    CheckMeta(
        check_id="macie_001_not_enabled",
        title="Amazon Macie is not enabled in this region",
        service="macie2",
        severity=Severity.LOW,
        description=(
            "Amazon Macie is not enabled in this region, so automated discovery/classification of "
            "sensitive data in S3 is not running. Note: this only proves the service is on, not that "
            "any data has actually been classified - CIS marks the underlying control Manual for that reason."
        ),
        remediation="In the Macie console for this region, choose Enable Macie and configure a discovery-results bucket.",
        references=["https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html"],
        required_actions=["macie2:GetMacieSession"],
        scope="region",
        cis_benchmarks=["2.1.3"],
    )
)
class MacieNotEnabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        client = ctx.session_factory.client("macie2", region)
        result, error = safe_call(client.get_macie_session)
        if error:
            if _is_service_not_enabled(error[0], error[1]):
                return [_finding(meta, Status.FAIL, region, {"reason": "Macie not enabled in this region"})]
            return [_error_finding(meta, error[0], error[1], region)]

        status = Status.PASS if result.get("status") == "ENABLED" else Status.FAIL
        return [_finding(meta, status, region, {"macie_status": result.get("status")})]
