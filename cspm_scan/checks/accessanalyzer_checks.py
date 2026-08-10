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


@register_check(
    CheckMeta(
        check_id="accessanalyzer_001_not_enabled",
        title="IAM Access Analyzer is not enabled in this region",
        service="accessanalyzer",
        severity=Severity.MEDIUM,
        description="No active IAM Access Analyzer (account-level) was found in this region, so unintended cross-account/public resource access isn't being surfaced.",
        remediation="In IAM > Access Analyzer, create an analyzer with zone of trust 'This account' for this region.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html"],
        required_actions=["access-analyzer:ListAnalyzers"],
        scope="region",
        cis_benchmarks=["1.20"],
    )
)
class AccessAnalyzerNotEnabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        client = ctx.session_factory.client("accessanalyzer", region)

        analyzers = []
        try:
            paginator = client.get_paginator("list_analyzers")
            for page in paginator.paginate(type="ACCOUNT"):
                analyzers.extend(page.get("analyzers", []))
        except Exception as e:  # noqa: BLE001
            from botocore.exceptions import BotoCoreError, ClientError

            if isinstance(e, ClientError):
                return [_error_finding(meta, e.response["Error"]["Code"], str(e), region)]
            if isinstance(e, BotoCoreError):
                return [_error_finding(meta, type(e).__name__, str(e), region)]
            raise

        active = [a for a in analyzers if a.get("status") == "ACTIVE"]
        status = Status.PASS if active else Status.FAIL
        return [_finding(meta, status, region, {"analyzer_count": len(analyzers), "active_analyzer_count": len(active)})]
