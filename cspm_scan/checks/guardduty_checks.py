from cspm_scan.core.engine import safe_call
from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import BaseCheck, register_check


@register_check(
    CheckMeta(
        check_id="guardduty_001_detector_enabled",
        title="GuardDuty is not enabled in this region",
        service="guardduty",
        severity=Severity.MEDIUM,
        description="No enabled GuardDuty detector was found in this region, so threat detection findings are not being generated.",
        remediation="In GuardDuty, enable the service for this region (or verify the existing detector's status is ENABLED).",
        references=["https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html"],
        required_actions=["guardduty:ListDetectors", "guardduty:GetDetector"],
        scope="region",
        cis_benchmarks=[],  # GuardDuty is not part of the CIS AWS Foundations Benchmark
    )
)
class GuardDutyDetectorEnabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        gd = ctx.session_factory.client("guardduty", region)
        result, error = safe_call(gd.list_detectors)
        if error:
            return [self._error(meta, error, region)]

        detector_ids = result.get("DetectorIds", [])
        if not detector_ids:
            return [self._finding(meta, Status.FAIL, region, {"detector_ids": []})]

        detector, error = safe_call(gd.get_detector, DetectorId=detector_ids[0])
        if error:
            return [self._error(meta, error, region)]

        status = Status.PASS if detector.get("Status") == "ENABLED" else Status.FAIL
        return [
            self._finding(
                meta, status, region, {"detector_ids": detector_ids, "detector_status": detector.get("Status")}
            )
        ]

    @staticmethod
    def _error(meta: CheckMeta, error: tuple[str, str], region: str) -> Finding:
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
            error_code=error[0],
            evidence={"message": error[1]},
        )

    @staticmethod
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
