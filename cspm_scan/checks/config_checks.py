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
        check_id="config_001_recorder_not_enabled",
        title="AWS Config recorder is not enabled or not recording successfully",
        service="config",
        severity=Severity.MEDIUM,
        description="This region has no AWS Config configuration recorder, or the recorder exists but is not actively recording, or its last delivery status was not successful.",
        remediation="In the AWS Config console for this region, set up a configuration recorder covering all resources (and global resources in one region), and confirm delivery to an S3 bucket.",
        references=["https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"],
        required_actions=["config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus"],
        scope="region",
        cis_benchmarks=["3.3"],
    )
)
class ConfigRecorderNotEnabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        client = ctx.session_factory.client("config", region)

        recorders_result, error = safe_call(client.describe_configuration_recorders)
        if error:
            return [_error_finding(meta, error[0], error[1], region)]

        recorders = recorders_result.get("ConfigurationRecorders", [])
        if not recorders:
            return [_finding(meta, Status.FAIL, "account", region, {"reason": "no configuration recorder exists"})]

        status_result, error = safe_call(client.describe_configuration_recorder_status)
        if error:
            return [_error_finding(meta, error[0], error[1], region)]

        status_by_name = {s["name"]: s for s in status_result.get("ConfigurationRecordersStatus", [])}

        findings = []
        for recorder in recorders:
            name = recorder["name"]
            recorder_status = status_by_name.get(name, {})
            is_recording = bool(recorder_status.get("recording"))
            last_status_ok = recorder_status.get("lastStatus") in ("SUCCESS", None)
            healthy = is_recording and last_status_ok
            status = Status.PASS if healthy else Status.FAIL
            findings.append(
                _finding(
                    meta,
                    status,
                    name,
                    region,
                    {"recording": is_recording, "last_status": recorder_status.get("lastStatus")},
                )
            )
        return findings
