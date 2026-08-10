"""Scan orchestration: runs every registered check, contains errors so one bad
check/API call never aborts the whole scan."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from botocore.exceptions import BotoCoreError, ClientError

from .models import Finding, Status
from .registry import CHECK_REGISTRY
from .session import SessionFactory

DEFAULT_MAX_WORKERS = 8


@dataclass
class ScanContext:
    session_factory: SessionFactory
    regions: list[str]
    account_id: str


def safe_call(fn, **kwargs):
    """Call a boto3 client method; return (result, None) or (None, (error_code, message))."""
    try:
        return fn(**kwargs), None
    except ClientError as e:
        return None, (e.response["Error"]["Code"], str(e))
    except BotoCoreError as e:
        return None, (type(e).__name__, str(e))


class ScanEngine:
    def __init__(self, ctx: ScanContext, max_workers: int = DEFAULT_MAX_WORKERS):
        self.ctx = ctx
        self.max_workers = max_workers

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        checks = sorted(CHECK_REGISTRY.items())

        # Account-scoped checks run once each, sequentially - they're not the
        # concurrency bottleneck (region-scoped checks fanning out across every
        # enabled region are), and running them sequentially keeps IAM API usage
        # (which is often more aggressively throttled) predictable.
        for _, check in checks:
            if check.meta.scope == "account":
                findings.extend(self._run_one(check, region=None))

        region_tasks = [
            (check, region)
            for _, check in checks
            if check.meta.scope == "region"
            for region in self.ctx.regions
        ]
        if region_tasks:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self._run_one, check, region) for check, region in region_tasks]
                for future in as_completed(futures):
                    findings.extend(future.result())

        for f in findings:
            f.account_id = self.ctx.account_id
        return findings

    def _run_one(self, check, region: str | None) -> list[Finding]:
        meta = check.meta
        try:
            return check.execute(self.ctx, region=region)
        except Exception as e:  # noqa: BLE001 - a bug in one check must not abort the scan
            return [
                Finding(
                    check_id=meta.check_id,
                    title=meta.title,
                    service=meta.service,
                    severity=meta.severity,
                    status=Status.ERROR,
                    resource_id="n/a",
                    region=region or "global",
                    description=meta.description,
                    remediation=meta.remediation,
                    references=meta.references,
                    cis_benchmarks=meta.cis_benchmarks,
                    error_code=type(e).__name__,
                    evidence={"exception": str(e)},
                )
            ]
