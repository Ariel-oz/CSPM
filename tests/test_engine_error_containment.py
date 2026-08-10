from types import SimpleNamespace

from cspm_scan.core.engine import ScanContext, ScanEngine
from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import CHECK_REGISTRY, BaseCheck, register_check


def _ctx(regions=None):
    return ScanContext(session_factory=SimpleNamespace(), regions=regions or [], account_id="123456789012")


def test_check_that_raises_produces_single_error_finding_not_crash():
    check_id = "test_engine_001_raises"
    try:

        @register_check(
            CheckMeta(
                check_id=check_id,
                title="Always raises",
                service="test",
                severity=Severity.LOW,
                description="d",
                remediation="r",
                references=[],
                required_actions=[],
                scope="account",
                cis_benchmarks=[],
            )
        )
        class _AlwaysRaises(BaseCheck):
            def execute(self, ctx, region=None):
                raise RuntimeError("boom")

        findings = ScanEngine(_ctx()).run()

        matching = [f for f in findings if f.check_id == check_id]
        assert len(matching) == 1
        assert matching[0].status == Status.ERROR
        assert matching[0].error_code == "RuntimeError"
    finally:
        CHECK_REGISTRY.pop(check_id, None)


def test_one_bad_check_does_not_stop_others_from_running():
    bad_id = "test_engine_002_bad"
    good_id = "test_engine_003_good"
    try:

        @register_check(
            CheckMeta(
                check_id=bad_id,
                title="Bad",
                service="test",
                severity=Severity.LOW,
                description="d",
                remediation="r",
                references=[],
                required_actions=[],
                scope="account",
                cis_benchmarks=[],
            )
        )
        class _Bad(BaseCheck):
            def execute(self, ctx, region=None):
                raise ValueError("bad")

        @register_check(
            CheckMeta(
                check_id=good_id,
                title="Good",
                service="test",
                severity=Severity.LOW,
                description="d",
                remediation="r",
                references=[],
                required_actions=[],
                scope="account",
                cis_benchmarks=[],
            )
        )
        class _Good(BaseCheck):
            def execute(self, ctx, region=None):
                return [
                    Finding(
                        check_id=good_id,
                        title="Good",
                        service="test",
                        severity=Severity.LOW,
                        status=Status.PASS,
                        resource_id="x",
                        region="global",
                        description="d",
                        remediation="r",
                    )
                ]

        findings = ScanEngine(_ctx()).run()

        ids = {f.check_id for f in findings}
        assert bad_id in ids
        assert good_id in ids
        assert next(f for f in findings if f.check_id == good_id).status == Status.PASS
    finally:
        CHECK_REGISTRY.pop(bad_id, None)
        CHECK_REGISTRY.pop(good_id, None)


def test_region_scoped_check_runs_once_per_region():
    check_id = "test_engine_004_region"
    try:

        @register_check(
            CheckMeta(
                check_id=check_id,
                title="Per-region",
                service="test",
                severity=Severity.LOW,
                description="d",
                remediation="r",
                references=[],
                required_actions=[],
                scope="region",
                cis_benchmarks=[],
            )
        )
        class _PerRegion(BaseCheck):
            def execute(self, ctx, region=None):
                return [
                    Finding(
                        check_id=check_id,
                        title="Per-region",
                        service="test",
                        severity=Severity.LOW,
                        status=Status.PASS,
                        resource_id="x",
                        region=region,
                        description="d",
                        remediation="r",
                    )
                ]

        findings = ScanEngine(_ctx(regions=["us-east-1", "eu-west-1", "ap-south-1"])).run()

        matching_regions = sorted(f.region for f in findings if f.check_id == check_id)
        assert matching_regions == ["ap-south-1", "eu-west-1", "us-east-1"]
    finally:
        CHECK_REGISTRY.pop(check_id, None)


def test_account_id_stamped_on_every_finding():
    check_id = "test_engine_005_stamp"
    try:

        @register_check(
            CheckMeta(
                check_id=check_id,
                title="Stamp",
                service="test",
                severity=Severity.LOW,
                description="d",
                remediation="r",
                references=[],
                required_actions=[],
                scope="account",
                cis_benchmarks=[],
            )
        )
        class _Stamp(BaseCheck):
            def execute(self, ctx, region=None):
                return [
                    Finding(
                        check_id=check_id,
                        title="Stamp",
                        service="test",
                        severity=Severity.LOW,
                        status=Status.PASS,
                        resource_id="x",
                        region="global",
                        description="d",
                        remediation="r",
                    )
                ]

        findings = ScanEngine(_ctx()).run()

        assert all(f.account_id == "123456789012" for f in findings)
    finally:
        CHECK_REGISTRY.pop(check_id, None)
