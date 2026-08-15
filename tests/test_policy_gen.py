from cspm_scan.core.models import CheckMeta, Severity
from cspm_scan.core.policy_gen import BASELINE_ACTIONS, build_policy
from cspm_scan.core.registry import CHECK_REGISTRY, BaseCheck, register_check


def test_build_policy_includes_baseline_and_check_actions():
    check_id = "test_900_policy_gen"
    try:

        @register_check(
            CheckMeta(
                check_id=check_id,
                title="t",
                service="s3",
                severity=Severity.LOW,
                description="d",
                remediation="r",
                references=[],
                required_actions=["s3:GetBucketAcl", "s3:GetBucketPolicy"],
                scope="account",
                cis_benchmarks=[],
            )
        )
        class _Check(BaseCheck):
            def execute(self, ctx, region=None):
                return []

        policy = build_policy()
        assert policy["Version"] == "2012-10-17"
        sids = {s["Sid"]: s for s in policy["Statement"]}
        assert "S3READONLY" in sids
        assert "s3:GetBucketAcl" in sids["S3READONLY"]["Action"]
        assert "s3:GetBucketPolicy" in sids["S3READONLY"]["Action"]
        for action in BASELINE_ACTIONS:
            prefix, _ = action.split(":")
            assert action in sids[f"{prefix.upper()}READONLY"]["Action"]
    finally:
        CHECK_REGISTRY.pop(check_id, None)
