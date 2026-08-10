import pytest

from cspm_scan.core.models import CheckMeta, Severity
from cspm_scan.core.registry import CHECK_REGISTRY, BaseCheck, register_check


def _meta(check_id):
    return CheckMeta(
        check_id=check_id,
        title="t",
        service="x",
        severity=Severity.LOW,
        description="d",
        remediation="r",
        references=[],
        required_actions=["x:Describe"],
        scope="account",
        cis_benchmarks=[],
    )


def test_register_check_adds_to_registry():
    check_id = "test_001_registers"
    try:

        @register_check(_meta(check_id))
        class _MyCheck(BaseCheck):
            def execute(self, ctx, region=None):
                return []

        assert check_id in CHECK_REGISTRY
        assert isinstance(CHECK_REGISTRY[check_id], _MyCheck)
    finally:
        CHECK_REGISTRY.pop(check_id, None)


def test_duplicate_check_id_raises():
    check_id = "test_002_dup"
    try:

        @register_check(_meta(check_id))
        class _First(BaseCheck):
            def execute(self, ctx, region=None):
                return []

        with pytest.raises(ValueError):

            @register_check(_meta(check_id))
            class _Second(BaseCheck):
                def execute(self, ctx, region=None):
                    return []
    finally:
        CHECK_REGISTRY.pop(check_id, None)
