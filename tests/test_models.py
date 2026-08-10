import json

import pytest

from cspm_scan.core.models import CheckMeta, Finding, Severity, Status


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFORMATIONAL


def test_finding_to_dict_is_json_safe():
    f = Finding(
        check_id="iam_001_root_account_mfa",
        title="Root account MFA",
        service="iam",
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        resource_id="root",
        region="global",
        description="desc",
        remediation="fix it",
    )
    d = f.to_dict()
    json.dumps(d)  # must not raise
    assert d["severity"] == "CRITICAL"
    assert d["status"] == "fail"
    assert isinstance(d["scanned_at"], str)


def test_check_meta_rejects_bad_scope():
    with pytest.raises(ValueError):
        CheckMeta(
            check_id="x_001_y",
            title="t",
            service="x",
            severity=Severity.LOW,
            description="d",
            remediation="r",
            references=[],
            required_actions=[],
            scope="bogus",
            cis_benchmarks=[],
        )
