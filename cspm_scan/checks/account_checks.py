from cspm_scan.core.engine import safe_call
from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import BaseCheck, register_check


def _error_finding(meta: CheckMeta, error_code: str, message: str) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=Status.ERROR,
        resource_id="account",
        region="global",
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        error_code=error_code,
        evidence={"message": message},
    )


def _finding(meta: CheckMeta, status: Status, evidence: dict) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=status,
        resource_id="account",
        region="global",
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        evidence=evidence,
    )


@register_check(
    CheckMeta(
        check_id="account_001_security_contact_missing",
        title="Account has no Security alternate contact configured",
        service="account",
        severity=Severity.LOW,
        description="The account has no Security alternate contact set, so AWS has no dedicated channel to reach the security team about abuse reports or security-relevant account activity.",
        remediation="In Billing and Cost Management > Account, or via the Account console, set the Security alternate contact to a monitored distribution list.",
        references=["https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html"],
        required_actions=["account:GetAlternateContact"],
        scope="account",
        cis_benchmarks=["1.2"],
    )
)
class SecurityContactMissingCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        client = ctx.session_factory.client("account", "us-east-1")
        result, error = safe_call(client.get_alternate_contact, AlternateContactType="SECURITY")
        if error:
            if error[0] == "ResourceNotFoundException":
                return [_finding(meta, Status.FAIL, {"reason": "no Security alternate contact configured"})]
            return [_error_finding(meta, error[0], error[1])]

        contact = result.get("AlternateContact", {})
        return [_finding(meta, Status.PASS, {"email_address": contact.get("EmailAddress")})]
