import csv
import io
import time
from datetime import datetime, timezone

from botocore.exceptions import BotoCoreError, ClientError

from cspm_scan.core.engine import safe_call
from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import BaseCheck, register_check

CREDENTIAL_REPORT_POLL_ATTEMPTS = 6
CREDENTIAL_REPORT_POLL_DELAY_SECONDS = 2
ACCESS_KEY_MAX_AGE_DAYS = 90


def _error_finding(meta: CheckMeta, error_code: str, message: str, resource_id: str = "root") -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=Status.ERROR,
        resource_id=resource_id,
        region="global",
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        error_code=error_code,
        evidence={"message": message},
    )


def _finding(meta: CheckMeta, status: Status, resource_id: str, evidence: dict) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=status,
        resource_id=resource_id,
        region="global",
        description=meta.description,
        remediation=meta.remediation,
        references=meta.references,
        cis_benchmarks=meta.cis_benchmarks,
        evidence=evidence,
    )


def _get_credential_report(iam) -> tuple[list[dict], tuple[str, str] | None]:
    """Generate + fetch the IAM credential report as a list of row dicts.
    Polls briefly since a freshly-requested report starts in state STARTED."""
    _, error = safe_call(iam.generate_credential_report)
    if error and error[0] != "ReportInProgress":
        return [], error

    for attempt in range(CREDENTIAL_REPORT_POLL_ATTEMPTS):
        report, error = safe_call(iam.get_credential_report)
        if report:
            break
        if error and error[0] != "ReportInProgress":
            return [], error
        time.sleep(CREDENTIAL_REPORT_POLL_DELAY_SECONDS)
    else:
        return [], ("ReportInProgress", "Credential report was not ready after polling")

    content = report["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(content)))
    return rows, None


def _parse_report_datetime(value: str) -> datetime | None:
    if not value or value in ("N/A", "no_information"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@register_check(
    CheckMeta(
        check_id="iam_001_root_account_mfa",
        title="Root account does not have MFA enabled",
        service="iam",
        severity=Severity.CRITICAL,
        description="The AWS account root user has no multi-factor authentication device configured.",
        remediation=(
            "Sign in as the root user, go to IAM > My security credentials > "
            "Multi-factor authentication (MFA), and activate a hardware or virtual MFA device."
        ),
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"],
        required_actions=["iam:GetAccountSummary"],
        scope="account",
        cis_benchmarks=["1.5"],
    )
)
class RootAccountMfaCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        summary, error = safe_call(iam.get_account_summary)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        mfa_enabled = bool(summary["SummaryMap"].get("AccountMFAEnabled"))
        status = Status.PASS if mfa_enabled else Status.FAIL
        return [_finding(meta, status, "root", {"AccountMFAEnabled": summary["SummaryMap"].get("AccountMFAEnabled")})]


@register_check(
    CheckMeta(
        check_id="iam_002_root_access_keys_present",
        title="Root account has active access keys",
        service="iam",
        severity=Severity.CRITICAL,
        description="The AWS account root user has one or more active access keys, which should never be used for programmatic access.",
        remediation=(
            "Sign in as the root user, go to IAM > My security credentials > Access keys, "
            "and delete any root access keys. Use IAM users/roles for programmatic access instead."
        ),
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_add-key"],
        required_actions=["iam:GetAccountSummary"],
        scope="account",
        cis_benchmarks=["1.4"],
    )
)
class RootAccessKeysPresentCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        summary, error = safe_call(iam.get_account_summary)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        keys_present = bool(summary["SummaryMap"].get("AccountAccessKeysPresent"))
        status = Status.FAIL if keys_present else Status.PASS
        return [
            _finding(
                meta, status, "root", {"AccountAccessKeysPresent": summary["SummaryMap"].get("AccountAccessKeysPresent")}
            )
        ]


@register_check(
    CheckMeta(
        check_id="iam_003_user_console_mfa_disabled",
        title="IAM user with console access has no MFA device",
        service="iam",
        severity=Severity.HIGH,
        description="An IAM user with a console password has no MFA device active, allowing console sign-in with just a password.",
        remediation="In IAM > Users > <user> > Security credentials, assign an MFA device to the user.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html"],
        required_actions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
        scope="account",
        cis_benchmarks=["1.10"],
    )
)
class UserConsoleMfaDisabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        rows, error = _get_credential_report(iam)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        findings = []
        for row in rows:
            if row["user"] == "<root_account>":
                continue
            if row.get("password_enabled") != "true":
                continue
            mfa_active = row.get("mfa_active") == "true"
            status = Status.PASS if mfa_active else Status.FAIL
            findings.append(
                _finding(
                    meta,
                    status,
                    row["arn"],
                    {"user": row["user"], "password_enabled": row["password_enabled"], "mfa_active": row["mfa_active"]},
                )
            )
        return findings


_PASSWORD_POLICY_MIN_LENGTH = 14
_PASSWORD_POLICY_REUSE_PREVENTION = 24
_UNUSED_CREDENTIAL_MAX_AGE_DAYS = 45
_ROOT_RECENT_USAGE_WINDOW_DAYS = 7
_INITIAL_KEY_HEURISTIC_TOLERANCE_SECONDS = 300


def _parse_policy_document(raw) -> dict:
    """AWS returns PolicyDocument/Document fields as URL-encoded JSON strings
    (no botocore jsonvalue auto-decoding for these IAM shapes) - decode them here."""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    import json
    import urllib.parse

    try:
        return json.loads(urllib.parse.unquote(raw))
    except (ValueError, TypeError):
        return {}


def _statements(document: dict) -> list[dict]:
    statement = document.get("Statement", [])
    return statement if isinstance(statement, list) else [statement]


def _is_wildcard(value) -> bool:
    if isinstance(value, str):
        return value == "*"
    if isinstance(value, list):
        return "*" in value
    return False


def _is_admin_equivalent(document: dict) -> bool:
    for stmt in _statements(document):
        if stmt.get("Effect") != "Allow":
            continue
        if _is_wildcard(stmt.get("Action")) and _is_wildcard(stmt.get("Resource")):
            return True
    return False


def _fetch_authorization_details(iam):
    """Shared by iam_006 and iam_014: one paginated get_account_authorization_details
    call, returning (entities, managed_policy_docs, error)."""
    managed_policy_docs: dict[str, dict] = {}
    entities: list[dict] = []
    try:
        paginator = iam.get_paginator("get_account_authorization_details")
        for page in paginator.paginate():
            for policy in page.get("Policies", []):
                default_version = policy.get("DefaultVersionId")
                for version in policy.get("PolicyVersionList", []):
                    if version.get("VersionId") == default_version:
                        managed_policy_docs[policy["Arn"]] = _parse_policy_document(version.get("Document"))
            entities.extend(page.get("UserDetailList", []))
            entities.extend(page.get("GroupDetailList", []))
            entities.extend(page.get("RoleDetailList", []))
    except Exception as e:  # noqa: BLE001
        if isinstance(e, ClientError):
            return [], {}, (e.response["Error"]["Code"], str(e))
        if isinstance(e, BotoCoreError):
            return [], {}, (type(e).__name__, str(e))
        raise
    return entities, managed_policy_docs, None


@register_check(
    CheckMeta(
        check_id="iam_006_overly_permissive_policy",
        title="IAM entity has an admin-equivalent policy (Action:* on Resource:*)",
        service="iam",
        severity=Severity.HIGH,
        description=(
            "An IAM user, group, or role has an attached or inline policy granting Action:* on Resource:*, "
            "effectively full administrator access."
        ),
        remediation=(
            "Replace the wildcard policy with a scoped policy granting only the specific actions and "
            "resources the entity actually needs (least privilege)."
        ),
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"],
        required_actions=["iam:GetAccountAuthorizationDetails"],
        scope="account",
        cis_benchmarks=["1.16"],
    )
)
class OverlyPermissivePolicyCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")

        entities, managed_policy_docs, error = _fetch_authorization_details(iam)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        findings = []
        for entity in entities:
            arn = entity.get("Arn", "unknown")
            offending_policies = []

            for inline in entity.get("UserPolicyList", []) + entity.get("GroupPolicyList", []) + entity.get("RolePolicyList", []):
                if _is_admin_equivalent(_parse_policy_document(inline.get("PolicyDocument"))):
                    offending_policies.append({"type": "inline", "name": inline.get("PolicyName")})

            for attached in entity.get("AttachedManagedPolicies", []):
                doc = managed_policy_docs.get(attached.get("PolicyArn"))
                if doc and _is_admin_equivalent(doc):
                    offending_policies.append({"type": "managed", "name": attached.get("PolicyName"), "arn": attached.get("PolicyArn")})

            status = Status.FAIL if offending_policies else Status.PASS
            findings.append(_finding(meta, status, arn, {"offending_policies": offending_policies}))

        return findings


@register_check(
    CheckMeta(
        check_id="iam_014_permissions_via_groups_only",
        title="IAM user receives permissions via directly-attached or inline policies, not only groups",
        service="iam",
        severity=Severity.LOW,
        description="An IAM user has an inline policy or a directly-attached managed policy, instead of receiving all permissions through group membership.",
        remediation="Create/attach an IAM group with the equivalent managed policies, add the user to it, then remove the user's inline policies and direct managed-policy attachments.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions"],
        required_actions=["iam:GetAccountAuthorizationDetails"],
        scope="account",
        cis_benchmarks=["1.15"],
    )
)
class PermissionsViaGroupsOnlyCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")

        entities, _managed_policy_docs, error = _fetch_authorization_details(iam)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        findings = []
        for entity in entities:
            if "UserPolicyList" not in entity:
                continue  # only IAM users' entries carry this key; groups/roles are out of scope for this control
            arn = entity.get("Arn", "unknown")
            inline_names = [p.get("PolicyName") for p in entity.get("UserPolicyList", [])]
            attached_names = [p.get("PolicyName") for p in entity.get("AttachedManagedPolicies", [])]
            status = Status.FAIL if (inline_names or attached_names) else Status.PASS
            findings.append(
                _finding(
                    meta, status, arn, {"inline_policies": inline_names, "directly_attached_policies": attached_names}
                )
            )
        return findings


@register_check(
    CheckMeta(
        check_id="iam_007_password_policy_min_length",
        title="Account password policy does not require a minimum length of 14",
        service="iam",
        severity=Severity.MEDIUM,
        description="The account password policy is missing, or its MinimumPasswordLength is set below 14 characters.",
        remediation="In IAM > Account settings, set Minimum password length to 14 or greater.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"],
        required_actions=["iam:GetAccountPasswordPolicy"],
        scope="account",
        cis_benchmarks=["1.8"],
    )
)
class PasswordPolicyMinLengthCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        result, error = safe_call(iam.get_account_password_policy)
        if error:
            if error[0] == "NoSuchEntity":
                return [_finding(meta, Status.FAIL, "account", {"reason": "no password policy configured"})]
            return [_error_finding(meta, error[0], error[1])]

        min_length = result["PasswordPolicy"].get("MinimumPasswordLength", 0)
        status = Status.PASS if min_length >= _PASSWORD_POLICY_MIN_LENGTH else Status.FAIL
        return [_finding(meta, status, "account", {"minimum_password_length": min_length})]


@register_check(
    CheckMeta(
        check_id="iam_008_password_policy_reuse_prevention",
        title="Account password policy does not prevent password reuse",
        service="iam",
        severity=Severity.MEDIUM,
        description="The account password policy is missing, or its PasswordReusePrevention is set below 24 previous passwords.",
        remediation="In IAM > Account settings, set 'Number of passwords to remember' to 24 or greater.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"],
        required_actions=["iam:GetAccountPasswordPolicy"],
        scope="account",
        cis_benchmarks=["1.9"],
    )
)
class PasswordPolicyReusePreventionCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        result, error = safe_call(iam.get_account_password_policy)
        if error:
            if error[0] == "NoSuchEntity":
                return [_finding(meta, Status.FAIL, "account", {"reason": "no password policy configured"})]
            return [_error_finding(meta, error[0], error[1])]

        reuse_prevention = result["PasswordPolicy"].get("PasswordReusePrevention") or 0
        status = Status.PASS if reuse_prevention >= _PASSWORD_POLICY_REUSE_PREVENTION else Status.FAIL
        return [_finding(meta, status, "account", {"password_reuse_prevention": reuse_prevention})]


@register_check(
    CheckMeta(
        check_id="iam_009_access_key_unused_45d",
        title="IAM access key has been unused for 45 days or more",
        service="iam",
        severity=Severity.MEDIUM,
        description="An active IAM access key has not been used in the last 45 days (or has never been used since being issued more than 45 days ago).",
        remediation="In IAM > Users > <user> > Security credentials, deactivate or delete the unused access key.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html"],
        required_actions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
        scope="account",
        cis_benchmarks=["1.12"],
    )
)
class AccessKeyUnused45dCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        rows, error = _get_credential_report(iam)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        now = datetime.now(timezone.utc)
        findings = []
        for row in rows:
            if row["user"] == "<root_account>":
                continue
            for key_num in (1, 2):
                if row.get(f"access_key_{key_num}_active") != "true":
                    continue
                last_used_at = _parse_report_datetime(row.get(f"access_key_{key_num}_last_used_date", ""))
                rotated_at = _parse_report_datetime(row.get(f"access_key_{key_num}_last_rotated", ""))
                reference_date = last_used_at or rotated_at
                idle_days = (now - reference_date).days if reference_date else None
                status = Status.FAIL if idle_days is not None and idle_days > _UNUSED_CREDENTIAL_MAX_AGE_DAYS else Status.PASS
                findings.append(
                    _finding(
                        meta,
                        status,
                        f"{row['arn']}:access_key_{key_num}",
                        {"user": row["user"], "idle_days": idle_days, "ever_used": last_used_at is not None},
                    )
                )
        return findings


@register_check(
    CheckMeta(
        check_id="iam_010_console_access_unused_45d",
        title="IAM user's console password has been unused for 45 days or more",
        service="iam",
        severity=Severity.MEDIUM,
        description="An IAM user has a console password enabled but has not signed in within the last 45 days (or never since the password was created more than 45 days ago).",
        remediation="In IAM > Users > <user> > Security credentials, disable or remove the console password if it's no longer needed.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html"],
        required_actions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
        scope="account",
        cis_benchmarks=["1.12"],
    )
)
class ConsoleAccessUnused45dCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        rows, error = _get_credential_report(iam)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        now = datetime.now(timezone.utc)
        findings = []
        for row in rows:
            if row["user"] == "<root_account>":
                continue
            if row.get("password_enabled") != "true":
                continue
            last_used_at = _parse_report_datetime(row.get("password_last_used", ""))
            created_at = _parse_report_datetime(row.get("user_creation_time", ""))
            reference_date = last_used_at or created_at
            idle_days = (now - reference_date).days if reference_date else None
            status = Status.FAIL if idle_days is not None and idle_days > _UNUSED_CREDENTIAL_MAX_AGE_DAYS else Status.PASS
            findings.append(
                _finding(meta, status, row["arn"], {"user": row["user"], "idle_days": idle_days, "ever_signed_in": last_used_at is not None})
            )
        return findings


@register_check(
    CheckMeta(
        check_id="iam_011_access_key_rotation_90d",
        title="IAM access key has not been rotated in 90 days or more",
        service="iam",
        severity=Severity.MEDIUM,
        description="An active IAM access key has not been rotated (replaced with a new key) in over 90 days.",
        remediation="In IAM > Users > <user> > Security credentials, create a new access key, update applications to use it, then deactivate/delete the old key.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"],
        required_actions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
        scope="account",
        cis_benchmarks=["1.14"],
    )
)
class AccessKeyRotation90dCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        rows, error = _get_credential_report(iam)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        now = datetime.now(timezone.utc)
        findings = []
        for row in rows:
            if row["user"] == "<root_account>":
                continue
            for key_num in (1, 2):
                if row.get(f"access_key_{key_num}_active") != "true":
                    continue
                rotated_at = _parse_report_datetime(row.get(f"access_key_{key_num}_last_rotated", ""))
                age_days = (now - rotated_at).days if rotated_at else None
                status = Status.FAIL if age_days is not None and age_days > ACCESS_KEY_MAX_AGE_DAYS else Status.PASS
                findings.append(
                    _finding(meta, status, f"{row['arn']}:access_key_{key_num}", {"user": row["user"], "age_days": age_days})
                )
        return findings


@register_check(
    CheckMeta(
        check_id="iam_012_multiple_active_access_keys",
        title="IAM user has more than one active access key",
        service="iam",
        severity=Severity.LOW,
        description="An IAM user has two active access keys simultaneously, which increases the exposure surface if either is compromised.",
        remediation="Deactivate or delete the older of the two active keys once you've confirmed the newer key is in use everywhere.",
        references=["https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html"],
        required_actions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
        scope="account",
        cis_benchmarks=["1.13"],
    )
)
class MultipleActiveAccessKeysCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        rows, error = _get_credential_report(iam)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        findings = []
        for row in rows:
            if row["user"] == "<root_account>":
                continue
            both_active = row.get("access_key_1_active") == "true" and row.get("access_key_2_active") == "true"
            status = Status.FAIL if both_active else Status.PASS
            findings.append(_finding(meta, status, row["arn"], {"user": row["user"], "both_keys_active": both_active}))
        return findings


@register_check(
    CheckMeta(
        check_id="iam_013_initial_access_key_at_user_creation",
        title="IAM user's active access key was issued at user creation and never rotated",
        service="iam",
        severity=Severity.LOW,
        description=(
            "An IAM user's active access key was created at the same time as the user itself and has never "
            "been rotated since. This is a heuristic proxy (the credential report has no separate 'key created' "
            "field, only 'last rotated', which equals the creation date for a never-rotated key) - it will miss "
            "an initial key that was later rotated once and is now stale for other reasons."
        ),
        remediation="Rotate the access key: create a new one, update applications, then deactivate/delete this one.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html"],
        required_actions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
        scope="account",
        cis_benchmarks=["1.11"],
    )
)
class InitialAccessKeyAtUserCreationCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        rows, error = _get_credential_report(iam)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        findings = []
        for row in rows:
            if row["user"] == "<root_account>":
                continue
            created_at = _parse_report_datetime(row.get("user_creation_time", ""))
            for key_num in (1, 2):
                if row.get(f"access_key_{key_num}_active") != "true":
                    continue
                rotated_at = _parse_report_datetime(row.get(f"access_key_{key_num}_last_rotated", ""))
                never_rotated_since_creation = bool(
                    created_at
                    and rotated_at
                    and abs((rotated_at - created_at).total_seconds()) <= _INITIAL_KEY_HEURISTIC_TOLERANCE_SECONDS
                )
                status = Status.FAIL if never_rotated_since_creation else Status.PASS
                findings.append(
                    _finding(
                        meta,
                        status,
                        f"{row['arn']}:access_key_{key_num}",
                        {"user": row["user"], "never_rotated_since_creation": never_rotated_since_creation},
                    )
                )
        return findings


@register_check(
    CheckMeta(
        check_id="iam_015_support_role_created",
        title="No IAM role exists with AWSSupportAccess for AWS Support case management",
        service="iam",
        severity=Severity.LOW,
        description="No IAM role in the account has the AWS-managed AWSSupportAccess policy attached, so operations staff would need to use more privileged credentials to open AWS Support cases.",
        remediation="Create an IAM role trusted by your operations team's identities and attach the AWS-managed AWSSupportAccess policy to it.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html"],
        required_actions=["iam:ListRoles", "iam:ListAttachedRolePolicies"],
        scope="account",
        cis_benchmarks=["1.17"],
    )
)
class SupportRoleCreatedCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")

        found_role = None
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    attached, error = safe_call(iam.list_attached_role_policies, RoleName=role["RoleName"])
                    if error:
                        continue  # a single role's lookup failing shouldn't abort the whole account-level check
                    if any(p["PolicyArn"] == "arn:aws:iam::aws:policy/AWSSupportAccess" for p in attached.get("AttachedPolicies", [])):
                        found_role = role["RoleName"]
                        break
                if found_role:
                    break
        except (ClientError, BotoCoreError) as e:
            code = e.response["Error"]["Code"] if isinstance(e, ClientError) else type(e).__name__
            return [_error_finding(meta, code, str(e))]

        status = Status.PASS if found_role else Status.FAIL
        return [_finding(meta, status, "account", {"role_with_support_access": found_role})]


@register_check(
    CheckMeta(
        check_id="iam_016_expired_server_certificates",
        title="IAM has an expired SSL/TLS server certificate stored",
        service="iam",
        severity=Severity.LOW,
        description="An SSL/TLS server certificate stored in IAM has passed its expiration date.",
        remediation="Delete the expired certificate: aws iam delete-server-certificate --server-certificate-name <name>. If still needed, replace it with a current certificate first.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html"],
        required_actions=["iam:ListServerCertificates"],
        scope="account",
        cis_benchmarks=["1.19"],
    )
)
class ExpiredServerCertificatesCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        result, error = safe_call(iam.list_server_certificates)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        now = datetime.now(timezone.utc)
        findings = []
        for cert in result.get("ServerCertificateMetadataList", []):
            expiration = cert.get("Expiration")
            expired = bool(expiration and expiration < now)
            status = Status.FAIL if expired else Status.PASS
            findings.append(
                _finding(
                    meta, status, cert["ServerCertificateName"], {"expiration": expiration, "expired": expired}
                )
            )
        return findings


@register_check(
    CheckMeta(
        check_id="iam_017_root_hardware_mfa",
        title="Root account MFA device is virtual, not hardware",
        service="iam",
        severity=Severity.HIGH,
        description="The root user has MFA enabled, but the device assigned is a virtual MFA device rather than a hardware MFA device.",
        remediation="Sign in as the root user, remove the virtual MFA device, and assign a hardware MFA device instead.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html#enable-hw-mfa-for-root"],
        required_actions=["iam:GetAccountSummary", "iam:ListVirtualMFADevices"],
        scope="account",
        cis_benchmarks=["1.6"],
    )
)
class RootHardwareMfaCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        summary, error = safe_call(iam.get_account_summary)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        if not summary["SummaryMap"].get("AccountMFAEnabled"):
            return [_finding(meta, Status.NOT_APPLICABLE, "root", {"reason": "root has no MFA device at all (see iam_001)"})]

        devices, error = safe_call(iam.list_virtual_mfa_devices, AssignmentStatus="Assigned")
        if error:
            return [_error_finding(meta, error[0], error[1])]

        root_arn = f"arn:aws:iam::{ctx.account_id}:root"
        root_has_virtual_mfa = any(d.get("User", {}).get("Arn") == root_arn for d in devices.get("VirtualMFADevices", []))
        status = Status.FAIL if root_has_virtual_mfa else Status.PASS
        return [_finding(meta, status, "root", {"root_has_virtual_mfa": root_has_virtual_mfa})]


@register_check(
    CheckMeta(
        check_id="iam_018_root_recent_usage",
        title="Root account was used recently",
        service="iam",
        severity=Severity.HIGH,
        description="The root user's password or an access key was used within the last 7 days, indicating root is being used for routine tasks instead of a dedicated IAM identity.",
        remediation="Stop using the root user for day-to-day tasks; use it only for the small set of actions that require root, and consider removing root access keys entirely.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"],
        required_actions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
        scope="account",
        cis_benchmarks=["1.7"],
    )
)
class RootRecentUsageCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")
        rows, error = _get_credential_report(iam)
        if error:
            return [_error_finding(meta, error[0], error[1])]

        root_row = next((r for r in rows if r["user"] == "<root_account>"), None)
        if root_row is None:
            return [_error_finding(meta, "RootRowMissing", "credential report had no <root_account> row")]

        now = datetime.now(timezone.utc)
        candidates = [
            _parse_report_datetime(root_row.get("password_last_used", "")),
            _parse_report_datetime(root_row.get("access_key_1_last_used_date", "")),
            _parse_report_datetime(root_row.get("access_key_2_last_used_date", "")),
        ]
        most_recent = max((c for c in candidates if c is not None), default=None)
        recently_used = bool(most_recent and (now - most_recent).days <= _ROOT_RECENT_USAGE_WINDOW_DAYS)
        status = Status.FAIL if recently_used else Status.PASS
        return [_finding(meta, status, "root", {"most_recent_use": most_recent, "recently_used": recently_used})]


@register_check(
    CheckMeta(
        check_id="iam_020_cloudshell_full_access_attached",
        title="AWSCloudShellFullAccess policy is attached to an IAM entity",
        service="iam",
        severity=Severity.LOW,
        description="The AWS-managed AWSCloudShellFullAccess policy is attached to a user, group, or role, which can allow file transfer in/out of the AWS environment via CloudShell that bypasses other network controls.",
        remediation="Detach AWSCloudShellFullAccess from the affected entity and, if CloudShell access is still needed, scope down permissions with a customer-managed policy.",
        references=["https://docs.aws.amazon.com/cloudshell/latest/userguide/sec-auth-with-identities.html"],
        required_actions=["iam:ListEntitiesForPolicy"],
        scope="account",
        cis_benchmarks=["1.22"],
    )
)
class CloudShellFullAccessAttachedCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        iam = ctx.session_factory.client("iam", "us-east-1")

        entities = {"users": [], "groups": [], "roles": []}
        try:
            paginator = iam.get_paginator("list_entities_for_policy")
            for page in paginator.paginate(PolicyArn="arn:aws:iam::aws:policy/AWSCloudShellFullAccess"):
                entities["users"].extend(u["UserName"] for u in page.get("PolicyUsers", []))
                entities["groups"].extend(g["GroupName"] for g in page.get("PolicyGroups", []))
                entities["roles"].extend(r["RoleName"] for r in page.get("PolicyRoles", []))
        except (ClientError, BotoCoreError) as e:
            code = e.response["Error"]["Code"] if isinstance(e, ClientError) else type(e).__name__
            return [_error_finding(meta, code, str(e))]

        any_attached = bool(entities["users"] or entities["groups"] or entities["roles"])
        status = Status.FAIL if any_attached else Status.PASS
        return [_finding(meta, status, "account", entities)]
