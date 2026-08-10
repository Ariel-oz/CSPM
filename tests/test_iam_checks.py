from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.iam_checks import (
    AccessKeyRotation90dCheck,
    AccessKeyUnused45dCheck,
    CloudShellFullAccessAttachedCheck,
    ConsoleAccessUnused45dCheck,
    ExpiredServerCertificatesCheck,
    InitialAccessKeyAtUserCreationCheck,
    MultipleActiveAccessKeysCheck,
    OverlyPermissivePolicyCheck,
    PasswordPolicyMinLengthCheck,
    PasswordPolicyReusePreventionCheck,
    PermissionsViaGroupsOnlyCheck,
    RootAccessKeysPresentCheck,
    RootAccountMfaCheck,
    RootHardwareMfaCheck,
    RootRecentUsageCheck,
    SupportRoleCreatedCheck,
    UserConsoleMfaDisabledCheck,
)
from cspm_scan.core.models import Status


def _iam_client():
    return boto3.client(
        "iam",
        region_name="us-east-1",
        aws_access_key_id="fake",
        aws_secret_access_key="fake",
    )


def _ctx(client, account_id="123456789012"):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client), account_id=account_id)


def test_root_account_mfa_pass():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 1}})
    stub.activate()

    findings = RootAccountMfaCheck().execute(_ctx(client))

    assert len(findings) == 1
    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_root_account_mfa_fail():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 0}})
    stub.activate()

    findings = RootAccountMfaCheck().execute(_ctx(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_root_access_keys_present_fail():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response("get_account_summary", {"SummaryMap": {"AccountAccessKeysPresent": 1}})
    stub.activate()

    findings = RootAccessKeysPresentCheck().execute(_ctx(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_access_denied_produces_error_finding():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_client_error("get_account_summary", service_error_code="AccessDenied", service_message="denied")
    stub.activate()

    findings = RootAccountMfaCheck().execute(_ctx(client))

    assert findings[0].status == Status.ERROR
    assert findings[0].error_code == "AccessDenied"
    stub.deactivate()


_CSV_HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
    "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
    "access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    "access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,"
    "cert_2_active,cert_2_last_rotated\n"
)


def _credential_report_csv(rows: list[str]) -> bytes:
    return (_CSV_HEADER + "\n".join(rows)).encode("utf-8")


def _stub_credential_report(stub, csv_bytes: bytes):
    stub.add_response("generate_credential_report", {"State": "COMPLETE"})
    stub.add_response(
        "get_credential_report",
        {"Content": csv_bytes, "ReportFormat": "text/csv", "GeneratedTime": datetime.now(timezone.utc)},
    )


def test_user_console_mfa_disabled():
    client = _iam_client()
    stub = Stubber(client)
    csv_bytes = _credential_report_csv(
        [
            "<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,not_supported,N/A,N/A,N/A,false,"
            "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
            "alice,arn:aws:iam::123456789012:user/alice,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,false,"
            "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
            "bob,arn:aws:iam::123456789012:user/bob,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true,"
            "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]
    )
    _stub_credential_report(stub, csv_bytes)
    stub.activate()

    findings = UserConsoleMfaDisabledCheck().execute(_ctx(client))

    by_user = {f.evidence["user"]: f for f in findings}
    assert by_user["alice"].status == Status.FAIL
    assert by_user["bob"].status == Status.PASS
    assert "root" not in by_user
    stub.deactivate()


def test_overly_permissive_policy_detects_admin_inline_and_managed():
    import json

    client = _iam_client()
    stub = Stubber(client)
    stub.add_response(
        "get_account_authorization_details",
        {
            "UserDetailList": [
                {
                    "Arn": "arn:aws:iam::123456789012:user/admin_user",
                    "UserPolicyList": [
                        {
                            "PolicyName": "InlineAdmin",
                            "PolicyDocument": json.dumps(
                                {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
                            ),
                        }
                    ],
                    "AttachedManagedPolicies": [],
                },
                {
                    "Arn": "arn:aws:iam::123456789012:user/scoped_user",
                    "UserPolicyList": [
                        {
                            "PolicyName": "S3ReadOnly",
                            "PolicyDocument": json.dumps(
                                {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
                            ),
                        }
                    ],
                    "AttachedManagedPolicies": [],
                },
            ],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
            "IsTruncated": False,
        },
        {},
    )
    stub.activate()

    findings = OverlyPermissivePolicyCheck().execute(_ctx(client))

    by_arn = {f.resource_id: f for f in findings}
    assert by_arn["arn:aws:iam::123456789012:user/admin_user"].status == Status.FAIL
    assert by_arn["arn:aws:iam::123456789012:user/scoped_user"].status == Status.PASS
    stub.deactivate()


def test_permissions_via_groups_only_flags_direct_attachment():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response(
        "get_account_authorization_details",
        {
            "UserDetailList": [
                {
                    "Arn": "arn:aws:iam::123456789012:user/direct_user",
                    "UserPolicyList": [],
                    "AttachedManagedPolicies": [{"PolicyName": "S3ReadOnly", "PolicyArn": "arn:aws:iam::aws:policy/S3ReadOnly"}],
                },
                {
                    "Arn": "arn:aws:iam::123456789012:user/group_only_user",
                    "UserPolicyList": [],
                    "AttachedManagedPolicies": [],
                },
            ],
            "GroupDetailList": [{"Arn": "arn:aws:iam::123456789012:group/somegroup", "GroupPolicyList": [], "AttachedManagedPolicies": []}],
            "RoleDetailList": [],
            "Policies": [],
            "IsTruncated": False,
        },
        {},
    )
    stub.activate()

    findings = PermissionsViaGroupsOnlyCheck().execute(_ctx(client))

    by_arn = {f.resource_id: f for f in findings}
    assert len(findings) == 2  # the group entry must be excluded
    assert by_arn["arn:aws:iam::123456789012:user/direct_user"].status == Status.FAIL
    assert by_arn["arn:aws:iam::123456789012:user/group_only_user"].status == Status.PASS
    stub.deactivate()


def test_password_policy_min_length_fail_and_pass():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response("get_account_password_policy", {"PasswordPolicy": {"MinimumPasswordLength": 8}})
    stub.add_response("get_account_password_policy", {"PasswordPolicy": {"MinimumPasswordLength": 14}})
    stub.activate()

    findings1 = PasswordPolicyMinLengthCheck().execute(_ctx(client))
    findings2 = PasswordPolicyMinLengthCheck().execute(_ctx(client))

    assert findings1[0].status == Status.FAIL
    assert findings2[0].status == Status.PASS
    stub.deactivate()


def test_password_policy_min_length_no_policy_is_fail():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_client_error("get_account_password_policy", service_error_code="NoSuchEntity", service_message="none")
    stub.activate()

    findings = PasswordPolicyMinLengthCheck().execute(_ctx(client))

    assert findings[0].status == Status.FAIL
    assert findings[0].error_code is None
    stub.deactivate()


def test_password_policy_reuse_prevention_fail_and_pass():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response("get_account_password_policy", {"PasswordPolicy": {"PasswordReusePrevention": 3}})
    stub.add_response("get_account_password_policy", {"PasswordPolicy": {"PasswordReusePrevention": 24}})
    stub.activate()

    findings1 = PasswordPolicyReusePreventionCheck().execute(_ctx(client))
    findings2 = PasswordPolicyReusePreventionCheck().execute(_ctx(client))

    assert findings1[0].status == Status.FAIL
    assert findings2[0].status == Status.PASS
    stub.deactivate()


def test_access_key_unused_45d():
    client = _iam_client()
    stub = Stubber(client)
    old_used = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    recent_used = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    csv_bytes = _credential_report_csv(
        [
            f"idle_user,arn:aws:iam::123456789012:user/idle_user,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true,"
            f"true,2020-01-01T00:00:00+00:00,{old_used},N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
            f"active_user,arn:aws:iam::123456789012:user/active_user,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true,"
            f"true,2020-01-01T00:00:00+00:00,{recent_used},N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]
    )
    _stub_credential_report(stub, csv_bytes)
    stub.activate()

    findings = AccessKeyUnused45dCheck().execute(_ctx(client))

    by_user = {f.evidence["user"]: f for f in findings}
    assert by_user["idle_user"].status == Status.FAIL
    assert by_user["active_user"].status == Status.PASS
    stub.deactivate()


def test_console_access_unused_45d():
    client = _iam_client()
    stub = Stubber(client)
    old_used = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    recent_used = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    csv_bytes = _credential_report_csv(
        [
            f"idle_console,arn:aws:iam::123456789012:user/idle_console,2020-01-01T00:00:00+00:00,true,{old_used},N/A,N/A,true,"
            "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
            f"active_console,arn:aws:iam::123456789012:user/active_console,2020-01-01T00:00:00+00:00,true,{recent_used},N/A,N/A,true,"
            "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]
    )
    _stub_credential_report(stub, csv_bytes)
    stub.activate()

    findings = ConsoleAccessUnused45dCheck().execute(_ctx(client))

    by_user = {f.evidence["user"]: f for f in findings}
    assert by_user["idle_console"].status == Status.FAIL
    assert by_user["active_console"].status == Status.PASS
    stub.deactivate()


def test_access_key_rotation_90d():
    client = _iam_client()
    stub = Stubber(client)
    old_rotated = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    recent_rotated = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    csv_bytes = _credential_report_csv(
        [
            f"stale_user,arn:aws:iam::123456789012:user/stale_user,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true,"
            f"true,{old_rotated},N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
            f"fresh_user,arn:aws:iam::123456789012:user/fresh_user,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true,"
            f"true,{recent_rotated},N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]
    )
    _stub_credential_report(stub, csv_bytes)
    stub.activate()

    findings = AccessKeyRotation90dCheck().execute(_ctx(client))

    by_user = {f.evidence["user"]: f for f in findings}
    assert by_user["stale_user"].status == Status.FAIL
    assert by_user["fresh_user"].status == Status.PASS
    stub.deactivate()


def test_multiple_active_access_keys():
    client = _iam_client()
    stub = Stubber(client)
    csv_bytes = _credential_report_csv(
        [
            "two_keys,arn:aws:iam::123456789012:user/two_keys,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true,"
            "true,2020-01-01T00:00:00+00:00,N/A,N/A,N/A,true,2020-01-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,false,N/A",
            "one_key,arn:aws:iam::123456789012:user/one_key,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true,"
            "true,2020-01-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]
    )
    _stub_credential_report(stub, csv_bytes)
    stub.activate()

    findings = MultipleActiveAccessKeysCheck().execute(_ctx(client))

    by_user = {f.evidence["user"]: f for f in findings}
    assert by_user["two_keys"].status == Status.FAIL
    assert by_user["one_key"].status == Status.PASS
    stub.deactivate()


def test_initial_access_key_at_user_creation():
    client = _iam_client()
    stub = Stubber(client)
    created = "2020-01-01T00:00:00+00:00"
    csv_bytes = _credential_report_csv(
        [
            f"never_rotated,arn:aws:iam::123456789012:user/never_rotated,{created},true,N/A,N/A,N/A,true,"
            f"true,{created},N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
            "rotated_since,arn:aws:iam::123456789012:user/rotated_since,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true,"
            "true,2024-06-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]
    )
    _stub_credential_report(stub, csv_bytes)
    stub.activate()

    findings = InitialAccessKeyAtUserCreationCheck().execute(_ctx(client))

    by_user = {f.evidence["user"]: f for f in findings}
    assert by_user["never_rotated"].status == Status.FAIL
    assert by_user["rotated_since"].status == Status.PASS
    stub.deactivate()


def test_support_role_created_found():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response(
        "list_roles",
        {"Roles": [{"RoleName": "OpsSupport", "Path": "/", "RoleId": "AROAEXAMPLE123456789", "Arn": "arn:aws:iam::123456789012:role/OpsSupport", "CreateDate": datetime.now(timezone.utc)}]},
    )
    stub.add_response(
        "list_attached_role_policies",
        {"AttachedPolicies": [{"PolicyName": "AWSSupportAccess", "PolicyArn": "arn:aws:iam::aws:policy/AWSSupportAccess"}]},
        {"RoleName": "OpsSupport"},
    )
    stub.activate()

    findings = SupportRoleCreatedCheck().execute(_ctx(client))

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_support_role_created_missing():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response(
        "list_roles",
        {"Roles": [{"RoleName": "Other", "Path": "/", "RoleId": "AROAEXAMPLE987654321", "Arn": "arn:aws:iam::123456789012:role/Other", "CreateDate": datetime.now(timezone.utc)}]},
    )
    stub.add_response("list_attached_role_policies", {"AttachedPolicies": []}, {"RoleName": "Other"})
    stub.activate()

    findings = SupportRoleCreatedCheck().execute(_ctx(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_expired_server_certificates():
    client = _iam_client()
    stub = Stubber(client)
    now = datetime.now(timezone.utc)
    stub.add_response(
        "list_server_certificates",
        {
            "ServerCertificateMetadataList": [
                {
                    "ServerCertificateName": "expired-cert",
                    "Path": "/",
                    "ServerCertificateId": "ASCAEXAMPLE123456789",
                    "Arn": "arn:aws:iam::123456789012:server-certificate/expired-cert",
                    "Expiration": now - timedelta(days=1),
                },
                {
                    "ServerCertificateName": "valid-cert",
                    "Path": "/",
                    "ServerCertificateId": "ASCAEXAMPLE987654321",
                    "Arn": "arn:aws:iam::123456789012:server-certificate/valid-cert",
                    "Expiration": now + timedelta(days=30),
                },
            ]
        },
    )
    stub.activate()

    findings = ExpiredServerCertificatesCheck().execute(_ctx(client))

    by_name = {f.resource_id: f for f in findings}
    assert by_name["expired-cert"].status == Status.FAIL
    assert by_name["valid-cert"].status == Status.PASS
    stub.deactivate()


def test_root_hardware_mfa_pass_when_no_virtual_device():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 1}})
    stub.add_response("list_virtual_mfa_devices", {"VirtualMFADevices": []}, {"AssignmentStatus": "Assigned"})
    stub.activate()

    findings = RootHardwareMfaCheck().execute(_ctx(client))

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_root_hardware_mfa_fail_when_virtual_device_assigned_to_root():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 1}})
    stub.add_response(
        "list_virtual_mfa_devices",
        {
            "VirtualMFADevices": [
                {
                    "SerialNumber": "arn:aws:iam::123456789012:mfa/root-account-mfa-device",
                    "User": {
                        "Path": "/",
                        "UserName": "root",
                        "UserId": "AIDAEXAMPLE123456",
                        "Arn": "arn:aws:iam::123456789012:root",
                        "CreateDate": datetime.now(timezone.utc),
                    },
                }
            ]
        },
        {"AssignmentStatus": "Assigned"},
    )
    stub.activate()

    findings = RootHardwareMfaCheck().execute(_ctx(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_root_hardware_mfa_not_applicable_when_no_mfa_at_all():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 0}})
    stub.activate()

    findings = RootHardwareMfaCheck().execute(_ctx(client))

    assert findings[0].status == Status.NOT_APPLICABLE
    stub.deactivate()


def test_root_recent_usage_fail_and_pass():
    client = _iam_client()
    stub = Stubber(client)
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    csv_bytes = _credential_report_csv(
        [
            f"<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,true,{recent},N/A,N/A,true,"
            "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]
    )
    _stub_credential_report(stub, csv_bytes)
    stub.activate()

    findings = RootRecentUsageCheck().execute(_ctx(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_root_recent_usage_pass_when_stale():
    client = _iam_client()
    stub = Stubber(client)
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    csv_bytes = _credential_report_csv(
        [
            f"<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,true,{old},N/A,N/A,true,"
            "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]
    )
    _stub_credential_report(stub, csv_bytes)
    stub.activate()

    findings = RootRecentUsageCheck().execute(_ctx(client))

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_cloudshell_full_access_attached_fail_and_pass():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response(
        "list_entities_for_policy",
        {"PolicyGroups": [], "PolicyUsers": [{"UserName": "shelluser"}], "PolicyRoles": [], "IsTruncated": False},
        {"PolicyArn": "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"},
    )
    stub.activate()

    findings = CloudShellFullAccessAttachedCheck().execute(_ctx(client))

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_cloudshell_full_access_not_attached_is_pass():
    client = _iam_client()
    stub = Stubber(client)
    stub.add_response(
        "list_entities_for_policy",
        {"PolicyGroups": [], "PolicyUsers": [], "PolicyRoles": [], "IsTruncated": False},
        {"PolicyArn": "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"},
    )
    stub.activate()

    findings = CloudShellFullAccessAttachedCheck().execute(_ctx(client))

    assert findings[0].status == Status.PASS
    stub.deactivate()
