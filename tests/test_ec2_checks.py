from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from cspm_scan.checks.ec2_checks import (
    DefaultSecurityGroupNotRestrictedCheck,
    EbsVolumeUnencryptedCheck,
    InstanceImdsv2DisabledCheck,
    InstanceMissingIamProfileCheck,
    NaclOpenToWorldAdminPortsCheck,
    SecurityGroupOpenToWorldCheck,
    VpcFlowLogsDisabledCheck,
)
from cspm_scan.core.models import Status


def _ec2_client():
    return boto3.client("ec2", region_name="us-east-1", aws_access_key_id="fake", aws_secret_access_key="fake")


def _ctx(client):
    return SimpleNamespace(session_factory=SimpleNamespace(client=lambda service, region: client))


def test_sg_open_ssh_to_world_is_fail():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-open",
                    "GroupName": "open-ssh",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                    ],
                }
            ]
        },
    )
    stub.activate()

    findings = SecurityGroupOpenToWorldCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_sg_open_http_only_is_pass():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-web",
                    "GroupName": "web",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                    ],
                }
            ]
        },
    )
    stub.activate()

    findings = SecurityGroupOpenToWorldCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_sg_all_traffic_to_world_is_fail():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-allopen",
                    "GroupName": "all-open",
                    "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                }
            ]
        },
    )
    stub.activate()

    findings = SecurityGroupOpenToWorldCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_ebs_unencrypted_is_fail():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response("describe_volumes", {"Volumes": [{"VolumeId": "vol-1", "Encrypted": False}]})
    stub.activate()

    findings = EbsVolumeUnencryptedCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_ebs_encrypted_is_pass():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response("describe_volumes", {"Volumes": [{"VolumeId": "vol-2", "Encrypted": True}]})
    stub.activate()

    findings = EbsVolumeUnencryptedCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def _instance(instance_id, http_tokens=None, iam_profile=False):
    inst = {
        "InstanceId": instance_id,
        "InstanceType": "t3.micro",
        "ImageId": "ami-0123456789abcdef0",
        "State": {"Name": "running", "Code": 16},
    }
    if http_tokens is not None:
        inst["MetadataOptions"] = {"HttpTokens": http_tokens, "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 1}
    if iam_profile:
        inst["IamInstanceProfile"] = {"Arn": "arn:aws:iam::123456789012:instance-profile/x", "Id": "AIPAEXAMPLE"}
    return inst


def test_imdsv2_required_is_pass_and_optional_is_fail():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "ReservationId": "r-1",
                    "OwnerId": "123456789012",
                    "Instances": [_instance("i-required", http_tokens="required"), _instance("i-optional", http_tokens="optional")],
                }
            ]
        },
        {"Filters": [{"Name": "instance-state-name", "Values": ["pending", "running", "shutting-down", "stopping", "stopped"]}]},
    )
    stub.activate()

    findings = InstanceImdsv2DisabledCheck().execute(_ctx(client), region="us-east-1")

    by_id = {f.resource_id: f for f in findings}
    assert by_id["i-required"].status == Status.PASS
    assert by_id["i-optional"].status == Status.FAIL
    stub.deactivate()


def test_instance_missing_iam_profile():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "ReservationId": "r-1",
                    "OwnerId": "123456789012",
                    "Instances": [_instance("i-with-profile", iam_profile=True), _instance("i-without-profile", iam_profile=False)],
                }
            ]
        },
        {"Filters": [{"Name": "instance-state-name", "Values": ["pending", "running", "shutting-down", "stopping", "stopped"]}]},
    )
    stub.activate()

    findings = InstanceMissingIamProfileCheck().execute(_ctx(client), region="us-east-1")

    by_id = {f.resource_id: f for f in findings}
    assert by_id["i-with-profile"].status == Status.PASS
    assert by_id["i-without-profile"].status == Status.FAIL
    stub.deactivate()


def test_default_security_group_with_rules_is_fail():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-default1",
                    "GroupName": "default",
                    "VpcId": "vpc-1",
                    "IpPermissions": [{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-default1"}]}],
                    "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                }
            ]
        },
        {"Filters": [{"Name": "group-name", "Values": ["default"]}]},
    )
    stub.activate()

    findings = DefaultSecurityGroupNotRestrictedCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_default_security_group_with_no_rules_is_pass():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response(
        "describe_security_groups",
        {"SecurityGroups": [{"GroupId": "sg-default2", "GroupName": "default", "VpcId": "vpc-2", "IpPermissions": [], "IpPermissionsEgress": []}]},
        {"Filters": [{"Name": "group-name", "Values": ["default"]}]},
    )
    stub.activate()

    findings = DefaultSecurityGroupNotRestrictedCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_nacl_open_admin_port_before_deny_is_fail():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-open",
                    "VpcId": "vpc-1",
                    "IsDefault": False,
                    "Entries": [
                        {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"},
                        {"RuleNumber": 32767, "Protocol": "-1", "RuleAction": "deny", "Egress": False, "CidrBlock": "0.0.0.0/0"},
                    ],
                    "Associations": [],
                    "Tags": [],
                }
            ]
        },
    )
    stub.activate()

    findings = NaclOpenToWorldAdminPortsCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.FAIL
    stub.deactivate()


def test_nacl_deny_before_any_world_allow_is_pass():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-safe",
                    "VpcId": "vpc-2",
                    "IsDefault": True,
                    "Entries": [
                        {"RuleNumber": 100, "Protocol": "tcp", "RuleAction": "allow", "Egress": False, "CidrBlock": "10.0.0.0/16", "PortRange": {"From": 22, "To": 22}},
                        {"RuleNumber": 32767, "Protocol": "-1", "RuleAction": "deny", "Egress": False, "CidrBlock": "0.0.0.0/0"},
                    ],
                    "Associations": [],
                    "Tags": [],
                }
            ]
        },
    )
    stub.activate()

    findings = NaclOpenToWorldAdminPortsCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.PASS
    stub.deactivate()


def test_vpc_flow_logs_disabled_and_enabled():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-nolog", "State": "available", "CidrBlock": "10.0.0.0/16"}, {"VpcId": "vpc-withlog", "State": "available", "CidrBlock": "10.1.0.0/16"}]})
    stub.add_response("describe_flow_logs", {"FlowLogs": []}, {"Filter": [{"Name": "resource-id", "Values": ["vpc-nolog"]}]})
    stub.add_response(
        "describe_flow_logs",
        {"FlowLogs": [{"FlowLogId": "fl-1", "FlowLogStatus": "ACTIVE", "ResourceId": "vpc-withlog"}]},
        {"Filter": [{"Name": "resource-id", "Values": ["vpc-withlog"]}]},
    )
    stub.activate()

    findings = VpcFlowLogsDisabledCheck().execute(_ctx(client), region="us-east-1")

    by_id = {f.resource_id: f for f in findings}
    assert by_id["vpc-nolog"].status == Status.FAIL
    assert by_id["vpc-withlog"].status == Status.PASS
    stub.deactivate()


def test_imdsv2_check_access_denied_produces_error_finding():
    client = _ec2_client()
    stub = Stubber(client)
    stub.add_client_error(
        "describe_instances",
        service_error_code="AccessDenied",
        service_message="denied",
        expected_params={"Filters": [{"Name": "instance-state-name", "Values": ["pending", "running", "shutting-down", "stopping", "stopped"]}]},
    )
    stub.activate()

    findings = InstanceImdsv2DisabledCheck().execute(_ctx(client), region="us-east-1")

    assert findings[0].status == Status.ERROR
    assert findings[0].error_code == "AccessDenied"
    stub.deactivate()
