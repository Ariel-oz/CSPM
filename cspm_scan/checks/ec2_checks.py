from botocore.exceptions import BotoCoreError, ClientError

from cspm_scan.core.engine import safe_call
from cspm_scan.core.models import CheckMeta, Finding, Severity, Status
from cspm_scan.core.registry import BaseCheck, register_check

SENSITIVE_PORTS = {22, 3389}


def _error_finding(meta: CheckMeta, error_code: str, message: str, region: str) -> Finding:
    return Finding(
        check_id=meta.check_id,
        title=meta.title,
        service=meta.service,
        severity=meta.severity,
        status=Status.ERROR,
        resource_id="n/a",
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


def _is_world_open_cidr(perm: dict) -> bool:
    for r in perm.get("IpRanges", []):
        if r.get("CidrIp") == "0.0.0.0/0":
            return True
    for r in perm.get("Ipv6Ranges", []):
        if r.get("CidrIpv6") == "::/0":
            return True
    return False


def _is_sensitive_rule(perm: dict) -> bool:
    if perm.get("IpProtocol") == "-1":
        return True
    from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return any(from_port <= p <= to_port for p in SENSITIVE_PORTS)


@register_check(
    CheckMeta(
        check_id="ec2_001_security_group_open_to_world",
        title="Security group allows inbound traffic from 0.0.0.0/0 on a sensitive port or all traffic",
        service="ec2",
        severity=Severity.HIGH,
        description=(
            "A security group has an inbound rule allowing 0.0.0.0/0 or ::/0 on SSH (22), RDP (3389), "
            "or all ports/protocols."
        ),
        remediation="Restrict the security group's inbound rule to specific known CIDR ranges instead of 0.0.0.0/0 or ::/0.",
        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html"],
        required_actions=["ec2:DescribeSecurityGroups"],
        scope="region",
        cis_benchmarks=["5.2", "5.3"],
    )
)
class SecurityGroupOpenToWorldCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        ec2 = ctx.session_factory.client("ec2", region)
        result, error = safe_call(ec2.describe_security_groups)
        if error:
            return [_error_finding(meta, error[0], error[1], region)]

        findings = []
        for sg in result.get("SecurityGroups", []):
            offending = [
                perm
                for perm in sg.get("IpPermissions", [])
                if _is_world_open_cidr(perm) and _is_sensitive_rule(perm)
            ]
            status = Status.FAIL if offending else Status.PASS
            findings.append(
                _finding(
                    meta,
                    status,
                    sg["GroupId"],
                    region,
                    {"group_name": sg.get("GroupName"), "offending_rules": offending},
                )
            )
        return findings


@register_check(
    CheckMeta(
        check_id="ec2_002_ebs_volume_unencrypted",
        title="EBS volume is not encrypted",
        service="ec2",
        severity=Severity.MEDIUM,
        description="An EBS volume does not have encryption at rest enabled.",
        remediation="Enable EBS encryption by default for the account/region, or migrate the volume to an encrypted snapshot/volume.",
        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"],
        required_actions=["ec2:DescribeVolumes"],
        scope="region",
        cis_benchmarks=["2.2.1"],
    )
)
class EbsVolumeUnencryptedCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        ec2 = ctx.session_factory.client("ec2", region)
        result, error = safe_call(ec2.describe_volumes)
        if error:
            return [_error_finding(meta, error[0], error[1], region)]

        findings = []
        for volume in result.get("Volumes", []):
            status = Status.PASS if volume.get("Encrypted") else Status.FAIL
            findings.append(_finding(meta, status, volume["VolumeId"], region, {"encrypted": volume.get("Encrypted")}))
        return findings


_NON_TERMINAL_INSTANCE_STATES = ["pending", "running", "shutting-down", "stopping", "stopped"]


@register_check(
    CheckMeta(
        check_id="ec2_003_instance_imdsv2_disabled",
        title="EC2 instance does not require IMDSv2",
        service="ec2",
        severity=Severity.HIGH,
        description="An EC2 instance's metadata service allows IMDSv1 (token-optional access), which is more susceptible to SSRF-based credential theft than IMDSv2.",
        remediation="In the EC2 console, select the instance, Actions > Instance settings > Modify instance metadata options, and set 'IMDSv2' to Required.",
        references=[
            "https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/"
        ],
        required_actions=["ec2:DescribeInstances"],
        scope="region",
        cis_benchmarks=["5.6"],
    )
)
class InstanceImdsv2DisabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        ec2 = ctx.session_factory.client("ec2", region)

        findings = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": _NON_TERMINAL_INSTANCE_STATES}]
            ):
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        http_tokens = instance.get("MetadataOptions", {}).get("HttpTokens")
                        status = Status.PASS if http_tokens == "required" else Status.FAIL
                        findings.append(_finding(meta, status, instance["InstanceId"], region, {"http_tokens": http_tokens}))
        except (ClientError, BotoCoreError) as e:
            code = e.response["Error"]["Code"] if isinstance(e, ClientError) else type(e).__name__
            return [_error_finding(meta, code, str(e), region)]
        return findings


@register_check(
    CheckMeta(
        check_id="ec2_004_default_security_group_not_restricted",
        title="The default security group allows inbound or outbound traffic",
        service="ec2",
        severity=Severity.MEDIUM,
        description="A VPC's default security group has one or more inbound or outbound rules, so resources accidentally left in it (rather than a purpose-built security group) get network access.",
        remediation="Move any resources out of the default security group into purpose-built security groups, then remove all inbound and outbound rules from the default security group.",
        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html#default-security-group"],
        required_actions=["ec2:DescribeSecurityGroups"],
        scope="region",
        cis_benchmarks=["5.4"],
    )
)
class DefaultSecurityGroupNotRestrictedCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        ec2 = ctx.session_factory.client("ec2", region)
        result, error = safe_call(
            ec2.describe_security_groups, Filters=[{"Name": "group-name", "Values": ["default"]}]
        )
        if error:
            return [_error_finding(meta, error[0], error[1], region)]

        findings = []
        for sg in result.get("SecurityGroups", []):
            has_rules = bool(sg.get("IpPermissions")) or bool(sg.get("IpPermissionsEgress"))
            status = Status.FAIL if has_rules else Status.PASS
            findings.append(
                _finding(
                    meta,
                    status,
                    sg["GroupId"],
                    region,
                    {"vpc_id": sg.get("VpcId"), "inbound_rules": len(sg.get("IpPermissions", [])), "outbound_rules": len(sg.get("IpPermissionsEgress", []))},
                )
            )
        return findings


def _nacl_entries_by_direction(entries: list[dict], egress: bool) -> list[dict]:
    return sorted((e for e in entries if bool(e.get("Egress")) == egress), key=lambda e: e["RuleNumber"])


def _nacl_rule_covers_admin_port(entry: dict) -> bool:
    if entry.get("Protocol") == "-1":
        return True
    port_range = entry.get("PortRange") or {}
    from_port, to_port = port_range.get("From"), port_range.get("To")
    if from_port is None or to_port is None:
        return False
    return any(from_port <= p <= to_port for p in SENSITIVE_PORTS)


def _nacl_allows_world_admin_access(entries: list[dict]) -> tuple[bool, dict | None]:
    """NACL evaluates rules in ascending RuleNumber order; the first rule that matches
    (CIDR + protocol/port) a given packet decides its fate. Only rules whose CIDR is
    0.0.0.0/0 or ::/0 can match traffic from an arbitrary internet source, so among
    those, the lowest-numbered one that also covers an admin port is determinative."""
    for entry in _nacl_entries_by_direction(entries, egress=False):
        is_world = entry.get("CidrBlock") == "0.0.0.0/0" or entry.get("Ipv6CidrBlock") == "::/0"
        if not is_world or not _nacl_rule_covers_admin_port(entry):
            continue
        return entry.get("RuleAction") == "allow", entry
    return False, None


@register_check(
    CheckMeta(
        check_id="ec2_005_nacl_open_to_world_admin_ports",
        title="Network ACL allows inbound traffic from 0.0.0.0/0 or ::/0 on a remote administration port",
        service="ec2",
        severity=Severity.HIGH,
        description="A network ACL's lowest-numbered matching inbound rule for 0.0.0.0/0 or ::/0 allows traffic on SSH (22), RDP (3389), or all ports/protocols.",
        remediation="Edit the network ACL's inbound rules to remove or narrow the 0.0.0.0/0 (or ::/0) allow, or insert a lower-numbered deny rule ahead of it.",
        references=["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html"],
        required_actions=["ec2:DescribeNetworkAcls"],
        scope="region",
        cis_benchmarks=["5.1"],
    )
)
class NaclOpenToWorldAdminPortsCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        ec2 = ctx.session_factory.client("ec2", region)

        findings = []
        try:
            paginator = ec2.get_paginator("describe_network_acls")
            for page in paginator.paginate():
                for nacl in page.get("NetworkAcls", []):
                    allowed, matching_entry = _nacl_allows_world_admin_access(nacl.get("Entries", []))
                    status = Status.FAIL if allowed else Status.PASS
                    findings.append(
                        _finding(
                            meta,
                            status,
                            nacl["NetworkAclId"],
                            region,
                            {"vpc_id": nacl.get("VpcId"), "matching_entry": matching_entry},
                        )
                    )
        except (ClientError, BotoCoreError) as e:
            code = e.response["Error"]["Code"] if isinstance(e, ClientError) else type(e).__name__
            return [_error_finding(meta, code, str(e), region)]
        return findings


@register_check(
    CheckMeta(
        check_id="ec2_006_vpc_flow_logs_disabled",
        title="VPC does not have an active flow log",
        service="ec2",
        severity=Severity.MEDIUM,
        description="A VPC has no active flow log delivering network traffic metadata to CloudWatch Logs or S3, limiting network-level audit visibility.",
        remediation="In the VPC console, select the VPC, Flow Logs tab, and create a flow log (Reject or All traffic filter) delivering to CloudWatch Logs or S3.",
        references=["https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html"],
        required_actions=["ec2:DescribeVpcs", "ec2:DescribeFlowLogs"],
        scope="region",
        cis_benchmarks=["3.7"],
    )
)
class VpcFlowLogsDisabledCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        ec2 = ctx.session_factory.client("ec2", region)
        vpcs_result, error = safe_call(ec2.describe_vpcs)
        if error:
            return [_error_finding(meta, error[0], error[1], region)]

        findings = []
        for vpc in vpcs_result.get("Vpcs", []):
            vpc_id = vpc["VpcId"]
            flow_logs_result, error = safe_call(
                ec2.describe_flow_logs, Filter=[{"Name": "resource-id", "Values": [vpc_id]}]
            )
            if error:
                findings.append(_error_finding(meta, error[0], error[1], region))
                continue
            active = any(fl.get("FlowLogStatus") == "ACTIVE" for fl in flow_logs_result.get("FlowLogs", []))
            status = Status.PASS if active else Status.FAIL
            findings.append(_finding(meta, status, vpc_id, region, {"has_active_flow_log": active}))
        return findings


@register_check(
    CheckMeta(
        check_id="ec2_007_instance_missing_iam_profile",
        title="EC2 instance has no IAM instance profile attached",
        service="ec2",
        severity=Severity.LOW,
        description=(
            "An EC2 instance has no IAM instance profile attached, suggesting it may rely on long-lived "
            "credentials instead of temporary role credentials. Note: presence of a profile is a weak proxy "
            "for actual usage - CIS itself marks this control Manual for that reason."
        ),
        remediation="Attach an IAM role to the instance: aws ec2 associate-iam-instance-profile --instance-id <id> --iam-instance-profile Name=<profile>.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html"],
        required_actions=["ec2:DescribeInstances"],
        scope="region",
        cis_benchmarks=["1.18"],
    )
)
class InstanceMissingIamProfileCheck(BaseCheck):
    def execute(self, ctx, region=None) -> list[Finding]:
        meta = self.meta
        ec2 = ctx.session_factory.client("ec2", region)

        findings = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": _NON_TERMINAL_INSTANCE_STATES}]
            ):
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        has_profile = "IamInstanceProfile" in instance
                        status = Status.PASS if has_profile else Status.FAIL
                        findings.append(_finding(meta, status, instance["InstanceId"], region, {"has_iam_instance_profile": has_profile}))
        except (ClientError, BotoCoreError) as e:
            code = e.response["Error"]["Code"] if isinstance(e, ClientError) else type(e).__name__
            return [_error_finding(meta, code, str(e), region)]
        return findings
