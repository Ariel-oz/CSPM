from botocore.stub import Stubber

from cspm_scan.core.session import PreflightError, SessionFactory


def test_bad_profile_raises_preflight_error():
    import pytest

    with pytest.raises(PreflightError):
        SessionFactory(profile="__definitely_does_not_exist__")


def test_preflight_success_populates_account_and_regions(isolated_aws_profile):
    factory = SessionFactory(profile=isolated_aws_profile)

    sts_client = factory.client("sts", "us-east-1")
    sts_stub = Stubber(sts_client)
    sts_stub.add_response(
        "get_caller_identity",
        {"UserId": "AIDAEXAMPLE", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/scanner"},
    )
    sts_stub.activate()

    ec2_client = factory.client("ec2", "us-east-1")
    ec2_stub = Stubber(ec2_client)
    ec2_stub.add_response(
        "describe_regions",
        {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]},
        {"AllRegions": False},
    )
    ec2_stub.activate()

    identity = factory.preflight()

    assert identity["Account"] == "123456789012"
    assert factory.account_id == "123456789012"
    assert factory.regions == ["eu-west-1", "us-east-1"]

    sts_stub.deactivate()
    ec2_stub.deactivate()


def test_explicit_regions_skip_discovery(isolated_aws_profile):
    factory = SessionFactory(profile=isolated_aws_profile, regions=["ap-south-1"])

    sts_client = factory.client("sts", "us-east-1")
    sts_stub = Stubber(sts_client)
    sts_stub.add_response(
        "get_caller_identity",
        {"UserId": "AIDAEXAMPLE", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/scanner"},
    )
    sts_stub.activate()

    factory.preflight()

    assert factory.regions == ["ap-south-1"]
    sts_stub.deactivate()


def test_client_is_cached(isolated_aws_profile):
    factory = SessionFactory(profile=isolated_aws_profile)
    c1 = factory.client("s3", "us-east-1")
    c2 = factory.client("s3", "us-east-1")
    c3 = factory.client("s3", "eu-west-1")
    assert c1 is c2
    assert c1 is not c3
