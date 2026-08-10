"""boto3 session/client construction: preflight auth check, region discovery, client caching, retries."""

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})


class PreflightError(RuntimeError):
    """Raised when the profile/credentials can't authenticate to AWS at all."""


class SessionFactory:
    def __init__(self, profile: str, regions: list[str] | None = None):
        self.profile = profile
        try:
            self.session = boto3.Session(profile_name=profile)
        except Exception as e:  # botocore.exceptions.ProfileNotFound, etc.
            raise PreflightError(f"Could not load AWS profile '{profile}': {e}") from e
        self._client_cache: dict[tuple[str, str], object] = {}
        self._explicit_regions = regions
        self.account_id: str | None = None
        self.regions: list[str] = []

    def preflight(self) -> dict:
        """Fail fast with a clear message if the profile/creds are bad. Also resolves regions."""
        sts = self.client("sts", "us-east-1")
        try:
            identity = sts.get_caller_identity()
        except (ClientError, BotoCoreError) as e:
            raise PreflightError(
                f"Profile '{self.profile}' failed to authenticate to AWS: {e}"
            ) from e
        self.account_id = identity["Account"]
        self.regions = self._explicit_regions or self._discover_enabled_regions()
        return identity

    def _discover_enabled_regions(self) -> list[str]:
        ec2 = self.client("ec2", "us-east-1")
        resp = ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])

    def client(self, service: str, region: str):
        key = (service, region)
        if key not in self._client_cache:
            self._client_cache[key] = self.session.client(
                service, region_name=region, config=RETRY_CONFIG
            )
        return self._client_cache[key]
