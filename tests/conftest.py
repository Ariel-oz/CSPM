import os
import tempfile

import pytest


@pytest.fixture
def isolated_aws_profile():
    """Point boto3 at a throwaway, isolated AWS config/credentials pair so tests
    never depend on (or touch) the user's real ~/.aws files."""
    with tempfile.TemporaryDirectory() as tmp:
        config_path = os.path.join(tmp, "config")
        creds_path = os.path.join(tmp, "credentials")
        with open(config_path, "w") as f:
            f.write("[profile testprofile]\nregion = us-east-1\n")
        with open(creds_path, "w") as f:
            f.write("[testprofile]\naws_access_key_id = AKIAFAKEFAKEFAKEFAKE\naws_secret_access_key = fakefakefakefakefakefakefakefakefakefake\n")

        old_config = os.environ.get("AWS_CONFIG_FILE")
        old_creds = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
        os.environ["AWS_CONFIG_FILE"] = config_path
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = creds_path
        try:
            yield "testprofile"
        finally:
            if old_config is None:
                os.environ.pop("AWS_CONFIG_FILE", None)
            else:
                os.environ["AWS_CONFIG_FILE"] = old_config
            if old_creds is None:
                os.environ.pop("AWS_SHARED_CREDENTIALS_FILE", None)
            else:
                os.environ["AWS_SHARED_CREDENTIALS_FILE"] = old_creds
