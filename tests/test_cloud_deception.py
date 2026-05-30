import pytest
from unittest.mock import AsyncMock, MagicMock
from backend.deception.cloud_deception import (
    CloudCredentialGenerator,
    CloudIntelManager,
    get_sts_caller_identity,
    get_iam_list_users,
)


# ---------------------------------------------------------------------------
# Credential Generation Tests
# ---------------------------------------------------------------------------

class TestCloudCredentialGenerator:

    def setup_method(self):
        self.gen = CloudCredentialGenerator(seed="test-seed")

    def test_aws_credential_generation(self):
        creds = self.gen.generate_aws_credentials()
        assert creds["access_key_id"].startswith("AKIA")
        assert len(creds["access_key_id"]) == 20
        assert len(creds["secret_access_key"]) > 20
        assert creds["region"] == "us-east-1"
        assert len(creds["account_id"]) == 12
        assert creds["account_id"].isdigit()

    def test_aws_credentials_file_format(self):
        content = self.gen.to_aws_credentials_file()
        assert "[default]" in content
        assert "aws_access_key_id" in content
        assert "aws_secret_access_key" in content
        assert "region" in content

    def test_azure_credential_generation(self):
        creds = self.gen.generate_azure_credentials()
        assert "clientId" in creds
        assert "clientSecret" in creds
        assert "subscriptionId" in creds
        assert "tenantId" in creds
        assert "activeDirectoryEndpointUrl" in creds
        assert "resourceManagerEndpointUrl" in creds
        assert "DO NOT SHARE" in creds["description"]

    def test_gcp_service_account_generation(self):
        creds = self.gen.generate_gcp_service_account()
        assert creds["type"] == "service_account"
        assert "project_id" in creds
        assert "private_key_id" in creds
        assert "BEGIN RSA PRIVATE KEY" in creds["private_key"]
        assert "END RSA PRIVATE KEY" in creds["private_key"]
        assert creds["client_email"].endswith(".iam.gserviceaccount.com")
        assert creds["auth_uri"] == "https://accounts.google.com/o/oauth2/auth"
        assert creds["token_uri"] == "https://oauth2.googleapis.com/token"


# ---------------------------------------------------------------------------
# Fake AWS API Data Tests
# ---------------------------------------------------------------------------

class TestFakeAWSAPI:

    def test_sts_caller_identity(self):
        result = get_sts_caller_identity()
        assert "UserId" in result
        assert "Account" in result
        assert "Arn" in result
        assert "arn:aws:iam::" in result["Arn"]

    def test_iam_list_users(self):
        result = get_iam_list_users()
        assert "Users" in result
        assert len(result["Users"]) == 10
        usernames = [u["UserName"] for u in result["Users"]]
        assert "admin" in usernames
        assert "devops-deploy" in usernames
        assert "ci-cd-runner" in usernames
        assert "finance-reports" in usernames
        assert "backup-service" in usernames


# ---------------------------------------------------------------------------
# Intelligence Manager Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def sio_mock():
    mock = MagicMock()
    mock.emit = AsyncMock()
    return mock


@pytest.fixture
def slack_mock():
    return AsyncMock()


@pytest.fixture
def profile_store():
    return {}


@pytest.fixture
def intel(sio_mock, slack_mock, profile_store):
    return CloudIntelManager(
        sio=sio_mock,
        slack_alert_fn=slack_mock,
        profile_store=profile_store,
    )


@pytest.mark.asyncio
async def test_get_caller_identity_detection(intel):
    result = await intel.record_api_call("10.0.0.5", "aws", "GetCallerIdentity")
    assert result is not None
    assert result["event_type"] == "cloud_credential_used"
    assert result["severity"] == "high"
    assert result["mitre"] == "T1552.001"


@pytest.mark.asyncio
async def test_list_users_detection(intel):
    result = await intel.record_api_call("10.0.0.5", "aws", "ListUsers")
    assert result is not None
    assert result["event_type"] == "cloud_account_discovery"
    assert result["severity"] == "high"
    assert result["mitre"] == "T1087.004"


@pytest.mark.asyncio
async def test_catch_all_detection(intel):
    result = await intel.record_api_call("10.0.0.5", "aws", "ec2/DescribeInstances")
    assert result is not None
    assert result["event_type"] == "cloud_api_access"
    assert result["severity"] == "medium"
    assert result["mitre"] == "T1526"


@pytest.mark.asyncio
async def test_socketio_event_emitted(intel, sio_mock):
    await intel.record_api_call("10.0.0.5", "aws", "GetCallerIdentity")
    sio_mock.emit.assert_any_call("cloud_credential_used", pytest.approx({
        "provider": "aws",
        "api_call": "GetCallerIdentity",
        "attacker_ip": "10.0.0.5",
        "severity": "high",
        "mitre": "T1552.001",
        "timestamp": pytest.approx(sio_mock.emit.call_args_list[0][0][1]["timestamp"], abs=2),
    }))


@pytest.mark.asyncio
async def test_alert_generation(intel):
    await intel.record_api_call("10.0.0.5", "aws", "GetCallerIdentity")
    alerts = intel.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["mitre_technique_id"] == "T1552.001"


@pytest.mark.asyncio
async def test_mitre_mappings(intel):
    await intel.record_api_call("10.0.0.5", "aws", "GetCallerIdentity")
    await intel.record_api_call("10.0.0.5", "aws", "ListUsers")
    await intel.record_api_call("10.0.0.5", "aws", "s3/ListBuckets")
    alerts = intel.get_alerts()
    techniques = {a["mitre_technique_id"] for a in alerts}
    assert "T1552.001" in techniques
    assert "T1087.004" in techniques
    assert "T1526" in techniques


@pytest.mark.asyncio
async def test_profile_update(intel, profile_store):
    await intel.record_api_call("10.0.0.5", "aws", "GetCallerIdentity")
    profile = profile_store["10.0.0.5"]
    assert "Cloud Access" in profile["objectives"]
    assert "T1552.001" in profile["techniques_observed"]
    assert profile["confidence"] > 0.0


@pytest.mark.asyncio
async def test_profile_escalation_on_repeated_calls(intel, profile_store):
    await intel.record_api_call("10.0.0.5", "aws", "GetCallerIdentity")
    await intel.record_api_call("10.0.0.5", "aws", "ListUsers")
    await intel.record_api_call("10.0.0.5", "aws", "ListRoles")
    profile = profile_store["10.0.0.5"]
    assert "Privilege Escalation" in profile["objectives"]


@pytest.mark.asyncio
async def test_slack_notification(intel, slack_mock):
    await intel.record_api_call("10.0.0.5", "aws", "GetCallerIdentity")
    slack_mock.assert_called_once()
    call_kwargs = slack_mock.call_args[1]
    assert call_kwargs["severity"] == "high"
    assert "credential" in call_kwargs["message"].lower() or "AWS" in call_kwargs["message"]


@pytest.mark.asyncio
async def test_slack_failure_handling(sio_mock, profile_store):
    failing_slack = AsyncMock(side_effect=Exception("Slack down"))
    intel = CloudIntelManager(sio=sio_mock, slack_alert_fn=failing_slack, profile_store=profile_store)
    result = await intel.record_api_call("10.0.0.5", "aws", "GetCallerIdentity")
    assert result is not None
    assert result["event_type"] == "cloud_credential_used"


@pytest.mark.asyncio
async def test_event_logging(intel):
    await intel.record_api_call("10.0.0.5", "aws", "GetCallerIdentity", {"method": "GET"})
    events = intel.get_events()
    assert len(events) == 1
    assert events[0]["provider"] == "aws"
    assert events[0]["api_call"] == "GetCallerIdentity"
    assert events[0]["request_details"] == {"method": "GET"}
