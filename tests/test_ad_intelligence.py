import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from backend.intelligence.ad_detector import ADIntelligenceDetector


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
def detector(sio_mock, slack_mock, profile_store):
    return ADIntelligenceDetector(
        sio=sio_mock,
        slack_alert_fn=slack_mock,
        profile_store=profile_store,
    )


@pytest.mark.asyncio
async def test_domain_admin_detection(detector):
    result = await detector.analyze_query("10.0.0.5", "(memberOf=Domain Admins)")
    assert result is not None
    assert result["type"] == "domain_admin_discovery"
    assert result["severity"] == "high"
    assert result["mitre"] == "T1087.002"


@pytest.mark.asyncio
async def test_service_account_detection(detector):
    result = await detector.analyze_query("10.0.0.5", "(sAMAccountName=svc_backup)")
    assert result is not None
    assert result["type"] == "service_account_discovery"
    assert result["severity"] == "high"
    assert result["mitre"] == "T1087.002"


@pytest.mark.asyncio
async def test_password_discovery(detector):
    result = await detector.analyze_query("10.0.0.5", "(description=*Password*)")
    assert result is not None
    assert result["type"] == "credential_exposure_discovery"
    assert result["severity"] == "critical"
    assert result["mitre"] == "T1552"


@pytest.mark.asyncio
async def test_socketio_event_emitted(detector, sio_mock):
    await detector.analyze_query("10.0.0.5", "(memberOf=Domain Admins)")
    sio_mock.emit.assert_any_call("ad_enumeration", {
        "attacker_ip": "10.0.0.5",
        "query": "(memberOf=Domain Admins)",
        "severity": "high",
        "event_type": "domain_admin_discovery",
        "mitre": "T1087.002",
        "timestamp": pytest.approx(sio_mock.emit.call_args_list[0][0][1]["timestamp"], abs=2),
    })


@pytest.mark.asyncio
async def test_mitre_mapping(detector):
    result = await detector.analyze_query("10.0.0.5", "(description=*Password*)")
    assert result["mitre"] == "T1552"
    assert result["mitre_name"] == "Unsecured Credentials"
    assert result["tactic"] == "Credential Access"


@pytest.mark.asyncio
async def test_alert_generation(detector):
    await detector.analyze_query("10.0.0.5", "(memberOf=Domain Admins)")
    alerts = detector.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["mitre_technique_id"] == "T1087.002"
    assert "Domain Admins" in alerts[0]["message"]


@pytest.mark.asyncio
async def test_slack_notification(detector, slack_mock):
    await detector.analyze_query("10.0.0.5", "(memberOf=Domain Admins)")
    slack_mock.assert_called_once()
    call_kwargs = slack_mock.call_args[1]
    assert call_kwargs["severity"] == "high"
    assert "Domain Admins" in call_kwargs["message"]


@pytest.mark.asyncio
async def test_slack_failure_handling(sio_mock, profile_store):
    failing_slack = AsyncMock(side_effect=Exception("Slack down"))
    detector = ADIntelligenceDetector(
        sio=sio_mock,
        slack_alert_fn=failing_slack,
        profile_store=profile_store,
    )
    result = await detector.analyze_query("10.0.0.5", "(memberOf=Domain Admins)")
    assert result is not None
    assert result["type"] == "domain_admin_discovery"


@pytest.mark.asyncio
async def test_profile_update(detector, profile_store):
    await detector.analyze_query("10.0.0.5", "(memberOf=Domain Admins)")
    profile = profile_store["10.0.0.5"]
    assert "Privilege Escalation" in profile["objectives"]
    assert "T1087.002" in profile["techniques_observed"]
    assert profile["confidence"] > 0.0


@pytest.mark.asyncio
async def test_profile_update_credential_access(detector, profile_store):
    await detector.analyze_query("10.0.0.5", "(description=*Password*)")
    profile = profile_store["10.0.0.5"]
    assert "Credential Access" in profile["objectives"]
    assert "T1552" in profile["techniques_observed"]


@pytest.mark.asyncio
async def test_confidence_increases(detector, profile_store):
    await detector.analyze_query("10.0.0.5", "(memberOf=Domain Admins)")
    c1 = profile_store["10.0.0.5"]["confidence"]
    await detector.analyze_query("10.0.0.5", "(description=*Password*)")
    c2 = profile_store["10.0.0.5"]["confidence"]
    assert c2 > c1


@pytest.mark.asyncio
async def test_no_detection_for_normal_query(detector):
    result = await detector.analyze_query("10.0.0.5", "(objectClass=user)")
    assert result is None
    assert len(detector.get_alerts()) == 0


@pytest.mark.asyncio
async def test_critical_severity_takes_priority(detector):
    result = await detector.analyze_query(
        "10.0.0.5",
        "(description=*Password*)"
    )
    assert result["severity"] == "critical"
