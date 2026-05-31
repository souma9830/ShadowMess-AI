import pytest
import time
import json
from unittest.mock import AsyncMock, MagicMock, patch
from backend.integrations.siem import SIEMIntegration
from backend.models import AttackerAction, AttackerProfile
from backend.detection.surface_mapper import AttackSurfaceMapper


# ---------------------------------------------------------------------------
# Task 13.1 — SIEM Integration Tests
# ---------------------------------------------------------------------------

class TestSIEMIntegration:

    def setup_method(self):
        self.siem = SIEMIntegration()
        self.action = AttackerAction(
            attacker_ip="10.0.0.5",
            action_type="credential_theft",
            target_node_id="node-3",
            detail="Stole .aws/credentials",
            timestamp=time.time(),
            mitre_technique_id="T1552.001",
            mitre_technique_name="Unsecured Credentials: Credentials In Files",
        )
        self.profile = AttackerProfile(
            attacker_ip="10.0.0.5",
            skill_level="Advanced",
            objective="Cloud Access",
            apt_resemblance="APT29",
            tools_detected=["nmap", "aws-cli"],
            confidence=0.85,
            summary="Advanced attacker targeting cloud.",
        )

    def test_build_event_payload(self):
        payload = self.siem._build_event_payload(self.action, self.profile)
        assert payload["action"] == "credential_theft"
        assert payload["src_ip"] == "10.0.0.5"
        assert payload["mitre_id"] == "T1552.001"
        assert payload["skill_level"] == "Advanced"
        assert payload["severity"] == "critical"

    def test_build_event_payload_no_profile(self):
        payload = self.siem._build_event_payload(self.action, None)
        assert payload["skill_level"] == "unknown"
        assert payload["objective"] == "unknown"

    def test_build_event_payload_dict_profile(self):
        profile_dict = {"skill_level": "Intermediate", "objective": "Recon"}
        payload = self.siem._build_event_payload(self.action, profile_dict)
        assert payload["skill_level"] == "Intermediate"

    @pytest.mark.asyncio
    async def test_splunk_no_url_noop(self):
        self.siem.splunk_hec_url = ""
        await self.siem.send_to_splunk(self.action)

    @pytest.mark.asyncio
    async def test_elastic_no_url_noop(self):
        self.siem.elastic_url = ""
        await self.siem.send_to_elastic(self.action)

    @pytest.mark.asyncio
    async def test_sentinel_no_config_noop(self):
        self.siem.sentinel_workspace_id = ""
        await self.siem.send_to_sentinel(self.action)

    @pytest.mark.asyncio
    async def test_syslog_no_host_noop(self):
        self.siem.syslog_host = ""
        await self.siem.send_syslog_cef(self.action)

    @pytest.mark.asyncio
    async def test_send_all_no_crash(self):
        await self.siem.send_all(self.action, self.profile)

    @pytest.mark.asyncio
    async def test_splunk_failure_handled(self):
        self.siem.splunk_hec_url = "http://nonexistent:9999"
        self.siem.splunk_hec_token = "fake-token"
        await self.siem.send_to_splunk(self.action)

    @pytest.mark.asyncio
    async def test_elastic_failure_handled(self):
        self.siem.elastic_url = "http://nonexistent:9999"
        await self.siem.send_to_elastic(self.action)

    def test_severity_critical_for_cred_theft(self):
        payload = self.siem._build_event_payload(self.action, None)
        assert payload["severity"] == "critical"

    def test_severity_high_for_port_scan(self):
        scan_action = AttackerAction(
            attacker_ip="10.0.0.5", action_type="port_scan",
            target_node_id="node-1", detail="SYN scan", timestamp=time.time(),
        )
        payload = self.siem._build_event_payload(scan_action, None)
        assert payload["severity"] == "high"


# ---------------------------------------------------------------------------
# Task 13.2 — Breadcrumb Agent Tests
# ---------------------------------------------------------------------------

class TestBreadcrumbAgent:

    def test_import(self):
        from agents.breadcrumb_agent import BreadcrumbAgent
        agent = BreadcrumbAgent(server_url="http://localhost:8000")
        assert agent.server_url == "http://localhost:8000"

    def test_cleanup_tag(self):
        from agents.breadcrumb_agent import BREADCRUMB_TAG
        assert "corp-infra-managed" in BREADCRUMB_TAG

    def test_plant_aws_credentials_format(self, tmp_path, monkeypatch):
        from agents.breadcrumb_agent import BreadcrumbAgent
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        agent = BreadcrumbAgent()
        result = agent.plant_aws_credentials([{"ip": "172.20.0.10", "node_type": "db_server"}])
        assert "[corp-prod]" in result
        assert "aws_access_key_id" in result
        creds_file = tmp_path / ".aws" / "credentials"
        assert creds_file.exists()
        assert "AKIA" in creds_file.read_text()

    def test_plant_bash_history(self, tmp_path, monkeypatch):
        from agents.breadcrumb_agent import BreadcrumbAgent
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        (tmp_path / ".bash_history").write_text("")
        agent = BreadcrumbAgent()
        nodes = [
            {"ip": "172.20.0.10", "node_type": "db_server"},
            {"ip": "172.20.0.11", "node_type": "web_server"},
        ]
        commands = agent.plant_bash_history(nodes)
        assert any("mysql" in c for c in commands)
        assert any("curl" in c for c in commands)

    def test_cleanup(self, tmp_path, monkeypatch):
        from agents.breadcrumb_agent import BreadcrumbAgent, BREADCRUMB_TAG
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        history = tmp_path / ".bash_history"
        history.write_text(f"real command\nfake command  {BREADCRUMB_TAG}\nanother real\n")
        agent = BreadcrumbAgent()
        removed = agent.cleanup()
        assert removed == 1
        assert BREADCRUMB_TAG not in history.read_text()
        assert "real command" in history.read_text()


# ---------------------------------------------------------------------------
# Task 13.3 — Surface Mapper Tests
# ---------------------------------------------------------------------------

class TestSurfaceMapper:

    def test_init(self):
        mapper = AttackSurfaceMapper(subnet="10.0.0.0/24", interface="eth0")
        assert mapper.subnet == "10.0.0.0/24"

    def test_default_distribution(self):
        mapper = AttackSurfaceMapper()
        dist = mapper._default_distribution()
        assert sum(dist.values()) > 0
        assert "web_server" in dist
        assert "db_server" in dist

    def test_tcp_connect_closed_port(self):
        result = AttackSurfaceMapper._tcp_connect("127.0.0.1", 59999)
        assert result is False

    def test_get_stats(self):
        mapper = AttackSurfaceMapper(subnet="192.168.1.0/24")
        stats = mapper.get_stats()
        assert stats["subnet"] == "192.168.1.0/24"
        assert stats["discovered_hosts"] == 0

    @pytest.mark.asyncio
    async def test_generate_mirrored_topology_fallback(self):
        mapper = AttackSurfaceMapper(subnet="192.168.99.0/24")
        result = await mapper.generate_mirrored_topology(target_count=14)
        assert "weights" in result
        assert len(result["weights"]) == 7
        assert abs(sum(result["weights"]) - 1.0) < 0.01
