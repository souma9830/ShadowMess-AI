import pytest
import json
import time
from backend.intelligence.stix_exporter import STIXExporter, generate_stix_bundle
from backend.models import AttackerAction, AttackerProfile


@pytest.fixture
def profile():
    return AttackerProfile(
        attacker_ip="192.168.1.100",
        skill_level="Advanced",
        objective="Credential Access and Cloud Enumeration",
        apt_resemblance="APT29",
        tools_detected=["nmap", "hydra", "aws-cli"],
        confidence=0.85,
        summary="Advanced attacker targeting cloud infrastructure via AD enumeration and credential theft.",
    )


@pytest.fixture
def actions():
    base = time.time() - 600
    return [
        AttackerAction(
            attacker_ip="192.168.1.100",
            action_type="port_scan",
            target_node_id="node-1",
            detail="SYN scan on ports 22,80,443,389",
            timestamp=base,
            mitre_technique_id="T1046",
            mitre_technique_name="Network Service Discovery",
        ),
        AttackerAction(
            attacker_ip="192.168.1.100",
            action_type="ldap_search",
            target_node_id="fake-auth-node",
            detail="LDAP search: (memberOf=Domain Admins)",
            timestamp=base + 60,
            mitre_technique_id="T1087.002",
            mitre_technique_name="Account Discovery: Domain Account",
        ),
        AttackerAction(
            attacker_ip="192.168.1.100",
            action_type="credential_theft",
            target_node_id="node-3",
            detail="Stolen credential: .aws/credentials",
            timestamp=base + 180,
            mitre_technique_id="T1552.001",
            mitre_technique_name="Unsecured Credentials: Credentials In Files",
        ),
        AttackerAction(
            attacker_ip="192.168.1.100",
            action_type="cloud_api",
            target_node_id="fake-aws",
            detail="GetCallerIdentity",
            timestamp=base + 300,
            mitre_technique_id="T1552.001",
            mitre_technique_name="Unsecured Credentials: Credentials In Files",
        ),
        AttackerAction(
            attacker_ip="192.168.1.100",
            action_type="canary_trigger",
            target_node_id="node-5",
            detail="Canary accessed: secret-config.json",
            timestamp=base + 450,
        ),
    ]


@pytest.fixture
def exporter():
    return STIXExporter()


class TestThreatActorCreation:

    def test_threat_actor_in_bundle(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        objects = bundle["objects"]
        actors = [o for o in objects if o["type"] == "threat-actor"]
        assert len(actors) == 1
        actor = actors[0]
        assert actor["name"] == "APT29"
        assert actor["sophistication"] == "advanced"
        assert "192.168.1.100" in actor["aliases"]
        assert "Credential Access" in actor["description"]

    def test_sophistication_mapping(self, exporter, actions):
        for skill, expected in [("Script Kiddie", "minimal"), ("Intermediate", "intermediate"),
                                ("Advanced", "advanced"), ("Nation-State APT", "strategic")]:
            p = AttackerProfile(
                attacker_ip="10.0.0.1", skill_level=skill, objective="test",
                apt_resemblance="", tools_detected=[], confidence=0.5, summary="",
            )
            bundle = exporter.profile_to_stix_bundle(p, [])
            actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
            assert actors[0]["sophistication"] == expected


class TestToolCreation:

    def test_tools_in_bundle(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        objects = bundle["objects"]
        tools = [o for o in objects if o["type"] == "tool"]
        tool_names = {t["name"] for t in tools}
        assert "nmap" in tool_names
        assert "hydra" in tool_names
        assert "aws-cli" in tool_names
        assert len(tools) == 3


class TestAttackPatternCreation:

    def test_attack_patterns_in_bundle(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        objects = bundle["objects"]
        patterns = [o for o in objects if o["type"] == "attack-pattern"]
        technique_ids = set()
        for p in patterns:
            for ref in p.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_ids.add(ref["external_id"])
        assert "T1046" in technique_ids
        assert "T1087.002" in technique_ids
        assert "T1552.001" in technique_ids

    def test_deduplication(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        objects = bundle["objects"]
        patterns = [o for o in objects if o["type"] == "attack-pattern"]
        # T1552.001 appears twice in actions but should be deduplicated
        t1552_patterns = [p for p in patterns if any(
            r.get("external_id") == "T1552.001" for r in p.get("external_references", [])
        )]
        assert len(t1552_patterns) == 1

    def test_mitre_url_in_references(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        for p in patterns:
            for ref in p.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    assert "https://attack.mitre.org/techniques/" in ref["url"]


class TestIndicatorCreation:

    def test_indicator_in_bundle(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        objects = bundle["objects"]
        indicators = [o for o in objects if o["type"] == "indicator"]
        assert len(indicators) == 1
        ind = indicators[0]
        assert "192.168.1.100" in ind["pattern"]
        assert ind["pattern_type"] == "stix"


class TestRelationshipCreation:

    def test_uses_relationships(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        objects = bundle["objects"]
        rels = [o for o in objects if o["type"] == "relationship"]
        uses_rels = [r for r in rels if r["relationship_type"] == "uses"]
        # 3 tools + 3 unique techniques = 6 uses relationships
        assert len(uses_rels) == 6

    def test_attributed_to_relationship(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        objects = bundle["objects"]
        rels = [o for o in objects if o["type"] == "relationship"]
        attr_rels = [r for r in rels if r["relationship_type"] == "attributed-to"]
        assert len(attr_rels) == 1


class TestBundleGeneration:

    def test_bundle_structure(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert bundle["id"].startswith("bundle--")
        assert "objects" in bundle
        assert len(bundle["objects"]) > 0

    def test_report_in_bundle(self, exporter, profile, actions):
        bundle = exporter.profile_to_stix_bundle(profile, actions)
        reports = [o for o in bundle["objects"] if o["type"] == "report"]
        assert len(reports) == 1
        report = reports[0]
        assert "192.168.1.100" in report["name"]
        assert "nmap" in report["description"]
        assert "object_refs" in report

    def test_backward_compatible_function(self, profile, actions):
        bundle = generate_stix_bundle("192.168.1.100", profile, actions)
        assert bundle["type"] == "bundle"
        actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
        assert len(actors) == 1

    def test_dict_profile_support(self, exporter, actions):
        profile_dict = {
            "attacker_ip": "10.0.0.5",
            "skill_level": "Intermediate",
            "objective": "Data Exfiltration",
            "apt_resemblance": "",
            "tools_detected": ["curl"],
            "confidence": 0.6,
            "summary": "Intermediate attacker.",
        }
        bundle = exporter.profile_to_stix_bundle(profile_dict, actions)
        assert bundle["type"] == "bundle"
        actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
        assert actors[0]["sophistication"] == "intermediate"


class TestHTMLReport:

    def test_html_report_generation(self, exporter, profile, actions):
        html = exporter.generate_html_report("192.168.1.100", profile, actions)
        assert "<!DOCTYPE html>" in html
        assert "192.168.1.100" in html
        assert "APT29" in html
        assert "T1046" in html
        assert "T1087.002" in html
        assert "nmap" in html
        assert "Recommended Actions" in html

    def test_html_report_sections(self, exporter, profile, actions):
        html = exporter.generate_html_report("192.168.1.100", profile, actions)
        assert "Threat Assessment" in html
        assert "MITRE ATT&amp;CK Summary" in html or "MITRE ATT&CK Summary" in html
        assert "Activity Breakdown" in html
        assert "Session Timeline" in html
        assert "Cloud Activity" in html
        assert "AD Enumeration" in html
        assert "Credential Theft" in html
        assert "Canary Triggers" in html
