"""
ShadowMesh — Task 12.1D: AD Intelligence Detector
==================================================
Detects high-value Active Directory enumeration patterns, generates alerts,
maps to MITRE ATT&CK, updates attacker profiles, and sends Slack notifications.

Detection triggers:
  - Domain Admin enumeration  → T1087.002 (Account Discovery: Domain Account)
  - Service account discovery → T1087.002
  - Password-in-description  → T1552 (Unsecured Credentials)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("ad_detector")


class ADIntelligenceDetector:

    def __init__(self, sio=None, slack_alert_fn=None, profile_store: Optional[Dict] = None):
        self.sio = sio
        self.slack_alert_fn = slack_alert_fn
        self.profile_store: Dict[str, Dict] = profile_store if profile_store is not None else {}
        self._alert_log: List[Dict] = []

    def get_alerts(self) -> List[Dict]:
        return list(self._alert_log)

    async def analyze_query(self, attacker_ip: str, query: str, node_id: str = "fake-auth-node") -> Optional[Dict]:
        detections = []

        da = self.detect_domain_admin_enumeration(query)
        if da:
            detections.append(da)

        svc = self.detect_service_account_discovery(query)
        if svc:
            detections.append(svc)

        pwd = self.detect_password_discovery(query)
        if pwd:
            detections.append(pwd)

        if not detections:
            return None

        highest = max(detections, key=lambda d: 1 if d["severity"] == "critical" else 0)

        await self._emit_event(attacker_ip, query, highest)
        await self._generate_alert(attacker_ip, highest)
        await self._send_slack(attacker_ip, highest)
        self._update_profile(attacker_ip, highest)

        return highest

    def detect_domain_admin_enumeration(self, query: str) -> Optional[Dict]:
        q = query.lower()
        if "domain admins" in q or "domain admin" in q:
            return {
                "severity": "high",
                "type": "domain_admin_discovery",
                "mitre": "T1087.002",
                "mitre_name": "Account Discovery: Domain Account",
                "tactic": "Discovery",
                "message": "Attacker enumerated Domain Admins — possible privilege escalation planning",
            }
        return None

    def detect_service_account_discovery(self, query: str) -> Optional[Dict]:
        q = query.lower()
        if "svc_" in q or "service account" in q:
            return {
                "severity": "high",
                "type": "service_account_discovery",
                "mitre": "T1087.002",
                "mitre_name": "Account Discovery: Domain Account",
                "tactic": "Discovery",
                "message": "Attacker discovered service account credentials",
            }
        return None

    def detect_password_discovery(self, query: str) -> Optional[Dict]:
        q = query.lower()
        if "password" in q and ("description" in q or "*" in q):
            return {
                "severity": "critical",
                "type": "credential_exposure_discovery",
                "mitre": "T1552",
                "mitre_name": "Unsecured Credentials",
                "tactic": "Credential Access",
                "message": "Attacker located credentials embedded in AD descriptions",
            }
        return None

    async def _emit_event(self, attacker_ip: str, query: str, detection: Dict) -> None:
        if not self.sio:
            return
        try:
            await self.sio.emit("ad_enumeration", {
                "attacker_ip": attacker_ip,
                "query": query,
                "severity": detection["severity"],
                "event_type": detection["type"],
                "mitre": detection["mitre"],
                "timestamp": time.time(),
            })
        except Exception as e:
            log.warning("[ad_detector] Socket.IO emit failed: %s", e)

    async def _generate_alert(self, attacker_ip: str, detection: Dict) -> None:
        alert = {
            "attacker_ip": attacker_ip,
            "severity": detection["severity"],
            "type": detection["type"],
            "message": detection["message"],
            "mitre_technique_id": detection["mitre"],
            "mitre_technique_name": detection["mitre_name"],
            "tactic": detection["tactic"],
            "timestamp": time.time(),
        }
        self._alert_log.append(alert)

        if self.sio:
            try:
                await self.sio.emit("alert", {
                    "message": detection["message"],
                    "severity": detection["severity"],
                })
            except Exception as e:
                log.warning("[ad_detector] Alert emit failed: %s", e)

    async def _send_slack(self, attacker_ip: str, detection: Dict) -> None:
        if not self.slack_alert_fn:
            return
        try:
            severity_label = "Critical Alert" if detection["severity"] == "critical" else "High Alert"
            await self.slack_alert_fn(
                message=f"{severity_label}: {detection['message']} (from {attacker_ip})",
                severity=detection["severity"],
                fields={
                    "Attacker IP": attacker_ip,
                    "Detection Type": detection["type"],
                    "MITRE Technique": f"{detection['mitre']} — {detection['mitre_name']}",
                    "Tactic": detection["tactic"],
                },
            )
        except Exception as e:
            log.warning("[ad_detector] Slack alert failed: %s", e)

    def _update_profile(self, attacker_ip: str, detection: Dict) -> None:
        profile = self.profile_store.get(attacker_ip)
        if profile is None:
            profile = {
                "objectives": [],
                "confidence": 0.0,
                "techniques_observed": [],
            }
            self.profile_store[attacker_ip] = profile

        technique = detection["mitre"]
        if technique not in profile.get("techniques_observed", []):
            profile.setdefault("techniques_observed", []).append(technique)

        if detection["type"] == "domain_admin_discovery":
            obj = "Privilege Escalation"
        elif detection["type"] == "credential_exposure_discovery":
            obj = "Credential Access"
        elif detection["type"] == "service_account_discovery":
            obj = "Privilege Escalation"
        else:
            obj = "Discovery"

        if obj not in profile.get("objectives", []):
            profile.setdefault("objectives", []).append(obj)

        profile["confidence"] = min(1.0, profile.get("confidence", 0.0) + 0.2)
