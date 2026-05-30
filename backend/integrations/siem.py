"""
ShadowMesh — Task 13.1: SIEM/SOAR Integration
==============================================
Native integrations for Splunk HEC, Elasticsearch, Microsoft Sentinel,
and CEF syslog. Every attacker action is forwarded to configured SIEMs
in the background — never blocks the request path.

All methods are async, wrapped in try/except. SIEM failure must NEVER
crash the main application.

Environment variables:
  SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN
  ELASTIC_URL, ELASTIC_API_KEY
  SENTINEL_WORKSPACE_ID, SENTINEL_SHARED_KEY
  SYSLOG_HOST, SYSLOG_PORT
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from backend.models import AttackerAction

log = logging.getLogger("siem")


class SIEMIntegration:

    def __init__(self):
        self.splunk_hec_url = os.getenv("SPLUNK_HEC_URL", "")
        self.splunk_hec_token = os.getenv("SPLUNK_HEC_TOKEN", "")
        self.elastic_url = os.getenv("ELASTIC_URL", "")
        self.elastic_api_key = os.getenv("ELASTIC_API_KEY", "")
        self.sentinel_workspace_id = os.getenv("SENTINEL_WORKSPACE_ID", "")
        self.sentinel_shared_key = os.getenv("SENTINEL_SHARED_KEY", "")
        self.syslog_host = os.getenv("SYSLOG_HOST", "")
        self.syslog_port = int(os.getenv("SYSLOG_PORT", "514"))

    def _build_event_payload(self, action: AttackerAction, profile: Any = None) -> dict:
        if profile and isinstance(profile, dict):
            skill = profile.get("skill_level", "unknown")
            objective = profile.get("objective", "unknown")
        elif profile:
            skill = getattr(profile, "skill_level", "unknown")
            objective = getattr(profile, "objective", "unknown")
        else:
            skill = "unknown"
            objective = "unknown"

        severity = "critical" if action.action_type in ("credential_theft", "canary_trigger") else "high"

        return {
            "action": action.action_type,
            "src_ip": action.attacker_ip,
            "dest": action.target_node_id,
            "detail": action.detail,
            "mitre_id": action.mitre_technique_id,
            "mitre_name": action.mitre_technique_name,
            "skill_level": skill,
            "objective": objective,
            "severity": severity,
            "timestamp": action.timestamp,
        }

    async def send_to_splunk(self, action: AttackerAction, profile: Any = None) -> None:
        if not self.splunk_hec_url or not self.splunk_hec_token:
            return

        event_data = self._build_event_payload(action, profile)
        payload = {
            "time": action.timestamp,
            "host": "shadowmesh",
            "source": "shadowmesh:deception",
            "sourcetype": "shadowmesh:attacker_action",
            "index": "security",
            "event": event_data,
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    f"{self.splunk_hec_url}/services/collector",
                    json=payload,
                    headers={"Authorization": f"Splunk {self.splunk_hec_token}"},
                )
                log.debug("[siem] Splunk HEC: %d", resp.status_code)
        except Exception as e:
            log.warning("[siem] Splunk send failed: %s", e)

    async def send_to_elastic(self, action: AttackerAction, profile: Any = None) -> None:
        if not self.elastic_url:
            return

        dt = datetime.fromtimestamp(action.timestamp, tz=timezone.utc)
        index = f"shadowmesh-deception-{dt.strftime('%Y.%m.%d')}"

        doc = {
            "@timestamp": dt.isoformat(),
            "event.action": action.action_type,
            "source.ip": action.attacker_ip,
            "destination.domain": action.target_node_id,
            "message": action.detail,
            "threat.technique.id": [action.mitre_technique_id] if action.mitre_technique_id else [],
            "threat.technique.name": [action.mitre_technique_name] if action.mitre_technique_name else [],
            "tags": ["shadowmesh", "deception", "honeypot"],
        }

        headers = {"Content-Type": "application/json"}
        if self.elastic_api_key:
            headers["Authorization"] = f"ApiKey {self.elastic_api_key}"

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    f"{self.elastic_url}/{index}/_doc",
                    json=doc,
                    headers=headers,
                )
                log.debug("[siem] Elastic: %d", resp.status_code)
        except Exception as e:
            log.warning("[siem] Elastic send failed: %s", e)

    async def send_to_sentinel(self, action: AttackerAction, profile: Any = None) -> None:
        if not self.sentinel_workspace_id or not self.sentinel_shared_key:
            return

        event_data = self._build_event_payload(action, profile)
        body = json.dumps([event_data])
        content_length = len(body)

        rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        string_to_sign = f"POST\n{content_length}\napplication/json\nx-ms-date:{rfc1123_date}\n/api/logs"

        try:
            decoded_key = base64.b64decode(self.sentinel_shared_key)
            signature = base64.b64encode(
                hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
            ).decode("utf-8")

            auth = f"SharedKey {self.sentinel_workspace_id}:{signature}"
            url = f"https://{self.sentinel_workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": auth,
                        "Log-Type": "ShadowMeshDeception",
                        "x-ms-date": rfc1123_date,
                    },
                )
                log.debug("[siem] Sentinel: %d", resp.status_code)
        except Exception as e:
            log.warning("[siem] Sentinel send failed: %s", e)

    async def send_syslog_cef(self, action: AttackerAction, profile: Any = None) -> None:
        if not self.syslog_host:
            return

        severity = 7 if action.action_type in ("credential_theft", "canary_trigger") else 5
        mitre_id = action.mitre_technique_id or ""
        mitre_name = action.mitre_technique_name or ""

        cef = (
            f"CEF:0|ShadowMesh|DeceptionPlatform|1.0|{action.action_type}|"
            f"{action.detail[:128]}|{severity}|"
            f"src={action.attacker_ip} dst={action.target_node_id} "
            f"cs1={mitre_id} cs1Label=MITRETechnique "
            f"cs2={mitre_name} cs2Label=MITREName "
            f"rt={int(action.timestamp * 1000)}"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(cef.encode("utf-8"), (self.syslog_host, self.syslog_port))
            sock.close()
            log.debug("[siem] Syslog CEF sent to %s:%d", self.syslog_host, self.syslog_port)
        except Exception as e:
            log.warning("[siem] Syslog send failed: %s", e)

    async def send_all(self, action: AttackerAction, profile: Any = None) -> None:
        await self.send_to_splunk(action, profile)
        await self.send_to_elastic(action, profile)
        await self.send_to_sentinel(action, profile)
        await self.send_syslog_cef(action, profile)


siem = SIEMIntegration()
