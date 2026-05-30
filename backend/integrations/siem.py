"""
Task 13.1 — SIEM/SOAR Integration
Sends attacker action events to Splunk HEC, Elastic (ECS), Microsoft Sentinel,
and generic CEF syslog — so alerts appear in any existing SOC dashboard.

All methods are fire-and-forget: SIEM failures must never crash the main app.
"""

import os
import json
import time
import hmac
import hashlib
import base64
import socket
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from backend.models import AttackerAction, AttackerProfile

logger = logging.getLogger("shadowmesh.siem")

# ---------------------------------------------------------------------------
# Severity helper
# ---------------------------------------------------------------------------
_HIGH_SEVERITY_ACTIONS = {"credential_theft", "canary_trigger", "lateral_move"}


def _severity(action_type: str) -> str:
    return "critical" if action_type in _HIGH_SEVERITY_ACTIONS else "high"


# ---------------------------------------------------------------------------
# SIEMIntegration
# ---------------------------------------------------------------------------

class SIEMIntegration:
    """
    Native SIEM/SOAR integration for ShadowMesh.
    Reads credentials from environment variables — unconfigured destinations
    are silently skipped so a missing key never blocks the main flow.
    """

    def __init__(self) -> None:
        self.splunk_hec_url   = os.getenv("SPLUNK_HEC_URL", "")
        self.splunk_hec_token = os.getenv("SPLUNK_HEC_TOKEN", "")
        self.elastic_url      = os.getenv("ELASTIC_URL", "")
        self.elastic_api_key  = os.getenv("ELASTIC_API_KEY", "")
        self.sentinel_workspace_id = os.getenv("SENTINEL_WORKSPACE_ID", "")
        self.sentinel_shared_key   = os.getenv("SENTINEL_SHARED_KEY", "")
        self.syslog_host      = os.getenv("SYSLOG_HOST", "localhost")
        self.syslog_port      = int(os.getenv("SYSLOG_PORT", "514"))

    # ------------------------------------------------------------------
    # 1. Splunk HEC
    # ------------------------------------------------------------------
    async def send_to_splunk(
        self,
        event: AttackerAction,
        profile: Optional[AttackerProfile] = None,
    ) -> None:
        """POST a Splunk HTTP Event Collector (HEC) JSON event."""
        if not (self.splunk_hec_url and self.splunk_hec_token):
            return
        try:
            payload = {
                "time": event.timestamp,
                "host": "shadowmesh",
                "source": "shadowmesh:deception",
                "sourcetype": "shadowmesh:attacker_action",
                "index": "security",
                "event": {
                    "action":       event.action_type,
                    "src_ip":       event.attacker_ip,
                    "dest":         event.target_node_id,
                    "detail":       event.detail,
                    "mitre_id":     event.mitre_technique_id or "",
                    "mitre_name":   event.mitre_technique_name or "",
                    "skill_level":  profile.skill_level if profile else "unknown",
                    "objective":    profile.objective  if profile else "unknown",
                    "severity":     _severity(event.action_type),
                },
            }
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    f"{self.splunk_hec_url}/services/collector",
                    json=payload,
                    headers={"Authorization": f"Splunk {self.splunk_hec_token}"},
                )
                resp.raise_for_status()
                logger.debug("Splunk HEC → %s", resp.status_code)
        except Exception as exc:
            logger.warning("Splunk HEC send failed (non-critical): %s", exc)

    # ------------------------------------------------------------------
    # 2. Elastic / ECS
    # ------------------------------------------------------------------
    async def send_to_elastic(self, event: AttackerAction) -> None:
        """
        POST an Elastic Common Schema (ECS) document to the configured cluster.
        Index pattern: shadowmesh-deception-YYYY.MM.DD
        """
        if not (self.elastic_url and self.elastic_api_key):
            return
        try:
            ts = datetime.fromtimestamp(event.timestamp, tz=timezone.utc)
            index_name = f"shadowmesh-deception-{ts.strftime('%Y.%m.%d')}"
            doc = {
                "@timestamp":          ts.isoformat(),
                "event.action":        event.action_type,
                "event.severity":      _severity(event.action_type),
                "source.ip":           event.attacker_ip,
                "destination.domain":  event.target_node_id,
                "threat.technique.id": [event.mitre_technique_id or ""],
                "message":             event.detail,
                "tags":                ["shadowmesh", "deception", "honeypot"],
            }
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    f"{self.elastic_url}/{index_name}/_doc",
                    json=doc,
                    headers={"Authorization": f"ApiKey {self.elastic_api_key}"},
                )
                resp.raise_for_status()
                logger.debug("Elastic → %s", resp.status_code)
        except Exception as exc:
            logger.warning("Elastic send failed (non-critical): %s", exc)

    # ------------------------------------------------------------------
    # 3. Microsoft Sentinel — Data Collector API
    # ------------------------------------------------------------------
    def _sentinel_auth_header(self, body: str, date_str: str) -> str:
        """Build HMAC-SHA256 Authorization header for Sentinel Data Collector API."""
        content_length = len(body.encode("utf-8"))
        string_to_sign = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date_str}\n/api/logs"
        )
        decoded_key = base64.b64decode(self.sentinel_shared_key)
        signature = base64.b64encode(
            hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {self.sentinel_workspace_id}:{signature}"

    async def send_to_sentinel(self, event: AttackerAction) -> None:
        """
        POST to Microsoft Sentinel Log Analytics via the HTTP Data Collector API.
        Uses HMAC-SHA256 shared-key authentication.
        """
        if not (self.sentinel_workspace_id and self.sentinel_shared_key):
            return
        try:
            body = json.dumps([
                {
                    "TimeGenerated":    datetime.fromtimestamp(event.timestamp, tz=timezone.utc).isoformat(),
                    "AttackerIP":       event.attacker_ip,
                    "ActionType":       event.action_type,
                    "TargetNode":       event.target_node_id,
                    "Detail":           event.detail,
                    "MITRETechniqueId": event.mitre_technique_id or "",
                    "Severity":         _severity(event.action_type),
                }
            ])
            date_str = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
            auth = self._sentinel_auth_header(body, date_str)
            url = (
                f"https://{self.sentinel_workspace_id}.ods.opinsights.azure.com"
                "/api/logs?api-version=2016-04-01"
            )
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    url,
                    content=body.encode("utf-8"),
                    headers={
                        "Authorization":  auth,
                        "Log-Type":       "ShadowMeshDeception",
                        "x-ms-date":      date_str,
                        "Content-Type":   "application/json",
                    },
                )
                resp.raise_for_status()
                logger.debug("Sentinel → %s", resp.status_code)
        except Exception as exc:
            logger.warning("Sentinel send failed (non-critical): %s", exc)

    # ------------------------------------------------------------------
    # 4. CEF Syslog — works with ANY SIEM
    # ------------------------------------------------------------------
    async def send_syslog_cef(
        self,
        event: AttackerAction,
        host: Optional[str] = None,
        port: Optional[int] = None,
    ) -> None:
        """
        Send a CEF (Common Event Format) syslog UDP datagram.
        Compatible with ArcSight, QRadar, Splunk (syslog), Graylog, etc.
        """
        dest_host = host or self.syslog_host
        dest_port = port or self.syslog_port
        try:
            # Build CEF string
            cef = (
                f"CEF:0|ShadowMesh|DeceptionPlatform|1.0"
                f"|{event.action_type}"
                f"|{event.detail}"
                f"|7"
                f"|src={event.attacker_ip}"
                f" dst={event.target_node_id}"
                f" cs1={event.mitre_technique_id or 'N/A'}"
                f" cs1Label=MITRETechnique"
                f" cs2={event.mitre_technique_name or 'N/A'}"
                f" cs2Label=MITREName"
                f" rt={int(event.timestamp * 1000)}"
            )
            # Prepend syslog priority (facility=10/security, severity=2/critical → 82)
            message = f"<82>{cef}\n"

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                _udp_send,
                message.encode("utf-8"),
                dest_host,
                dest_port,
            )
            logger.debug("CEF syslog → %s:%s", dest_host, dest_port)
        except Exception as exc:
            logger.warning("CEF syslog send failed (non-critical): %s", exc)


def _udp_send(data: bytes, host: str, port: int) -> None:
    """Blocking UDP send — called in a thread executor to keep async clean."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(data, (host, port))


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
siem = SIEMIntegration()
