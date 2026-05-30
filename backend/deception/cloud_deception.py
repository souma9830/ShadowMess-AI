"""
ShadowMesh — Task 12.2: Cloud Deception Layer
==============================================
Generates fake cloud credentials (AWS, Azure, GCP), provides fake AWS API
endpoints, collects intelligence on credential usage, and integrates with
the alerting/profiling pipeline.

Architecture:
  CloudCredentialGenerator  — generates realistic fake cloud credentials
  CloudIntelManager         — tracks credential usage and triggers alerts
  Fake AWS routes           — /fake-aws/sts/*, /fake-aws/iam/*, catch-all
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
import uuid
from base64 import b64encode
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("cloud_deception")


# ---------------------------------------------------------------------------
# Cloud Credential Generator
# ---------------------------------------------------------------------------

class CloudCredentialGenerator:

    def __init__(self, seed: str = "shadowmesh-cloud"):
        self._seed = seed

    def generate_aws_credentials(self) -> Dict[str, str]:
        key_suffix = secrets.token_hex(8).upper()
        access_key_id = f"AKIA{key_suffix}"
        secret_access_key = secrets.token_urlsafe(30)
        account_id = str(int(hashlib.sha256(self._seed.encode()).hexdigest()[:12], 16) % 10**12).zfill(12)

        return {
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "region": "us-east-1",
            "account_id": account_id,
        }

    def to_aws_credentials_file(self) -> str:
        creds = self.generate_aws_credentials()
        return (
            f"[default]\n"
            f"aws_access_key_id = {creds['access_key_id']}\n"
            f"aws_secret_access_key = {creds['secret_access_key']}\n"
            f"region = {creds['region']}\n"
        )

    def generate_azure_credentials(self) -> Dict[str, str]:
        return {
            "clientId": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{self._seed}-azure-client")),
            "clientSecret": secrets.token_urlsafe(32),
            "subscriptionId": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{self._seed}-azure-sub")),
            "tenantId": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{self._seed}-azure-tenant")),
            "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
            "resourceManagerEndpointUrl": "https://management.azure.com/",
            "description": "Production deployment service principal — DO NOT SHARE",
        }

    def generate_gcp_service_account(self) -> Dict[str, str]:
        project_id = "shadowmesh-prod-" + secrets.token_hex(4)
        private_key_id = secrets.token_hex(20)
        client_id = str(int(hashlib.sha256(f"{self._seed}-gcp".encode()).hexdigest()[:18], 16))

        fake_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"MIIEpAIBAAKCAQEA{secrets.token_urlsafe(64)}\n"
            f"{secrets.token_urlsafe(64)}\n"
            f"{secrets.token_urlsafe(64)}\n"
            "-----END RSA PRIVATE KEY-----\n"
        )

        return {
            "type": "service_account",
            "project_id": project_id,
            "private_key_id": private_key_id,
            "private_key": fake_key,
            "client_email": f"deploy-sa@{project_id}.iam.gserviceaccount.com",
            "client_id": client_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }


# ---------------------------------------------------------------------------
# Cloud Intelligence Manager
# ---------------------------------------------------------------------------

class CloudIntelManager:

    def __init__(self, sio=None, slack_alert_fn=None, profile_store: Optional[Dict] = None):
        self.sio = sio
        self.slack_alert_fn = slack_alert_fn
        self.profile_store: Dict[str, Dict] = profile_store if profile_store is not None else {}
        self._events: List[Dict] = []
        self._alert_log: List[Dict] = []

    def get_events(self) -> List[Dict]:
        return list(self._events)

    def get_alerts(self) -> List[Dict]:
        return list(self._alert_log)

    async def record_api_call(
        self,
        attacker_ip: str,
        provider: str,
        api_call: str,
        request_details: Optional[Dict] = None,
    ) -> Optional[Dict]:
        event = {
            "attacker_ip": attacker_ip,
            "provider": provider,
            "api_call": api_call,
            "timestamp": time.time(),
            "request_details": request_details or {},
        }
        self._events.append(event)

        detection = self._classify(api_call)
        if detection:
            await self._emit_event(attacker_ip, provider, api_call, detection)
            await self._generate_alert(attacker_ip, provider, api_call, detection)
            await self._send_slack(attacker_ip, provider, api_call, detection)
            self._update_profile(attacker_ip, api_call, detection)

        return detection

    def _classify(self, api_call: str) -> Optional[Dict]:
        call = api_call.lower()

        if "getcalleridentity" in call:
            return {
                "event_type": "cloud_credential_used",
                "severity": "high",
                "mitre": "T1552.001",
                "mitre_name": "Unsecured Credentials: Credentials In Files",
                "tactic": "Credential Access",
                "message": "AWS credential used by attacker",
                "objective": "Cloud Access",
            }

        if "listusers" in call:
            return {
                "event_type": "cloud_account_discovery",
                "severity": "high",
                "mitre": "T1087.004",
                "mitre_name": "Account Discovery: Cloud Account",
                "tactic": "Discovery",
                "message": "Cloud account discovery detected",
                "objective": "Cloud Enumeration",
            }

        return {
            "event_type": "cloud_api_access",
            "severity": "medium",
            "mitre": "T1526",
            "mitre_name": "Cloud Service Discovery",
            "tactic": "Discovery",
            "message": f"Attacker targeting AWS service: {api_call}",
            "objective": "Cloud Enumeration",
        }

    async def _emit_event(self, attacker_ip: str, provider: str, api_call: str, detection: Dict) -> None:
        if not self.sio:
            return
        try:
            await self.sio.emit(detection["event_type"], {
                "provider": provider,
                "api_call": api_call,
                "attacker_ip": attacker_ip,
                "severity": detection["severity"],
                "mitre": detection["mitre"],
                "timestamp": time.time(),
            })
        except Exception as e:
            log.warning("[cloud_intel] Socket.IO emit failed: %s", e)

    async def _generate_alert(self, attacker_ip: str, provider: str, api_call: str, detection: Dict) -> None:
        alert = {
            "attacker_ip": attacker_ip,
            "provider": provider,
            "api_call": api_call,
            "severity": detection["severity"],
            "type": detection["event_type"],
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
                log.warning("[cloud_intel] Alert emit failed: %s", e)

    async def _send_slack(self, attacker_ip: str, provider: str, api_call: str, detection: Dict) -> None:
        if not self.slack_alert_fn:
            return
        try:
            await self.slack_alert_fn(
                message=f"{detection['message']} (from {attacker_ip})",
                severity=detection["severity"],
                fields={
                    "Attacker IP": attacker_ip,
                    "Provider": provider,
                    "API Call": api_call,
                    "MITRE Technique": f"{detection['mitre']} — {detection['mitre_name']}",
                },
            )
        except Exception as e:
            log.warning("[cloud_intel] Slack alert failed: %s", e)

    def _update_profile(self, attacker_ip: str, api_call: str, detection: Dict) -> None:
        profile = self.profile_store.get(attacker_ip)
        if profile is None:
            profile = {
                "objectives": [],
                "confidence": 0.0,
                "techniques_observed": [],
                "cloud_api_calls": 0,
            }
            self.profile_store[attacker_ip] = profile

        technique = detection["mitre"]
        if technique not in profile.get("techniques_observed", []):
            profile.setdefault("techniques_observed", []).append(technique)

        objective = detection.get("objective", "Cloud Access")
        if objective not in profile.get("objectives", []):
            profile.setdefault("objectives", []).append(objective)

        profile["cloud_api_calls"] = profile.get("cloud_api_calls", 0) + 1

        if profile["cloud_api_calls"] >= 3:
            if "Privilege Escalation" not in profile.get("objectives", []):
                profile["objectives"].append("Privilege Escalation")

        profile["confidence"] = min(1.0, profile.get("confidence", 0.0) + 0.15)


# ---------------------------------------------------------------------------
# Fake AWS API Data
# ---------------------------------------------------------------------------

_FAKE_IAM_USERS = [
    {"UserName": "admin", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/admin", "Path": "/", "CreateDate": "2021-03-15T08:30:00Z"},
    {"UserName": "devops-deploy", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/devops-deploy", "Path": "/", "CreateDate": "2021-06-20T14:00:00Z"},
    {"UserName": "ci-cd-runner", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/ci-cd-runner", "Path": "/service/", "CreateDate": "2022-01-10T09:15:00Z"},
    {"UserName": "finance-reports", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/finance-reports", "Path": "/", "CreateDate": "2022-04-05T11:30:00Z"},
    {"UserName": "backup-service", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/backup-service", "Path": "/service/", "CreateDate": "2021-09-01T07:00:00Z"},
    {"UserName": "jsmith", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/jsmith", "Path": "/", "CreateDate": "2021-03-20T10:00:00Z"},
    {"UserName": "mwilliams", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/mwilliams", "Path": "/", "CreateDate": "2021-05-12T13:45:00Z"},
    {"UserName": "terraform-prod", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/terraform-prod", "Path": "/service/", "CreateDate": "2022-02-28T16:20:00Z"},
    {"UserName": "monitoring-agent", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/monitoring-agent", "Path": "/service/", "CreateDate": "2021-11-15T08:00:00Z"},
    {"UserName": "security-audit", "UserId": "AIDA" + secrets.token_hex(8).upper(), "Arn": "arn:aws:iam::123456789012:user/security-audit", "Path": "/", "CreateDate": "2022-07-01T09:30:00Z"},
]


def get_sts_caller_identity(account_id: str = "123456789012") -> Dict:
    return {
        "UserId": "AIDA" + secrets.token_hex(8).upper(),
        "Account": account_id,
        "Arn": f"arn:aws:iam::{account_id}:user/deploy-service",
    }


def get_iam_list_users() -> Dict:
    return {
        "Users": _FAKE_IAM_USERS,
        "IsTruncated": False,
    }
