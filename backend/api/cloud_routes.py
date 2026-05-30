"""
ShadowMesh — Task 12.2B: Fake AWS API Routes
=============================================
FastAPI router providing fake AWS STS/IAM endpoints that log attacker
interactions and trigger intelligence collection.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from backend.deception.cloud_deception import (
    CloudCredentialGenerator,
    CloudIntelManager,
    get_iam_list_users,
    get_sts_caller_identity,
)

log = logging.getLogger("fake_aws")

router = APIRouter(prefix="/fake-aws")

cloud_cred_gen = CloudCredentialGenerator()
cloud_intel: Optional[CloudIntelManager] = None


def init_cloud_intel(sio=None, slack_alert_fn=None, profile_store=None):
    global cloud_intel
    cloud_intel = CloudIntelManager(
        sio=sio,
        slack_alert_fn=slack_alert_fn,
        profile_store=profile_store,
    )
    return cloud_intel


def get_cloud_intel() -> CloudIntelManager:
    global cloud_intel
    if cloud_intel is None:
        cloud_intel = CloudIntelManager()
    return cloud_intel


def _get_attacker_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.get("/sts/GetCallerIdentity")
async def sts_get_caller_identity(request: Request):
    attacker_ip = _get_attacker_ip(request)
    log.info("[fake-aws] GetCallerIdentity from %s", attacker_ip)

    intel = get_cloud_intel()
    await intel.record_api_call(
        attacker_ip=attacker_ip,
        provider="aws",
        api_call="GetCallerIdentity",
        request_details={"method": "GET", "path": "/sts/GetCallerIdentity"},
    )

    return get_sts_caller_identity()


@router.post("/iam/ListUsers")
async def iam_list_users(request: Request):
    attacker_ip = _get_attacker_ip(request)
    log.info("[fake-aws] ListUsers from %s", attacker_ip)

    intel = get_cloud_intel()
    await intel.record_api_call(
        attacker_ip=attacker_ip,
        provider="aws",
        api_call="ListUsers",
        request_details={"method": "POST", "path": "/iam/ListUsers"},
    )

    return get_iam_list_users()


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(path: str, request: Request):
    attacker_ip = _get_attacker_ip(request)
    body = None
    try:
        body = (await request.body()).decode("utf-8", errors="replace")[:2048]
    except Exception:
        pass

    log.info("[fake-aws] %s /%s from %s", request.method, path, attacker_ip)

    intel = get_cloud_intel()
    await intel.record_api_call(
        attacker_ip=attacker_ip,
        provider="aws",
        api_call=path,
        request_details={
            "method": request.method,
            "path": f"/{path}",
            "headers": dict(request.headers),
            "body": body,
        },
    )

    return {"status": "success"}
