"""
ShadowMesh — Fake LDAP / SSO Honeypot (Task 4.2D + Task 12.1C)
===============================================================
A Flask-based fake Auth honeypot server that:
  - Listens on port 389 inside the container (HTTP-based LDAP mock)
  - Returns realistic Active Directory data via FakeActiveDirectory engine
  - Supports LDAP bind, search, user/group/computer enumeration
  - Provides fake SAML metadata on GET /sso/metadata
  - Simulates authentication latency (500ms) on POST /sso/login
  - Binds headers indicating Server: Microsoft-IIS/10.0 and X-Powered-By: ASP.NET
  - Posts callback action telemetry back to the ShadowMesh FastAPI backend

Environment variables:
  NODE_ID              — Injected by container manager (default: fake-auth-node)
  ATTACKER_CALLBACK_URL — FastAPI core backend base URL (default: http://backend:8000)
"""

import os
import sys
import time
import uuid
import hashlib
import logging
import threading
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, jsonify, request, Response

# Support importing fake_ad from multiple locations
try:
    from backend.deception.fake_ad import FakeActiveDirectory, LDAPSearchEngine
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from fake_ad import FakeActiveDirectory, LDAPSearchEngine

# ---------------------------------------------------------------------------
# Configuration & Setup
# ---------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = int(os.environ.get("AUTH_PORT", 389))
NODE_ID = os.environ.get("NODE_ID", "fake-auth-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-auth")

app = Flask(__name__)

# Override Werkzeug WSGI server header output in local testing
try:
    import werkzeug.serving
    _orig_send_header = werkzeug.serving.WSGIRequestHandler.send_header

    def _patched_send_header(self, keyword, value):
        if keyword.lower() == 'server' and (not value or "Werkzeug" in value or value.strip() == ""):
            return
        _orig_send_header(self, keyword, value)

    werkzeug.serving.WSGIRequestHandler.send_header = _patched_send_header
except Exception:
    pass

# ---------------------------------------------------------------------------
# Active Directory Engine (initialized at startup)
# ---------------------------------------------------------------------------
fake_ad = FakeActiveDirectory(domain_name="corp.internal")
ldap_engine = LDAPSearchEngine(fake_ad)

log.info("[AD] Generated %d users, %d computers, %d groups",
         len(fake_ad.users), len(fake_ad.computers), len(fake_ad.groups))

# ---------------------------------------------------------------------------
# LDAP Response Enrichment
# ---------------------------------------------------------------------------
def _enrich_entry(entry: dict) -> dict:
    """Add synthetic AD metadata fields to every LDAP response entry."""
    dn = entry.get("dn", "")
    attrs = entry.get("attributes", {})

    guid_seed = hashlib.md5(dn.encode()).hexdigest()
    object_guid = str(uuid.UUID(guid_seed))

    base_dt = datetime(2021, 3, 15, 8, 30, 0, tzinfo=timezone.utc)
    seed_val = int(hashlib.sha256(dn.encode()).hexdigest()[:8], 16)
    when_created = base_dt + timedelta(days=seed_val % 1000)
    when_changed = when_created + timedelta(days=(seed_val % 300) + 30)

    attrs.setdefault("distinguishedName", dn)
    attrs.setdefault("objectClass", entry.get("objectClass", "top"))
    attrs["objectGUID"] = object_guid
    attrs["whenCreated"] = when_created.strftime("%Y%m%d%H%M%S.0Z")
    attrs["whenChanged"] = when_changed.strftime("%Y%m%d%H%M%S.0Z")

    entry["attributes"] = attrs
    return entry


# ---------------------------------------------------------------------------
# SAML Metadata (preserved from Task 4.2D)
# ---------------------------------------------------------------------------
SAML_METADATA_XML = """<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="https://sso.corp.internal/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <Organization>
    <OrganizationName xml:lang="en">Corp Internal SSO</OrganizationName>
    <OrganizationDisplayName xml:lang="en">Corporate Single Sign-On</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">https://corp.internal</OrganizationURL>
  </Organization>
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...REDACTED</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sso.corp.internal/login"/>
  </IDPSSODescriptor>
</EntityDescriptor>
"""

# ---------------------------------------------------------------------------
# Background Callbacks Engine
# ---------------------------------------------------------------------------
def _fire_callback(attacker_ip: str, action_type: str, detail: str) -> None:
    payload = {
        "attacker_ip": attacker_ip,
        "action_type": action_type,
        "target_node_id": NODE_ID,
        "detail": detail,
        "timestamp": time.time(),
    }
    try:
        resp = requests.post(CALLBACK_ENDPOINT, json=payload, timeout=5)
        log.info("[callback] POST %s -> %s (%s)", CALLBACK_ENDPOINT, resp.status_code, action_type)
    except Exception as exc:
        log.warning("[callback] Failed to reach backend: %s", exc)


def _fire_callback_async(attacker_ip: str, action_type: str, detail: str) -> None:
    t = threading.Thread(
        target=_fire_callback,
        args=(attacker_ip, action_type, detail),
        daemon=True,
    )
    t.start()

# ---------------------------------------------------------------------------
# Middleware: Add server banners
# ---------------------------------------------------------------------------
@app.after_request
def modify_response(response: Response) -> Response:
    response.headers["Server"] = "Microsoft-IIS/10.0"
    response.headers["X-Powered-By"] = "ASP.NET"
    return response

# ---------------------------------------------------------------------------
# AD Intelligence Detection (Task 12.1D)
# ---------------------------------------------------------------------------
def _detect_high_value_query(attacker_ip: str, query: str) -> None:
    """Detect high-value AD queries and fire enriched callbacks to backend."""
    q = query.lower()
    if "domain admins" in q or "domain admin" in q:
        _fire_callback_async(
            attacker_ip, "ad_enumeration",
            f"Domain Admin enumeration detected: {query} | mitre=T1087.002"
        )
    elif "svc_" in q or "service account" in q:
        _fire_callback_async(
            attacker_ip, "ad_enumeration",
            f"Service account discovery: {query} | mitre=T1087.002"
        )
    elif "password" in q and ("description" in q or "*" in q):
        _fire_callback_async(
            attacker_ip, "ad_enumeration",
            f"Password exposure discovery: {query} | mitre=T1552"
        )


# ---------------------------------------------------------------------------
# LDAP Routes (Task 12.1C)
# ---------------------------------------------------------------------------
@app.route("/ldap/bind", methods=["POST"])
def post_ldap_bind():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log.info("[ldap-bind] user=%s from=%s", username, attacker_ip)
    _fire_callback_async(attacker_ip, "ldap_bind", f"LDAP bind attempt: user={username}")

    return jsonify({
        "resultCode": 0,
        "message": "Bind successful",
    })


@app.route("/ldap/search", methods=["GET"])
def get_ldap_search():
    search_filter = request.args.get("filter", "(objectClass=user)")
    attributes_param = request.args.get("attributes", None)
    attributes = [a.strip() for a in attributes_param.split(",")] if attributes_param else None

    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log.info("[ldap-search] filter=%s attrs=%s from=%s", search_filter, attributes, attacker_ip)
    _fire_callback_async(attacker_ip, "ldap_search", f"LDAP search: filter={search_filter}")

    _detect_high_value_query(attacker_ip, search_filter)

    results = ldap_engine.to_ldap_response(search_filter, attributes)

    if not results:
        return jsonify({
            "resultCode": 32,
            "message": "No such object",
        })

    enriched = [_enrich_entry(entry) for entry in results]
    return jsonify({
        "resultCode": 0,
        "entries": enriched,
    })


@app.route("/ldap/users", methods=["GET"])
def get_ldap_users():
    page = request.args.get("page", 1, type=int)
    size = request.args.get("size", 25, type=int)
    page = max(1, page)
    size = max(1, min(size, 100))

    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log.info("[ldap-users] page=%d size=%d from=%s", page, size, attacker_ip)
    _fire_callback_async(attacker_ip, "ldap_enum", "LDAP user enumeration")

    all_users = ldap_engine.search_users()
    all_users = [_enrich_entry(e) for e in all_users]
    total = len(all_users)
    start = (page - 1) * size
    end = start + size
    page_users = all_users[start:end]

    return jsonify({
        "total": total,
        "page": page,
        "size": size,
        "users": page_users,
    })


@app.route("/ldap/groups", methods=["GET"])
def get_ldap_groups():
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log.info("[ldap-groups] from=%s", attacker_ip)
    _fire_callback_async(attacker_ip, "ldap_enum", "LDAP group enumeration")

    groups = ldap_engine.search_groups()
    enriched = [_enrich_entry(e) for e in groups]
    return jsonify({
        "resultCode": 0,
        "entries": enriched,
    })


@app.route("/ldap/computers", methods=["GET"])
def get_ldap_computers():
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log.info("[ldap-computers] from=%s", attacker_ip)
    _fire_callback_async(attacker_ip, "ldap_enum", "LDAP computer enumeration")

    computers = ldap_engine.search_computers()
    enriched = [_enrich_entry(e) for e in computers]
    return jsonify({
        "resultCode": 0,
        "entries": enriched,
    })


# ---------------------------------------------------------------------------
# SSO Routes (preserved from Task 4.2D)
# ---------------------------------------------------------------------------
@app.route("/sso/metadata", methods=["GET"])
def get_sso_metadata():
    return Response(SAML_METADATA_XML, mimetype="application/xml")


@app.route("/sso/login", methods=["POST"])
def post_sso_login():
    time.sleep(0.5)
    return Response("Login Failure: Invalid Token or Credentials", status=401, mimetype="text/plain")


# Custom 404 handler
@app.errorhandler(404)
def page_not_found(e):
    return Response("404 - File or directory not found.", status=404, mimetype="text/html")


if __name__ == "__main__":
    log.info("=== ShadowMesh Fake LDAP / SSO Honeypot ===")
    log.info("NODE_ID            : %s", NODE_ID)
    log.info("ATTACKER_CALLBACK  : %s", CALLBACK_ENDPOINT)
    log.info("Listening on       : %s:%d", HOST, PORT)
    app.run(host=HOST, port=PORT, threaded=True)
