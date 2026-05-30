"""
ShadowMesh — Task 4.2D: Fake LDAP / SSO Honeypot
=================================================
A Flask-based fake Auth honeypot server that:
  - Listens on port 389 inside the container (HTTP-based LDAP mock)
  - Returns fake XML user lists for GET /ldap/search
  - Fails consistently on POST /ldap/bind with LDAP code 49
  - Provides fake SAML metadata on GET /sso/metadata
  - Simulates authentication latency (500ms) on POST /sso/login
  - Binds headers indicating Server: Microsoft-IIS/10.0 and X-Powered-By: ASP.NET
  - Posts callback action telemetry back to the ShadowMesh FastAPI backend
  - Runs in isolation and maintains statelessness

Environment variables:
  NODE_ID              — Injected by container manager (default: fake-auth-node)
  ATTACKER_CALLBACK_URL — FastAPI core backend base URL (default: http://backend:8000)
"""

import os
import time
import logging
import threading
import requests
from flask import Flask, jsonify, request, Response, redirect

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
        # Skip Werkzeug's default/empty Server header to avoid duplication
        if keyword.lower() == 'server' and (not value or "Werkzeug" in value or value.strip() == ""):
            return
        _orig_send_header(self, keyword, value)
        
    werkzeug.serving.WSGIRequestHandler.send_header = _patched_send_header
except Exception:
    pass

# ---------------------------------------------------------------------------
# Fake Data Stores
# ---------------------------------------------------------------------------
# We generate 20 realistic fake users with bcrypt-style hashes
FAKE_USERS = [
    {"cn": "john.smith", "department": "Finance", "group": "Domain Users", "hash": "$2b$12$R1qK...ZzF"},
    {"cn": "alice.jones", "department": "Engineering", "group": "Domain Admins", "hash": "$2b$12$K9pL...MmB"},
    {"cn": "bob.brown", "department": "HR", "group": "Domain Users", "hash": "$2b$12$A4vN...CxD"},
    {"cn": "charlie.davis", "department": "Operations", "group": "Server Admins", "hash": "$2b$12$Y7rP...QgH"},
    {"cn": "diana.prince", "department": "Security", "group": "Domain Admins", "hash": "$2b$12$L2wT...JhK"},
    {"cn": "ethan.hunt", "department": "Executive", "group": "Enterprise Admins", "hash": "$2b$12$P5sX...BvN"},
    {"cn": "fiona.glen", "department": "Marketing", "group": "Domain Users", "hash": "$2b$12$M8cQ...TwF"},
    {"cn": "george.clark", "department": "Sales", "group": "Domain Users", "hash": "$2b$12$H3kR...ZpM"},
    {"cn": "hannah.abbott", "department": "QA", "group": "Domain Users", "hash": "$2b$12$J6yL...NvC"},
    {"cn": "ian.malcolm", "department": "Research", "group": "Domain Users", "hash": "$2b$12$W9bV...DxS"},
    {"cn": "julia.roberts", "department": "Legal", "group": "Domain Users", "hash": "$2b$12$C2xN...FqL"},
    {"cn": "kevin.bacon", "department": "PR", "group": "Domain Users", "hash": "$2b$12$V5mT...RhP"},
    {"cn": "laura.dern", "department": "Engineering", "group": "Developers", "hash": "$2b$12$N8pK...BxJ"},
    {"cn": "michael.scott", "department": "Management", "group": "Domain Users", "hash": "$2b$12$S3rF...MzG"},
    {"cn": "nancy.drew", "department": "Investigation", "group": "Domain Users", "hash": "$2b$12$D6yH...LvQ"},
    {"cn": "oscar.isaac", "department": "Design", "group": "Domain Users", "hash": "$2b$12$G9vC...NxT"},
    {"cn": "peter.parker", "department": "IT", "group": "Helpdesk", "hash": "$2b$12$F4bM...PvR"},
    {"cn": "quinn.fabray", "department": "HR", "group": "Domain Users", "hash": "$2b$12$X7kL...BzW"},
    {"cn": "rachel.green", "department": "Procurement", "group": "Domain Users", "hash": "$2b$12$T2pN...JxC"},
    {"cn": "sam.gamgee", "department": "Facilities", "group": "Domain Users", "hash": "$2b$12$L5mR...QvK"},
]

def generate_users_xml():
    xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>\n<users>']
    for u in FAKE_USERS:
        xml_parts.append(f"""
  <user>
    <cn>{u['cn']}</cn>
    <department>{u['department']}</department>
    <group>{u['group']}</group>
    <hash>{u['hash']}</hash>
  </user>""")
    xml_parts.append("\n</users>")
    return "".join(xml_parts)

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
    """POST request metrics back to FastAPI backend core."""
    payload = {
        "attacker_ip": attacker_ip,
        "action_type": action_type,
        "target_node_id": NODE_ID,
        "detail": detail,
        "timestamp": time.time(),
    }
    try:
        resp = requests.post(CALLBACK_ENDPOINT, json=payload, timeout=5)
        log.info("[callback] POST %s → %s (%s)", CALLBACK_ENDPOINT, resp.status_code, action_type)
    except Exception as exc:
        log.warning("[callback] Failed to reach backend: %s", exc)


def _fire_callback_async(attacker_ip: str, action_type: str, detail: str) -> None:
    """Spawn daemon thread to handle telemetry callback without blocking server responses."""
    t = threading.Thread(
        target=_fire_callback,
        args=(attacker_ip, action_type, detail),
        daemon=True,
    )
    t.start()

# ---------------------------------------------------------------------------
# Middleware: Add server banners and fire callback telemetry
# ---------------------------------------------------------------------------
@app.after_request
def modify_response(response: Response) -> Response:
    # Set headers mandated by senior specs
    response.headers["Server"] = "Microsoft-IIS/10.0"
    response.headers["X-Powered-By"] = "ASP.NET"
    
    # Extract attacker details
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    # All routes in Task 4.2D use action_type = "login_attempt"
    action_type = "login_attempt"
    detail = f"LDAP/SSO access — {request.method} {request.path}"
        
    _fire_callback_async(attacker_ip, action_type, detail)
    return response

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/ldap/search", methods=["GET"])
def get_ldap_search():
    return Response(generate_users_xml(), mimetype="application/xml")


@app.route("/ldap/bind", methods=["POST"])
def post_ldap_bind():
    # LDAP-style authentication failure
    return jsonify({
        "result": "invalidCredentials",
        "code": 49
    }), 401


@app.route("/sso/metadata", methods=["GET"])
def get_sso_metadata():
    return Response(SAML_METADATA_XML, mimetype="application/xml")


@app.route("/sso/login", methods=["POST"])
def post_sso_login():
    # Mandated 500ms delay
    time.sleep(0.5)
    
    # Always fail
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
