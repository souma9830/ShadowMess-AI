"""
ShadowMesh — Task 11.4: Fake Elasticsearch Honeypot
=====================================================
Flask-based server that mimics the Elasticsearch REST API, capturing index
discovery, document retrieval, and search queries as intelligence events.

Environment variables:
  NODE_ID               — Honeypot node ID
  ATTACKER_CALLBACK_URL — ShadowMesh backend base URL
"""

import os
import time
import logging
import threading
import requests
from flask import Flask, jsonify, request, Response

HOST = "0.0.0.0"
PORT = int(os.environ.get("ES_PORT", 9200))
NODE_ID = os.environ.get("NODE_ID", "fake-es-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-es")

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Fake cluster metadata
# ---------------------------------------------------------------------------
_CLUSTER_NAME = "prod-search-cluster"
_NODE_NAME    = "es-node-01"
_VERSION      = "8.13.2"
_BUILD_HASH   = "16cc90cd2d08a3b73d9579d4941ec7cc0441dc6a"

_INDICES: dict[str, dict] = {
    "employees": {
        "doc_count": 1842,
        "store_size": "4.2mb",
        "fields": ["id", "name", "email", "department", "salary", "ssn", "dob"],
    },
    "customers": {
        "doc_count": 94210,
        "store_size": "128.7mb",
        "fields": ["id", "name", "email", "phone", "address", "credit_card_last4"],
    },
    "transactions": {
        "doc_count": 2841093,
        "store_size": "1.8gb",
        "fields": ["id", "amount", "currency", "timestamp", "user_id", "merchant"],
    },
    "audit_logs": {
        "doc_count": 5120441,
        "store_size": "3.1gb",
        "fields": ["timestamp", "user", "action", "resource", "ip", "result"],
    },
    ".security-7": {
        "doc_count": 312,
        "store_size": "128kb",
        "fields": ["username", "password_hash", "roles", "enabled"],
    },
}

_FAKE_DOCS: dict[str, list[dict]] = {
    "employees": [
        {"id": "EMP-9401", "name": "Alice Smith",   "email": "asmith@corp.internal",   "department": "Executive",   "salary": 185000, "ssn": "FAKE-XXX-XX-0001"},
        {"id": "EMP-1024", "name": "Bob Jones",     "email": "bjones@corp.internal",   "department": "Engineering", "salary": 140000, "ssn": "FAKE-XXX-XX-0002"},
        {"id": "EMP-8830", "name": "Charlie Brown", "email": "cbrown@corp.internal",   "department": "DevOps",      "salary": 125000, "ssn": "FAKE-XXX-XX-0003"},
    ],
    ".security-7": [
        {"username": "elastic",   "password_hash": "$2b$12$FAKEHASH_shadowmesh_elastic",   "roles": ["superuser"],        "enabled": True},
        {"username": "kibana",    "password_hash": "$2b$12$FAKEHASH_shadowmesh_kibana",    "roles": ["kibana_system"],     "enabled": True},
        {"username": "logstash",  "password_hash": "$2b$12$FAKEHASH_shadowmesh_logstash",  "roles": ["logstash_system"],   "enabled": True},
    ],
}

_SENSITIVE_INDICES = {".security-7", "employees", "customers"}

# ---------------------------------------------------------------------------
# Callback
# ---------------------------------------------------------------------------

def _cb(action_type: str, detail: str) -> None:
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    payload = {
        "attacker_ip": attacker_ip,
        "action_type": action_type,
        "target_node_id": NODE_ID,
        "detail": detail,
        "timestamp": time.time(),
    }
    def _post():
        try:
            requests.post(CALLBACK_ENDPOINT, json=payload, timeout=5)
        except Exception as exc:
            log.warning("[callback] Failed: %s", exc)
    threading.Thread(target=_post, daemon=True).start()


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _es_headers(resp: Response) -> Response:
    resp.headers["X-Elastic-Product"] = "Elasticsearch"
    resp.headers["Content-Type"] = "application/json; charset=UTF-8"
    return resp


# ---------------------------------------------------------------------------
# Routes — cluster level
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def root():
    _cb("port_scan", f"ES root probe from {request.remote_addr}")
    return _es_headers(jsonify({
        "name": _NODE_NAME,
        "cluster_name": _CLUSTER_NAME,
        "cluster_uuid": "FAKE_UUID_shadowmesh_honeypot_001",
        "version": {
            "number": _VERSION,
            "build_flavor": "default",
            "build_type": "docker",
            "build_hash": _BUILD_HASH,
            "build_date": "2024-04-05T22:05:16.273979787Z",
            "build_snapshot": False,
            "lucene_version": "9.10.0",
            "minimum_wire_compatibility_version": "7.17.0",
            "minimum_index_compatibility_version": "7.0.0",
        },
        "tagline": "You Know, for Search",
    }))


@app.route("/_cluster/health", methods=["GET"])
def cluster_health():
    _cb("data_access", f"ES cluster health probe from {request.remote_addr}")
    return _es_headers(jsonify({
        "cluster_name": _CLUSTER_NAME,
        "status": "green",
        "timed_out": False,
        "number_of_nodes": 3,
        "number_of_data_nodes": 3,
        "active_primary_shards": 12,
        "active_shards": 24,
        "relocating_shards": 0,
        "initializing_shards": 0,
        "unassigned_shards": 0,
        "delayed_unassigned_shards": 0,
        "number_of_pending_tasks": 0,
        "number_of_in_flight_fetch": 0,
        "task_max_waiting_in_queue_millis": 0,
        "active_shards_percent_as_number": 100.0,
    }))


@app.route("/_cat/indices", methods=["GET"])
def cat_indices():
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log.info("[cat/indices] %s", attacker_ip)
    _cb("data_access", f"ES index enumeration from {attacker_ip}")

    # Return plain-text table (default _cat format) or JSON if ?format=json
    fmt = request.args.get("format", "text")
    if fmt == "json":
        rows = [
            {
                "health": "green", "status": "open",
                "index": name,
                "uuid": f"FAKE_{name[:8].upper()}_UUID",
                "pri": "1", "rep": "1",
                "docs.count": str(meta["doc_count"]),
                "docs.deleted": "0",
                "store.size": meta["store_size"],
                "pri.store.size": meta["store_size"],
            }
            for name, meta in _INDICES.items()
        ]
        return _es_headers(jsonify(rows))

    lines = ["health status index            uuid                   pri rep docs.count store.size"]
    for name, meta in _INDICES.items():
        lines.append(
            f"green  open   {name:<16} FAKE_{name[:8].upper():<18}   1   1 {meta['doc_count']:>10} {meta['store_size']:>10}"
        )
    return _es_headers(Response("\n".join(lines) + "\n", mimetype="text/plain"))


@app.route("/_nodes", methods=["GET"])
@app.route("/_nodes/stats", methods=["GET"])
def nodes():
    _cb("data_access", f"ES nodes probe from {request.remote_addr}")
    return _es_headers(jsonify({
        "_nodes": {"total": 3, "successful": 3, "failed": 0},
        "cluster_name": _CLUSTER_NAME,
        "nodes": {
            "FAKE_NODE_ID_01": {"name": "es-node-01", "roles": ["master", "data"]},
            "FAKE_NODE_ID_02": {"name": "es-node-02", "roles": ["data"]},
            "FAKE_NODE_ID_03": {"name": "es-node-03", "roles": ["data", "ingest"]},
        },
    }))


# ---------------------------------------------------------------------------
# Routes — index level
# ---------------------------------------------------------------------------

@app.route("/<index>", methods=["GET"])
def index_info(index: str):
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log.info("[index_info] %s → %r", attacker_ip, index)
    action = "data_access"
    if index in _SENSITIVE_INDICES:
        action = "credential_theft" if index == ".security-7" else "data_access"
    _cb(action, f"ES index access: {index!r} from {attacker_ip}")

    meta = _INDICES.get(index)
    if meta is None:
        return _es_headers(jsonify({
            "error": {"root_cause": [{"type": "index_not_found_exception", "reason": f"no such index [{index}]"}]},
            "status": 404,
        })), 404

    return _es_headers(jsonify({
        index: {
            "aliases": {},
            "mappings": {"properties": {f: {"type": "keyword"} for f in meta["fields"]}},
            "settings": {"index": {"number_of_shards": "1", "number_of_replicas": "1"}},
        }
    }))


@app.route("/<index>/_search", methods=["GET", "POST"])
def search(index: str):
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    body_raw = request.get_data(as_text=True)[:8192]
    log.info("[search] %s → index=%r query=%r", attacker_ip, index, body_raw[:300])

    action = "credential_theft" if index in _SENSITIVE_INDICES else "data_access"
    _cb(action, f"ES search: index={index!r} query={body_raw[:500]!r} from {attacker_ip}")

    docs = _FAKE_DOCS.get(index, [])
    hits = [
        {"_index": index, "_id": str(i + 1), "_score": 1.0, "_source": doc}
        for i, doc in enumerate(docs)
    ]
    return _es_headers(jsonify({
        "took": 4,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": len(hits), "relation": "eq"},
            "max_score": 1.0 if hits else None,
            "hits": hits,
        },
    }))


@app.route("/<index>/_doc/<doc_id>", methods=["GET"])
def get_doc(index: str, doc_id: str):
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log.info("[get_doc] %s → index=%r id=%r", attacker_ip, index, doc_id)

    action = "credential_theft" if index in _SENSITIVE_INDICES else "data_access"
    _cb(action, f"ES doc retrieval: index={index!r} id={doc_id!r} from {attacker_ip}")

    docs = _FAKE_DOCS.get(index, [])
    try:
        source = docs[int(doc_id) - 1]
        found = True
    except (IndexError, ValueError):
        source = {}
        found = False

    return _es_headers(jsonify({
        "_index": index, "_id": doc_id,
        "_version": 1, "_seq_no": 0, "_primary_term": 1,
        "found": found,
        "_source": source,
    }))


# Block all write operations
@app.route("/<path:path>", methods=["PUT", "POST", "DELETE", "PATCH"])
def block_writes(path: str):
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log.info("[blocked_write] %s → %s %s", attacker_ip, request.method, path)
    _cb("data_access", f"ES write attempt: {request.method} /{path} from {attacker_ip}")
    return _es_headers(jsonify({
        "error": {"type": "security_exception", "reason": "action [indices:data/write] is unauthorized"},
        "status": 403,
    })), 403


@app.errorhandler(404)
def not_found(e):
    return _es_headers(jsonify({
        "error": {"root_cause": [{"type": "index_not_found_exception", "reason": "no such index"}]},
        "status": 404,
    })), 404


if __name__ == "__main__":
    log.info("=== ShadowMesh Fake Elasticsearch Honeypot ===")
    log.info("NODE_ID           : %s", NODE_ID)
    log.info("CALLBACK          : %s", CALLBACK_ENDPOINT)
    log.info("Listening on      : %s:%d", HOST, PORT)
    app.run(host=HOST, port=PORT, threaded=True)
