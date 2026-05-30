"""
ShadowMesh — Task 11.4: Fake Redis Honeypot
============================================
Native RESP protocol server that captures AUTH passwords, KEY enumeration,
and GET access against sensitive-looking keys, then fires callbacks.

Environment variables:
  NODE_ID               — Honeypot node ID
  ATTACKER_CALLBACK_URL — ShadowMesh backend base URL
"""

import os
import socket
import threading
import time
import logging
import requests

HOST = "0.0.0.0"
PORT = int(os.environ.get("REDIS_PORT", 6379))
NODE_ID = os.environ.get("NODE_ID", "fake-redis-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-redis")

# ---------------------------------------------------------------------------
# Fake keyspace — realistic secrets an attacker would target
# ---------------------------------------------------------------------------
_KEYSPACE: dict[str, str] = {
    "session:admin":          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.FAKE",
    "api_key:prod":           "sk-prod-FAKEAKIA7f3a9c2b1d4e5f6a7b8c9d0e1f2a3b4c",
    "db_password":            "Pr0d-DB-P@ssw0rd-2025!",
    "aws_secret":             "FAKEAWSSECRET/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "stripe_secret_key":      "sk_test_FAKEKEYDONOTUSE1234567890abcdef",
    "jwt_secret":             "shadowmesh-fake-jwt-secret-do-not-use-in-production",
    "smtp_password":          "Smtp-P@ss-2025-FAKE",
    "redis_auth_token":       "rdt_FAKE_TOKEN_shadowmesh_honeypot",
    "config:database_url":    "postgresql://admin:Pr0d-DB-P@ssw0rd-2025!@db.internal:5432/proddb",
    "config:redis_url":       "redis://:rdt_FAKE_TOKEN@redis.internal:6379/0",
    "user:1000:token":        "tok_FAKE_user1000_shadowmesh",
    "user:1001:token":        "tok_FAKE_user1001_shadowmesh",
    "oauth:client_secret":    "oauth_FAKE_secret_shadowmesh_2025",
}

# Keys whose access triggers a credential_stolen alert
_SENSITIVE_KEYS = {
    "api_key:prod", "db_password", "aws_secret", "stripe_secret_key",
    "jwt_secret", "config:database_url",
}

_INFO_RESPONSE = """\
# Server
redis_version:7.2.4
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:0
redis_mode:standalone
os:Linux 5.15.0-105-generic x86_64
arch_bits:64
tcp_port:6379
uptime_in_seconds:864000
uptime_in_days:10
hz:10
configured_hz:10
aof_enabled:0
rdb_changes_since_last_save:0
rdb_last_bgsave_status:ok
used_memory:2097152
used_memory_human:2.00M
maxmemory:0
maxmemory_human:0B
role:master
connected_slaves:0
master_replid:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
master_repl_offset:0
repl_backlog_active:0
total_connections_received:1042
total_commands_processed:58291
instantaneous_ops_per_sec:12
total_net_input_bytes:1048576
total_net_output_bytes:2097152
keyspace_hits:4821
keyspace_misses:203
used_cpu_sys:12.450000
used_cpu_user:8.320000
# Keyspace
db0:keys=13,expires=0,avg_ttl=0
"""

# ---------------------------------------------------------------------------
# Callback
# ---------------------------------------------------------------------------

def _cb(attacker_ip: str, action_type: str, detail: str) -> None:
    def _post():
        try:
            requests.post(CALLBACK_ENDPOINT, json={
                "attacker_ip": attacker_ip,
                "action_type": action_type,
                "target_node_id": NODE_ID,
                "detail": detail,
                "timestamp": time.time(),
            }, timeout=5)
        except Exception as exc:
            log.warning("[callback] Failed: %s", exc)
    threading.Thread(target=_post, daemon=True).start()


# ---------------------------------------------------------------------------
# RESP protocol helpers
# ---------------------------------------------------------------------------

def _resp_simple(s: str) -> bytes:
    return f"+{s}\r\n".encode()


def _resp_error(s: str) -> bytes:
    return f"-ERR {s}\r\n".encode()


def _resp_bulk(s: str | None) -> bytes:
    if s is None:
        return b"$-1\r\n"
    encoded = s.encode()
    return f"${len(encoded)}\r\n".encode() + encoded + b"\r\n"


def _resp_array(items: list[str]) -> bytes:
    out = f"*{len(items)}\r\n".encode()
    for item in items:
        out += _resp_bulk(item)
    return out


def _resp_integer(n: int) -> bytes:
    return f":{n}\r\n".encode()


def _parse_resp(data: bytes) -> list[list[str]] | None:
    """
    Parse one or more RESP inline or array commands from a buffer.
    Returns a list of parsed commands (each command is a list of strings),
    or None if the buffer is incomplete/malformed.
    """
    commands = []
    pos = 0
    while pos < len(data):
        if data[pos:pos+1] == b"*":
            end = data.find(b"\r\n", pos)
            if end == -1:
                break
            count = int(data[pos+1:end])
            pos = end + 2
            args = []
            for _ in range(count):
                if data[pos:pos+1] != b"$":
                    return None
                end = data.find(b"\r\n", pos)
                if end == -1:
                    return None
                length = int(data[pos+1:end])
                pos = end + 2
                args.append(data[pos:pos+length].decode("utf-8", errors="replace"))
                pos += length + 2  # skip \r\n
            commands.append(args)
        else:
            # Inline command
            end = data.find(b"\r\n", pos)
            if end == -1:
                break
            line = data[pos:end].decode("utf-8", errors="replace").strip()
            if line:
                commands.append(line.split())
            pos = end + 2
    return commands if commands else None


# ---------------------------------------------------------------------------
# Command dispatcher
# ---------------------------------------------------------------------------

def _dispatch(args: list[str], attacker_ip: str, authenticated: list[bool]) -> bytes:
    """
    Dispatch a parsed RESP command and return the wire response.
    `authenticated` is a mutable single-element list used as a flag.
    """
    if not args:
        return _resp_error("empty command")

    cmd = args[0].upper()

    if cmd == "PING":
        return _resp_simple("PONG") if len(args) == 1 else _resp_bulk(args[1])

    if cmd == "AUTH":
        password = args[1] if len(args) > 1 else ""
        log.info("[auth] %s → password=%r", attacker_ip, password)
        _cb(attacker_ip, "credential_theft",
            f"Redis AUTH attempt: password={password!r}")
        authenticated[0] = True
        return _resp_simple("OK")

    if cmd == "QUIT":
        return _resp_simple("OK")

    if cmd == "INFO":
        return _resp_bulk(_INFO_RESPONSE)

    if cmd == "DBSIZE":
        return _resp_integer(len(_KEYSPACE))

    if cmd == "KEYS":
        pattern = args[1] if len(args) > 1 else "*"
        log.info("[keys] %s → pattern=%r", attacker_ip, pattern)
        _cb(attacker_ip, "data_access",
            f"Redis KEYS {pattern!r} — key enumeration from {attacker_ip}")
        if pattern == "*":
            return _resp_array(list(_KEYSPACE.keys()))
        # Simple glob: only support * wildcard
        import fnmatch
        matched = [k for k in _KEYSPACE if fnmatch.fnmatch(k, pattern)]
        return _resp_array(matched)

    if cmd == "GET":
        key = args[1] if len(args) > 1 else ""
        value = _KEYSPACE.get(key)
        log.info("[get] %s → key=%r value=%s", attacker_ip, key,
                 "FOUND" if value else "MISS")
        if key in _SENSITIVE_KEYS:
            _cb(attacker_ip, "credential_theft",
                f"Redis GET sensitive key={key!r} value={value!r} from {attacker_ip}")
        elif value is not None:
            _cb(attacker_ip, "data_access",
                f"Redis GET key={key!r} from {attacker_ip}")
        return _resp_bulk(value)

    if cmd == "SET":
        key = args[1] if len(args) > 1 else ""
        val = args[2] if len(args) > 2 else ""
        log.info("[set] %s → key=%r (ignored)", attacker_ip, key)
        _cb(attacker_ip, "data_access",
            f"Redis SET key={key!r} attempted from {attacker_ip}")
        return _resp_simple("OK")

    if cmd in ("CONFIG", "SLAVEOF", "REPLICAOF", "DEBUG", "FLUSHALL", "FLUSHDB"):
        log.info("[blocked] %s → %s", attacker_ip, cmd)
        _cb(attacker_ip, "data_access",
            f"Redis {cmd} attempted from {attacker_ip}")
        return _resp_error(f"unknown command '{cmd.lower()}'")

    if cmd == "COMMAND":
        return _resp_integer(200)

    return _resp_error(f"unknown command '{cmd.lower()}'")


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

def _handle(sock: socket.socket, addr: tuple) -> None:
    attacker_ip = addr[0]
    log.info("[connect] %s", attacker_ip)
    _cb(attacker_ip, "port_scan", f"Redis connection from {attacker_ip}")

    authenticated = [False]
    buf = b""
    try:
        sock.settimeout(120)
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            commands = _parse_resp(buf)
            if not commands:
                continue
            buf = b""
            for args in commands:
                response = _dispatch(args, attacker_ip, authenticated)
                sock.sendall(response)
                if args and args[0].upper() == "QUIT":
                    return
    except (OSError, TimeoutError):
        pass
    finally:
        sock.close()
        log.info("[disconnect] %s", attacker_ip)


def main() -> None:
    log.info("=== ShadowMesh Fake Redis Honeypot ===")
    log.info("NODE_ID           : %s", NODE_ID)
    log.info("CALLBACK          : %s", CALLBACK_ENDPOINT)
    log.info("Listening on      : %s:%d", HOST, PORT)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(128)
    log.info("Ready.")

    while True:
        try:
            client, addr = server.accept()
        except KeyboardInterrupt:
            break
        threading.Thread(target=_handle, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
