"""
ShadowMesh — Task 11.4: Fake MQTT Honeypot
===========================================
Native MQTT 3.1.1 broker that captures CONNECT credentials, SUBSCRIBE topics,
and PUBLISH payloads, then fires callbacks. Publishes realistic IoT telemetry
to lure attackers into deeper interaction.

Environment variables:
  NODE_ID               — Honeypot node ID
  ATTACKER_CALLBACK_URL — ShadowMesh backend base URL
"""

import os
import socket
import struct
import threading
import time
import logging
import json
import requests

HOST = "0.0.0.0"
PORT = int(os.environ.get("MQTT_PORT", 1883))
NODE_ID = os.environ.get("NODE_ID", "fake-mqtt-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-mqtt")

# MQTT packet type constants
_CONNECT     = 0x10
_CONNACK     = 0x20
_PUBLISH     = 0x30
_PUBACK      = 0x40
_SUBSCRIBE   = 0x82
_SUBACK      = 0x90
_PINGREQ     = 0xC0
_PINGRESP    = 0xD0
_DISCONNECT  = 0xE0

# Max PUBLISH payload captured (bytes) — prevents memory exhaustion
_MAX_PAYLOAD = 4096

# Fake telemetry topics published to connected clients
_TELEMETRY_TOPICS = [
    ("factory/line1/temperature",  lambda: json.dumps({"value": round(72.3 + (time.time() % 5), 2), "unit": "C"})),
    ("factory/line1/pressure",     lambda: json.dumps({"value": round(1.013 + (time.time() % 0.1), 4), "unit": "bar"})),
    ("scada/plc01/status",         lambda: json.dumps({"state": "RUNNING", "cycle": int(time.time()) % 10000})),
    ("building/hvac/setpoint",     lambda: json.dumps({"zone": "A", "setpoint": 21.5, "mode": "COOL"})),
    ("alerts/critical",            lambda: json.dumps({"level": "INFO", "msg": "Scheduled maintenance window 02:00-04:00"})),
]


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
# MQTT wire helpers
# ---------------------------------------------------------------------------

def _encode_remaining(length: int) -> bytes:
    """Encode MQTT variable-length remaining-length field."""
    out = b""
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        out += bytes([byte])
        if length == 0:
            break
    return out


def _decode_remaining(data: bytes, pos: int) -> tuple[int, int]:
    """Decode MQTT variable-length field. Returns (value, new_pos)."""
    multiplier = 1
    value = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value += (byte & 0x7F) * multiplier
        multiplier *= 128
        if not (byte & 0x80):
            break
        if multiplier > 128 * 128 * 128:
            raise ValueError("Malformed remaining length")
    return value, pos


def _read_utf8(data: bytes, pos: int) -> tuple[str, int]:
    """Read a 2-byte length-prefixed UTF-8 string."""
    if pos + 2 > len(data):
        raise ValueError("Truncated string length")
    length = struct.unpack_from("!H", data, pos)[0]
    pos += 2
    s = data[pos:pos + length].decode("utf-8", errors="replace")
    return s, pos + length


def _connack(return_code: int = 0, session_present: bool = False) -> bytes:
    flags = 0x01 if session_present else 0x00
    return bytes([_CONNACK, 0x02, flags, return_code])


def _suback(packet_id: int, return_codes: list[int]) -> bytes:
    payload = struct.pack("!H", packet_id) + bytes(return_codes)
    return bytes([_SUBACK]) + _encode_remaining(len(payload)) + payload


def _puback(packet_id: int) -> bytes:
    return bytes([_PUBACK, 0x02]) + struct.pack("!H", packet_id)


def _build_publish(topic: str, payload: str, qos: int = 0) -> bytes:
    topic_bytes = topic.encode()
    topic_len = struct.pack("!H", len(topic_bytes))
    payload_bytes = payload.encode()
    fixed = _PUBLISH | (qos << 1)
    body = topic_len + topic_bytes + payload_bytes
    return bytes([fixed]) + _encode_remaining(len(body)) + body


# ---------------------------------------------------------------------------
# CONNECT packet parser
# ---------------------------------------------------------------------------

def _parse_connect(data: bytes) -> dict:
    """
    Parse MQTT CONNECT packet body (after fixed header).
    Returns dict with keys: protocol, version, client_id, username, password,
    clean_session, keepalive.
    """
    pos = 0
    proto_name, pos = _read_utf8(data, pos)
    version = data[pos]; pos += 1
    connect_flags = data[pos]; pos += 1
    keepalive = struct.unpack_from("!H", data, pos)[0]; pos += 2

    clean_session  = bool(connect_flags & 0x02)
    will_flag      = bool(connect_flags & 0x04)
    username_flag  = bool(connect_flags & 0x80)
    password_flag  = bool(connect_flags & 0x40)

    client_id, pos = _read_utf8(data, pos)

    if will_flag:
        will_topic, pos = _read_utf8(data, pos)
        will_msg, pos   = _read_utf8(data, pos)

    username = ""
    password = ""
    if username_flag:
        username, pos = _read_utf8(data, pos)
    if password_flag:
        password, pos = _read_utf8(data, pos)

    return {
        "protocol": proto_name,
        "version": version,
        "client_id": client_id,
        "username": username,
        "password": password,
        "clean_session": clean_session,
        "keepalive": keepalive,
    }


# ---------------------------------------------------------------------------
# Telemetry publisher — runs in a daemon thread per connected client
# ---------------------------------------------------------------------------

def _publish_telemetry(sock: socket.socket, stop: threading.Event) -> None:
    """Continuously publish fake IoT telemetry to the connected client."""
    idx = 0
    while not stop.is_set():
        try:
            topic, payload_fn = _TELEMETRY_TOPICS[idx % len(_TELEMETRY_TOPICS)]
            pkt = _build_publish(topic, payload_fn())
            sock.sendall(pkt)
            log.debug("[publish] → %s", topic)
        except OSError:
            break
        idx += 1
        stop.wait(30)


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

def _handle(sock: socket.socket, addr: tuple) -> None:
    attacker_ip = addr[0]
    log.info("[connect] %s", attacker_ip)
    _cb(attacker_ip, "port_scan", f"MQTT connection from {attacker_ip}")

    stop_telemetry = threading.Event()
    telemetry_thread = None
    buf = b""

    try:
        sock.settimeout(120)
        connected = False

        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk

            while len(buf) >= 2:
                pkt_type = buf[0] & 0xF0
                try:
                    remaining, hdr_end = _decode_remaining(buf, 1)
                except ValueError:
                    buf = b""
                    break

                total = hdr_end + remaining
                if len(buf) < total:
                    break  # wait for more data

                packet_body = buf[hdr_end:total]
                buf = buf[total:]

                if pkt_type == _CONNECT:
                    try:
                        info = _parse_connect(packet_body)
                    except Exception as exc:
                        log.warning("[connect_parse] %s: %s", attacker_ip, exc)
                        sock.sendall(_connack(return_code=1))
                        return

                    log.info("[CONNECT] %s client_id=%r user=%r pass=%r",
                             attacker_ip, info["client_id"],
                             info["username"], info["password"])
                    _cb(attacker_ip, "login_attempt",
                        f"MQTT CONNECT: client_id={info['client_id']!r} "
                        f"user={info['username']!r} pass={info['password']!r}")

                    sock.sendall(_connack(return_code=0))
                    connected = True

                    # Start telemetry publisher
                    telemetry_thread = threading.Thread(
                        target=_publish_telemetry,
                        args=(sock, stop_telemetry),
                        daemon=True,
                    )
                    telemetry_thread.start()

                elif pkt_type == _SUBSCRIBE and connected:
                    if len(packet_body) < 2:
                        continue
                    packet_id = struct.unpack_from("!H", packet_body, 0)[0]
                    pos = 2
                    topics = []
                    return_codes = []
                    while pos < len(packet_body):
                        try:
                            topic, pos = _read_utf8(packet_body, pos)
                            qos = packet_body[pos]; pos += 1
                            topics.append(topic)
                            return_codes.append(min(qos, 1))
                        except (ValueError, IndexError):
                            break

                    log.info("[SUBSCRIBE] %s → %s", attacker_ip, topics)
                    _cb(attacker_ip, "data_access",
                        f"MQTT SUBSCRIBE topics={topics} from {attacker_ip}")
                    sock.sendall(_suback(packet_id, return_codes))

                elif pkt_type == _PUBLISH and connected:
                    # Parse topic and payload from PUBLISH
                    try:
                        topic, pos = _read_utf8(packet_body, 0)
                        qos = (buf[0] >> 1) & 0x03 if buf else 0
                        payload_raw = packet_body[pos:pos + _MAX_PAYLOAD]
                        payload_str = payload_raw.decode("utf-8", errors="replace")
                        log.info("[PUBLISH] %s → topic=%r payload=%r",
                                 attacker_ip, topic, payload_str[:200])
                        _cb(attacker_ip, "data_access",
                            f"MQTT PUBLISH topic={topic!r} payload={payload_str[:500]!r}")
                    except Exception as exc:
                        log.warning("[publish_parse] %s: %s", attacker_ip, exc)

                elif pkt_type == _PINGREQ:
                    sock.sendall(bytes([_PINGRESP, 0x00]))

                elif pkt_type == _DISCONNECT:
                    log.info("[DISCONNECT] %s", attacker_ip)
                    return

    except (OSError, TimeoutError):
        pass
    finally:
        stop_telemetry.set()
        sock.close()
        log.info("[disconnect] %s", attacker_ip)


def main() -> None:
    log.info("=== ShadowMesh Fake MQTT Honeypot ===")
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
