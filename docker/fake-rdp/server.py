"""
ShadowMesh — Task 11.2: Fake RDP Honeypot
==========================================
A credential-harvesting RDP honeypot that implements enough of the
MS-RDP protocol (TPKT/X.224/MCS/Security) to capture attacker
credentials, then returns a plausible authentication failure.

Protocol coverage:
  - TPKT framing (RFC 1006)
  - X.224 Connection Request/Confirm
  - MCS Connect-Initial / Connect-Response
  - RDP Security Exchange (Classic RDP — RC4 key exchange, plaintext creds)
  - NLA/CredSSP downgrade detection (client redirected to Classic RDP)
  - Client Info PDU parsing (username, domain, password, hostname)
  - Graceful disconnect after credential capture

What is NOT implemented (future extension via desktop_bitmap.py):
  - Full TLS/CredSSP NLA (requires impacket; yields NTLM hashes)
  - Desktop bitmap streaming
  - Input channel (keyboard/mouse post-auth)
  - Virtual channels (clipboard, audio, drives)

Every attacker interaction fires a structured POST callback to the
ShadowMesh backend, matching the pattern of all other fake services.

Environment variables:
  NODE_ID               — Honeypot node ID injected by container_manager
  ATTACKER_CALLBACK_URL — ShadowMesh backend base URL (default: http://backend:8000)
  RDP_PORT              — Listening port (default: 3389)
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
import time
import traceback
from typing import Optional

import requests

from rdp_session import RDPSession

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = int(os.environ.get("RDP_PORT", 3389))
NODE_ID = os.environ.get("NODE_ID", "fake-rdp-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

# Hard session timeout — prevents resource exhaustion from slow clients
SESSION_TIMEOUT_S = 300

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-rdp")

# ---------------------------------------------------------------------------
# RDP protocol constants
# ---------------------------------------------------------------------------

# TPKT
_TPKT_VERSION = 3

# X.224 PDU types
_X224_CR = 0xE0   # Connection Request
_X224_CC = 0xD0   # Connection Confirm
_X224_DR = 0x80   # Disconnect Request
_X224_DT = 0xF0   # Data

# MCS
_MCS_CONNECT_INITIAL  = 0x7F65
_MCS_CONNECT_RESPONSE = 0x7F66

# RDP Security
_SEC_EXCHANGE_PKT  = 0x0001
_SEC_INFO_PKT      = 0x0040
_SEC_LOGON_INFO    = 0x0040

# Negotiation flags
_PROTOCOL_RDP = 0x00000000
_PROTOCOL_SSL = 0x00000001
_PROTOCOL_NLA = 0x00000002

# Disconnect reason: logon failure
_DISCONNECT_REASON_LOGON_FAILURE = 0x0000_0005

# ---------------------------------------------------------------------------
# Callback
# ---------------------------------------------------------------------------

def _fire_callback(session: RDPSession, action_type: str, detail: str) -> None:
    """POST a structured attacker action event. Never raises."""
    payload = {
        "attacker_ip":    session.attacker_ip,
        "action_type":    action_type,
        "target_node_id": session.node_id,
        "detail":         detail,
        "timestamp":      time.time(),
    }
    try:
        requests.post(CALLBACK_ENDPOINT, json=payload, timeout=5)
    except Exception as exc:
        log.warning("[callback] Failed: %s", exc)


def _fire_async(session: RDPSession, action_type: str, detail: str) -> None:
    threading.Thread(
        target=_fire_callback,
        args=(session, action_type, detail),
        daemon=True,
    ).start()


# ---------------------------------------------------------------------------
# TPKT helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes; raises ConnectionError on short read."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf += chunk
    return buf


def _recv_tpkt(sock: socket.socket) -> bytes:
    """Read one complete TPKT packet; return the payload (X.224 data)."""
    header = _recv_exact(sock, 4)
    version, _, length_hi, length_lo = struct.unpack("BBBB", header)
    if version != _TPKT_VERSION:
        raise ValueError(f"Unexpected TPKT version: {version}")
    total_length = (length_hi << 8) | length_lo
    payload_length = total_length - 4
    if payload_length <= 0:
        return b""
    return _recv_exact(sock, payload_length)


def _make_tpkt(payload: bytes) -> bytes:
    """Wrap payload in a TPKT header."""
    length = len(payload) + 4
    return struct.pack("BBBB", _TPKT_VERSION, 0, (length >> 8) & 0xFF, length & 0xFF) + payload


def _make_x224_dt(data: bytes) -> bytes:
    """Wrap data in an X.224 Data TPDU."""
    # LI=2, PDU type=DT, EOT=0x80
    return bytes([2, _X224_DT, 0x80]) + data


# ---------------------------------------------------------------------------
# Phase 1: X.224 Connection Negotiation
# ---------------------------------------------------------------------------

def _handle_x224_cr(sock: socket.socket, session: RDPSession) -> int:
    """
    Read X.224 Connection Request, parse RDP Negotiation Request,
    send X.224 Connection Confirm with RDP_PROTOCOL_RDP (Classic RDP).

    Returns the protocol requested by the client (0=RDP, 1=SSL, 2=NLA).
    NLA clients are downgraded to Classic RDP — they will retry or proceed.
    """
    payload = _recv_tpkt(sock)
    # X.224 CR: LI, PDU type, DST-REF(2), SRC-REF(2), CLASS(1), [variable]
    if len(payload) < 7:
        raise ValueError("X.224 CR too short")

    li = payload[0]
    pdu_type = payload[1]
    if pdu_type != _X224_CR:
        raise ValueError(f"Expected X.224 CR (0xE0), got 0x{pdu_type:02X}")

    # RDP Negotiation Request starts after the fixed 7-byte X.224 header
    requested_protocol = _PROTOCOL_RDP
    if len(payload) > 7:
        neg_data = payload[7:]
        if len(neg_data) >= 8 and neg_data[0] == 0x01:  # TYPE_RDP_NEG_REQ
            requested_protocol = struct.unpack_from("<I", neg_data, 4)[0]

    if requested_protocol & _PROTOCOL_NLA:
        log.info("[%s] Client requested NLA — downgrading to Classic RDP", session.attacker_ip)
        _fire_async(session, "login_attempt",
                    "RDP NLA negotiation detected — downgraded to Classic RDP security")

    # Build X.224 Connection Confirm
    # RDP Negotiation Response: type=0x02, flags=0, length=8, selectedProtocol=RDP
    neg_response = struct.pack("<BBHI", 0x02, 0x00, 8, _PROTOCOL_RDP)
    # X.224 CC: LI, PDU=CC, DST-REF(2), SRC-REF(2), CLASS(1)
    x224_cc = bytes([
        6 + len(neg_response),  # LI
        _X224_CC,
        0x00, 0x00,             # DST-REF (echo client's SRC-REF)
        0x00, 0x00,             # SRC-REF
        0x00,                   # CLASS 0
    ]) + neg_response

    sock.sendall(_make_tpkt(x224_cc))
    log.info("[%s] X.224 handshake complete (protocol=0x%X)", session.attacker_ip, requested_protocol)
    return requested_protocol


# ---------------------------------------------------------------------------
# Phase 2: MCS Connect
# ---------------------------------------------------------------------------

# Minimal MCS Connect-Response (GCC Conference Create Response embedded)
# This is a pre-built valid response that satisfies most RDP clients enough
# to proceed to the Security Exchange phase.
_MCS_CONNECT_RESPONSE_PAYLOAD = bytes([
    # BER: CONNECT-RESPONSE
    0x7F, 0x66,
    # length (will be patched below if needed — fixed size here)
    0x81, 0x72,
    # result: rt-successful (0)
    0x0A, 0x01, 0x00,
    # calledConnectId: 0
    0x02, 0x01, 0x00,
    # domainParameters
    0x30, 0x19,
        0x02, 0x01, 0x22,  # maxChannelIds: 34
        0x02, 0x01, 0x03,  # maxUserIds: 3
        0x02, 0x01, 0x00,  # maxTokenIds: 0
        0x02, 0x01, 0x01,  # numPriorities: 1
        0x02, 0x01, 0x00,  # minThroughput: 0
        0x02, 0x01, 0x01,  # maxHeight: 1
        0x02, 0x02, 0xFF, 0xFF,  # maxMCSPDUsize: 65535
        0x02, 0x01, 0x02,  # protocolVersion: 2
    # userData (GCC Conference Create Response — minimal)
    0x04, 0x52,
        # T.124 GCC header
        0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01,
        0x2A, 0x14, 0x76, 0x0A, 0x01, 0x01, 0x00, 0x01,
        0xC0, 0x00, 0x4D, 0x63, 0x44, 0x6E,
        # Server Core Data (TS_UD_SC_CORE)
        0x01, 0x0C, 0x0C, 0x00,
            0x04, 0x00, 0x08, 0x00,  # version: RDP 5.0
            0x00, 0x00, 0x00, 0x00,
        # Server Network Data (TS_UD_SC_NET)
        0x03, 0x0C, 0x08, 0x00,
            0xEB, 0x03,              # MCSChannelId: 1003
            0x00, 0x00,
        # Server Security Data (TS_UD_SC_SEC1) — Classic RDP, 40-bit RC4
        0x02, 0x0C, 0x1C, 0x00,
            0x02, 0x00, 0x00, 0x00,  # encryptionMethod: 40-bit
            0x02, 0x00, 0x00, 0x00,  # encryptionLevel: CLIENT_COMPATIBLE
            # serverRandom (32 bytes — fake, not used for real crypto)
            0x20, 0x00, 0x00, 0x00,
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
            # serverCertificate length: 0 (no cert — triggers client fallback)
            0x00, 0x00, 0x00, 0x00,
])


def _handle_mcs_connect(sock: socket.socket, session: RDPSession) -> None:
    """
    Read MCS Connect-Initial (client capabilities), send Connect-Response.
    Parses client info fields for logging: hostname, build number.
    """
    payload = _recv_tpkt(sock)
    # Skip X.224 DT header (3 bytes) to reach MCS data
    if len(payload) < 3:
        raise ValueError("MCS packet too short")
    mcs_data = payload[3:]

    # Best-effort parse of GCC Conference Create Request for client info
    # The client hostname appears as a UTF-16LE string in the Client Core Data
    # block (TS_UD_CS_CORE), at a fixed offset within the userData blob.
    # We scan for the block type marker 0x01 0x0C rather than full BER decode.
    try:
        idx = mcs_data.find(b"\x01\x0C")
        if idx != -1 and len(mcs_data) > idx + 24:
            core_block = mcs_data[idx:]
            # clientName is at offset 24, 15 UTF-16LE chars (30 bytes)
            name_raw = core_block[24:54]
            name = name_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            if name:
                session.client_hostname = name
            # clientBuild at offset 8 (4 bytes LE)
            if len(core_block) >= 12:
                build = struct.unpack_from("<I", core_block, 8)[0]
                session.client_build = str(build)
    except Exception:
        pass  # Non-critical — best-effort parse

    # Send pre-built MCS Connect-Response wrapped in X.224 DT + TPKT
    x224_dt = _make_x224_dt(_MCS_CONNECT_RESPONSE_PAYLOAD)
    sock.sendall(_make_tpkt(x224_dt))
    log.info("[%s] MCS connect complete (client_host=%s build=%s)",
             session.attacker_ip, session.client_hostname, session.client_build)


# ---------------------------------------------------------------------------
# Phase 3: MCS Erect Domain + Attach User
# ---------------------------------------------------------------------------

def _handle_mcs_erect_attach(sock: socket.socket, session: RDPSession) -> None:
    """
    Read MCS Erect Domain Request and Attach User Request.
    Send Attach User Confirm.
    These are required MCS setup PDUs before channel joins.
    """
    # Erect Domain Request
    _recv_tpkt(sock)

    # Attach User Request
    _recv_tpkt(sock)

    # Attach User Confirm: BER tag 0x28, length 3, result=0, initiator=1001
    auc = bytes([0x28, 0x03, 0x00, 0x03, 0xEB])
    sock.sendall(_make_tpkt(_make_x224_dt(auc)))

    # Channel Join Requests — clients typically join 3-5 channels
    # We accept all of them with Channel Join Confirms
    for _ in range(5):
        try:
            sock.settimeout(2.0)
            pkt = _recv_tpkt(sock)
            # Channel Join Request: first byte 0x38
            if pkt and len(pkt) >= 3 and pkt[3] == 0x38:
                channel_id = struct.unpack_from(">H", pkt, 6)[0] if len(pkt) >= 8 else 0x03EB
                # Channel Join Confirm: tag=0x3E, result=0, initiator, requested, channelId
                cjc = struct.pack(">BBHHH", 0x3E, 0x06, 0x00, 0x03, channel_id, channel_id)
                sock.sendall(_make_tpkt(_make_x224_dt(cjc)))
        except socket.timeout:
            break
        finally:
            sock.settimeout(SESSION_TIMEOUT_S)


# ---------------------------------------------------------------------------
# Phase 4: Security Exchange + Client Info (credential capture)
# ---------------------------------------------------------------------------

def _parse_unicode_field(data: bytes, offset: int, length: int) -> str:
    """Extract a UTF-16LE string from data at offset with byte length."""
    if offset + length > len(data):
        return ""
    return data[offset:offset + length].decode("utf-16-le", errors="replace").rstrip("\x00")


def _handle_security_exchange(sock: socket.socket, session: RDPSession) -> None:
    """
    Read Security Exchange PDU (encrypted client random — discarded, we don't
    actually decrypt) and Client Info PDU (contains username, domain, password
    in UTF-16LE, nominally RC4-encrypted but often cleartext in low-security mode).

    We capture whatever is readable and fire a credential event.
    """
    # Security Exchange PDU
    try:
        pkt = _recv_tpkt(sock)
        # Skip X.224 DT (3 bytes) + MCS Send Data (variable) to reach SEC header
        # SEC header: flags(2) + flagsHi(2); SEC_EXCHANGE_PKT = 0x0001
        # We just consume this packet — the encrypted client random is useless
        # without the server private key (which we never generate properly).
        log.debug("[%s] Security Exchange PDU received (%d bytes)", session.attacker_ip, len(pkt))
    except Exception:
        pass

    # Client Info PDU — this is where credentials live
    try:
        pkt = _recv_tpkt(sock)
        if len(pkt) < 20:
            return

        # Skip X.224 DT (3 bytes) + MCS SDrq header (~8 bytes) + SEC header (4 bytes)
        # The exact offset varies; scan for the TS_INFO_PACKET marker
        # TS_INFO_PACKET starts with codePage(4) + flags(4) + cbDomain(2) + cbUserName(2)
        # + cbPassword(2) + cbAlternateShell(2) + cbWorkingDir(2) = 18 bytes fixed header
        # We scan for a plausible offset by looking for the INFO_UNICODE flag (0x0040)
        data = pkt

        # Try multiple offsets — the MCS/SEC header size varies by client
        for skip in (15, 18, 20, 24, 28):
            if len(data) < skip + 18:
                continue
            info = data[skip:]
            flags = struct.unpack_from("<I", info, 4)[0]
            if not (flags & 0x0040):  # INFO_UNICODE
                continue

            cb_domain   = struct.unpack_from("<H", info, 8)[0]
            cb_username = struct.unpack_from("<H", info, 10)[0]
            cb_password = struct.unpack_from("<H", info, 12)[0]

            # Sanity bounds: each field ≤ 512 bytes (256 UTF-16 chars)
            if any(v > 512 for v in (cb_domain, cb_username, cb_password)):
                continue

            offset = 18  # fixed header size
            domain   = _parse_unicode_field(info, offset, cb_domain)
            offset  += cb_domain + 2  # +2 for null terminator
            username = _parse_unicode_field(info, offset, cb_username)
            offset  += cb_username + 2
            password = _parse_unicode_field(info, offset, cb_password)

            if username:
                session.username = username
                session.domain   = domain or None
                session.password = password or None
                log.info("[%s] Credentials captured: domain=%r user=%r pass=%r",
                         session.attacker_ip, domain, username, password)
                break

    except Exception as exc:
        log.debug("[%s] Client Info parse error: %s", session.attacker_ip, exc)


# ---------------------------------------------------------------------------
# Phase 5: Send logon failure and disconnect
# ---------------------------------------------------------------------------

def _send_logon_failure(sock: socket.socket) -> None:
    """
    Send an RDP Error Info PDU indicating logon failure, then a
    Deactivate All PDU to cleanly terminate the session.

    The client will display "The credentials that were used to connect
    to [host] did not work." — a realistic Windows RDP error.
    """
    # TS_SET_ERROR_INFO_PDU: shareId=0x03EA, streamId=1, uncompressedLength=4,
    # pduType=SET_ERROR_INFO_PDU(0x002B), errorInfo=ERRINFO_LOGON_FAILURE(0x0000_0516)
    error_pdu = struct.pack(
        "<IBBHHI",
        0x000003EA,  # shareId
        0x00,        # streamId
        0x01,        # uncompressedLength hi
        0x0009,      # uncompressedLength (9 bytes)
        0x002B,      # pduType: SET_ERROR_INFO_PDU
        0x00000516,  # errorInfo: ERRINFO_LOGON_FAILURE
    )
    try:
        sock.sendall(_make_tpkt(_make_x224_dt(error_pdu)))
    except Exception:
        pass

    # X.224 Disconnect Request
    dr = bytes([0x02, _X224_DR, 0x00, 0x00, 0x00, 0x00, 0x00])
    try:
        sock.sendall(_make_tpkt(dr))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

def _handle_connection(client_sock: socket.socket, attacker_ip: str) -> None:
    """Drive the full RDP honeypot handshake for one attacker connection."""
    session = RDPSession(attacker_ip=attacker_ip, node_id=NODE_ID)
    log.info("[connect] %s", attacker_ip)

    _fire_async(session, "login_attempt",
                f"RDP connection initiated from {attacker_ip}")

    try:
        client_sock.settimeout(SESSION_TIMEOUT_S)

        _handle_x224_cr(client_sock, session)
        _handle_mcs_connect(client_sock, session)
        _handle_mcs_erect_attach(client_sock, session)
        _handle_security_exchange(client_sock, session)

        session.close()

        # Fire credential event
        cred_detail = (
            f"RDP credentials captured — "
            f"user={session.username!r} "
            f"domain={session.domain!r} "
            f"password={session.password!r} "
            f"client_host={session.client_hostname!r} "
            f"build={session.client_build!r} "
            f"duration={session.duration}s"
        )
        _fire_async(session, "credential_theft", cred_detail)
        log.info("[%s] Session complete — user=%r domain=%r duration=%.1fs",
                 attacker_ip, session.username, session.domain, session.duration)

        _send_logon_failure(client_sock)

    except (ConnectionError, OSError) as exc:
        session.close()
        log.info("[%s] Connection dropped: %s (duration=%.1fs)",
                 attacker_ip, exc, session.duration)
    except Exception:
        session.close()
        log.error("[%s] Unhandled error:\n%s", attacker_ip, traceback.format_exc())
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("=== ShadowMesh Fake RDP Honeypot ===")
    log.info("NODE_ID           : %s", NODE_ID)
    log.info("ATTACKER_CALLBACK : %s", CALLBACK_ENDPOINT)
    log.info("Listening on      : %s:%d", HOST, PORT)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(100)
    log.info("Ready. Waiting for attackers...")

    while True:
        try:
            client_sock, client_addr = server_sock.accept()
        except KeyboardInterrupt:
            log.info("Shutting down.")
            break

        threading.Thread(
            target=_handle_connection,
            args=(client_sock, client_addr[0]),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()
