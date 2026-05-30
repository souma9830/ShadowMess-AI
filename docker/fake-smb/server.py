"""
ShadowMesh — Task 11.4: Fake SMB Honeypot
==========================================
impacket-based SMB server that captures share enumeration, authentication
attempts, and file access events, then fires callbacks to the ShadowMesh
backend.

Environment variables:
  NODE_ID               — Honeypot node ID (default: fake-smb-node)
  ATTACKER_CALLBACK_URL — ShadowMesh backend base URL
"""

import os
import time
import logging
import threading
import requests
from impacket import smbserver, ntlm
from impacket.smbserver import SimpleSMBServer

HOST = "0.0.0.0"
PORT = 445
NODE_ID = os.environ.get("NODE_ID", "fake-smb-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-smb")

# ---------------------------------------------------------------------------
# Fake share definitions — realistic Windows file server layout
# ---------------------------------------------------------------------------
FAKE_SHARES = {
    "FINANCE$": {
        "comment": "Finance Department Share",
        "files": [
            "Q1_2025_Budget.xlsx",
            "Q2_2025_Forecast.xlsx",
            "Payroll_May2025.xlsx",
            "Annual_Report_2024.pdf",
            "Audit_Trail_2024.csv",
        ],
    },
    "IT_ADMIN": {
        "comment": "IT Administration",
        "files": [
            "network_diagram.vsdx",
            "server_inventory.xlsx",
            "vpn_config_backup.zip",
            "ad_export_2025.ldif",
            "passwords_old.txt",
        ],
    },
    "BACKUP": {
        "comment": "Backup Storage",
        "files": [
            "db_backup_20250501.tar.gz",
            "db_backup_20250515.tar.gz",
            "config_backup_prod.zip",
        ],
    },
    "IPC$": {"comment": "Remote IPC", "files": []},
}

# ---------------------------------------------------------------------------
# Callback helper
# ---------------------------------------------------------------------------

def _fire_callback(attacker_ip: str, action_type: str, detail: str) -> None:
    """POST attacker action to ShadowMesh backend. Never raises."""
    payload = {
        "attacker_ip": attacker_ip,
        "action_type": action_type,
        "target_node_id": NODE_ID,
        "detail": detail,
        "timestamp": time.time(),
    }
    try:
        requests.post(CALLBACK_ENDPOINT, json=payload, timeout=5)
    except Exception as exc:
        log.warning("[callback] Failed: %s", exc)


def _cb(attacker_ip: str, action_type: str, detail: str) -> None:
    threading.Thread(target=_fire_callback, args=(attacker_ip, action_type, detail), daemon=True).start()


# ---------------------------------------------------------------------------
# Instrumented SMB server subclass
# ---------------------------------------------------------------------------

class HoneypotSMBServer(SimpleSMBServer):
    """
    Extends impacket's SimpleSMBServer to intercept authentication and
    share/file access events for intelligence collection.
    """

    def processConfigFile(self, configFile: str = None) -> None:
        """Skip config file loading — we configure programmatically."""
        pass

    def addShare(self, shareName: str, sharePath: str, shareComment: str = "") -> None:
        """Register a share with a virtual (non-existent) path."""
        self.getServerConfig().add_section(shareName)
        self.getServerConfig().set(shareName, "comment", shareComment)
        self.getServerConfig().set(shareName, "path", sharePath)
        self.getServerConfig().set(shareName, "readonly", "yes")
        self.getServerConfig().set(shareName, "browseable", "yes")


def _build_server() -> HoneypotSMBServer:
    """Construct and configure the SMB honeypot server."""
    import configparser
    import tempfile

    # impacket requires a minimal config file on disk
    cfg = configparser.ConfigParser()
    cfg["global"] = {
        "server_name": "FILESERVER01",
        "server_os": "Windows Server 2019",
        "server_domain": "CORP",
        "comment": "Corporate File Server",
        "challenge": "A" * 16,
    }
    cfg_path = os.path.join(tempfile.gettempdir(), "smb.conf")
    with open(cfg_path, "w") as f:
        cfg.write(f)

    server = HoneypotSMBServer(HOST, PORT, configFile=cfg_path)

    # Register fake shares pointing to /tmp (read-only, never actually read)
    for share_name, share_info in FAKE_SHARES.items():
        server.addShare(share_name, "/tmp", share_info["comment"])

    # Hook: capture every authentication attempt
    original_auth = server.hookSmbCommand if hasattr(server, "hookSmbCommand") else None

    def _auth_hook(conn_data, smb_command, recv_packet):
        try:
            client_ip = conn_data.get("ClientIP", "unknown")
            username = conn_data.get("Username", "")
            domain = conn_data.get("Domain", "")
            log.info("[auth] %s → domain=%r user=%r", client_ip, domain, username)
            _cb(client_ip, "login_attempt",
                f"SMB auth: domain={domain!r} user={username!r}")
        except Exception:
            pass

    server.setLogFile("/dev/null")
    return server


# ---------------------------------------------------------------------------
# Connection-level logging via monkey-patching impacket's session handler
# ---------------------------------------------------------------------------

def _patch_smb_server(server: HoneypotSMBServer) -> None:
    """
    Monkey-patch impacket's SMBServer to intercept NEGOTIATE, SESSION_SETUP,
    TREE_CONNECT, and QUERY_INFO commands for intelligence collection.
    """
    original_handle = server.processRequest if hasattr(server, "processRequest") else None

    # impacket exposes a hook dict for SMB commands
    # SMB2 command codes: NEGOTIATE=0, SESSION_SETUP=1, TREE_CONNECT=3, QUERY_INFO=16
    _SMB2_SESSION_SETUP = 0x0001
    _SMB2_TREE_CONNECT  = 0x0003
    _SMB2_QUERY_INFO    = 0x0010

    original_hooks = {}

    def _make_hook(cmd_id, original_fn):
        def _hook(conn_data, smb_command, recv_packet):
            try:
                client_ip = conn_data.get("ClientIP", "unknown")
                if cmd_id == _SMB2_SESSION_SETUP:
                    username = smb_command.fields.get("Buffer", b"")
                    log.info("[session_setup] %s", client_ip)
                    _cb(client_ip, "login_attempt",
                        f"SMB SESSION_SETUP from {client_ip}")
                elif cmd_id == _SMB2_TREE_CONNECT:
                    path = smb_command.fields.get("Buffer", b"").decode("utf-16-le", errors="replace")
                    log.info("[tree_connect] %s → %r", client_ip, path)
                    _cb(client_ip, "data_access",
                        f"SMB share enumeration: {path!r} from {client_ip}")
                elif cmd_id == _SMB2_QUERY_INFO:
                    log.info("[query_info] %s", client_ip)
                    _cb(client_ip, "data_access",
                        f"SMB file query from {client_ip}")
            except Exception:
                pass
            if original_fn:
                return original_fn(conn_data, smb_command, recv_packet)
        return _hook

    for cmd_id in (_SMB2_SESSION_SETUP, _SMB2_TREE_CONNECT, _SMB2_QUERY_INFO):
        orig = server.hookSmbCommand(cmd_id, None) if hasattr(server, "hookSmbCommand") else None
        server.hookSmbCommand(cmd_id, _make_hook(cmd_id, orig))


def main() -> None:
    log.info("=== ShadowMesh Fake SMB Honeypot ===")
    log.info("NODE_ID           : %s", NODE_ID)
    log.info("CALLBACK          : %s", CALLBACK_ENDPOINT)
    log.info("Listening on      : %s:%d", HOST, PORT)
    log.info("Shares            : %s", list(FAKE_SHARES.keys()))

    try:
        server = _build_server()
        _patch_smb_server(server)
        log.info("SMB server ready")
        server.start()
    except Exception as exc:
        log.error("SMB server failed to start: %s", exc)
        raise


if __name__ == "__main__":
    main()
