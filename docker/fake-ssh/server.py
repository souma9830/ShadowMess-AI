"""
ShadowMesh — Task 4.1: Fake SSH Honeypot
=========================================
A Paramiko-based SSH honeypot that:
  - Accepts ANY username/password (always succeeds after an 800ms delay)
  - Presents a fake interactive bash shell
  - Returns hardcoded realistic-looking responses to known commands
  - Fires a POST callback to the ShadowMesh backend for every login and command
  - NEVER executes any real system command

Environment variables:
  NODE_ID              — The honeypot node ID injected by the container_manager
  ATTACKER_CALLBACK_URL — Base URL of the ShadowMesh backend (default: http://backend:8000)

Usage:
  python server.py          # Starts listening on port 22 inside the container
"""

import os
import socket
import threading
import time
import logging
import traceback

import paramiko
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = int(os.environ.get("SSH_PORT", 22))
NODE_ID = os.environ.get("NODE_ID", "fake-ssh-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-ssh")

# ---------------------------------------------------------------------------
# Fake /etc/passwd  (20 realistic-looking but totally fabricated entries)
# ---------------------------------------------------------------------------
FAKE_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
mysql:x:110:118:MySQL Server:/var/lib/mysql:/bin/false
postgres:x:111:119:PostgreSQL administrator:/var/lib/postgresql:/bin/bash
admin:x:1000:1000:ShadowAdmin,,,:/home/admin:/bin/bash
devops:x:1001:1001:DevOps Engineer,,,:/home/devops:/bin/bash
"""

# ---------------------------------------------------------------------------
# Hardcoded command responses — spec-compliant
# ---------------------------------------------------------------------------
COMMAND_RESPONSES: dict[str, str] = {
    "ls": "Documents  Downloads  .ssh  .bash_history  financial_reports  employee_data",
    "pwd": "/home/admin",
    "whoami": "admin",
    "id": "uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),27(sudo)",
    "cat /etc/passwd": FAKE_PASSWD.strip(),
    "uname -a": "Linux db-prod-01 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
    "ps aux": (
        "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root           1  0.0  0.1 168112 11428 ?        Ss   09:00   0:01 /sbin/init\n"
        "root         412  0.0  0.0  14432  1820 ?        Ss   09:00   0:00 /usr/sbin/sshd -D\n"
        "mysql        731  0.5  2.3 1823412 94716 ?       Sl   09:00   1:02 /usr/sbin/mysqld\n"
        "postgres     812  0.1  1.8 312052 73408 ?        Ss   09:00   0:18 postgres: checkpointer\n"
        "admin       1337  0.0  0.0  21296  5104 pts/0    Ss   09:12   0:00 -bash\n"
        "admin       1401  0.0  0.0  38388  3392 pts/0    R+   09:14   0:00 ps aux"
    ),
    "netstat -an": (
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:5432            0.0.0.0:*               LISTEN\n"
        "tcp        0    116 172.20.0.5:22           172.20.0.1:52341        ESTABLISHED\n"
        "tcp6       0      0 :::80                   :::*                    LISTEN\n"
        "tcp6       0      0 :::443                  :::*                    LISTEN"
    ),
    "history": (
        "    1  apt-get update\n"
        "    2  apt-get install -y mysql-server\n"
        "    3  systemctl start mysql\n"
        "    4  mysql_secure_installation\n"
        "    5  ufw allow 3306/tcp\n"
        "    6  nano /etc/mysql/mysql.conf.d/mysqld.cnf\n"
        "    7  tail -f /var/log/mysql/error.log\n"
        "    8  ls\n"
        "    9  history"
    ),
}

# ---------------------------------------------------------------------------
# Callback helper
# ---------------------------------------------------------------------------
def _fire_callback(attacker_ip: str, action_type: str, detail: str) -> None:
    """POST an attacker action to the ShadowMesh backend. Never raises."""
    payload = {
        "attacker_ip": attacker_ip,
        "action_type": action_type,
        "target_node_id": NODE_ID,
        "detail": detail,
        "timestamp": time.time(),
    }
    try:
        resp = requests.post(CALLBACK_ENDPOINT, json=payload, timeout=5)
        log.info("[callback] POST %s → %s %s", CALLBACK_ENDPOINT, resp.status_code, action_type)
    except Exception as exc:
        # Never let a broken backend bring down the honeypot
        log.warning("[callback] Failed to reach backend: %s", exc)


def _fire_callback_async(attacker_ip: str, action_type: str, detail: str) -> None:
    """Fire callback in a daemon thread so it never blocks the shell loop."""
    t = threading.Thread(
        target=_fire_callback,
        args=(attacker_ip, action_type, detail),
        daemon=True,
    )
    t.start()

# ---------------------------------------------------------------------------
# Paramiko server interface — pure authentication + session gating
# ---------------------------------------------------------------------------
class _HoneypotServerInterface(paramiko.ServerInterface):
    """
    Paramiko hook layer.
    - check_auth_password always returns AUTH_SUCCESSFUL after the 800 ms delay
    - check_channel_request gates on session only
    - check_channel_pty_request / check_channel_shell_request both approve
    """

    def __init__(self, attacker_ip: str) -> None:
        self.attacker_ip = attacker_ip
        self.event = threading.Event()

    # Accept any username/password pair
    def check_auth_password(self, username: str, password: str) -> int:
        log.info("[auth] %s → username=%r password=%r", self.attacker_ip, username, password)

        # 800 ms realistic login delay before granting access
        time.sleep(0.8)

        _fire_callback_async(
            self.attacker_ip,
            action_type="login_attempt",
            detail=f"SSH login accepted — username={username!r} password={password!r}",
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_none(self, username: str) -> int:
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

# ---------------------------------------------------------------------------
# Interactive fake shell — command dispatch
# ---------------------------------------------------------------------------
def _resolve_command(raw: str) -> str:
    """
    Look up the command in COMMAND_RESPONSES (exact match after stripping).
    Falls back to the 'command not found' message for anything not in the map.
    """
    cmd = raw.strip()
    if cmd in COMMAND_RESPONSES:
        return COMMAND_RESPONSES[cmd]
    # Extract the first token as the command name for the error message
    first_token = cmd.split()[0] if cmd.split() else cmd
    return f"bash: {first_token}: command not found"


def _run_fake_shell(channel: paramiko.Channel, attacker_ip: str) -> None:
    """
    Drives the fake interactive bash shell over the given Paramiko channel.
    Reads commands line-by-line, dispatches to _resolve_command, and fires
    a callback for every command executed.
    """
    prompt = b"admin@db-prod-01:~$ "
    channel.sendall(b"\r\nWelcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n")
    channel.sendall(b" * Documentation:  https://help.ubuntu.com\r\n\r\n")
    channel.sendall(prompt)

    buf = b""
    while True:
        try:
            data = channel.recv(1024)
        except OSError:
            break

        if not data:
            break

        for byte in data:
            char = bytes([byte])

            # Handle carriage return / newline — command submitted
            if char in (b"\r", b"\n"):
                channel.sendall(b"\r\n")
                cmd_str = buf.decode("utf-8", errors="replace").strip()
                buf = b""

                if not cmd_str:
                    channel.sendall(prompt)
                    continue

                if cmd_str in ("exit", "logout", "quit"):
                    channel.sendall(b"logout\r\n")
                    channel.close()
                    return

                response = _resolve_command(cmd_str)
                channel.sendall((response + "\r\n").encode("utf-8"))

                _fire_callback_async(
                    attacker_ip,
                    action_type="command_exec",
                    detail=f"SSH command executed: {cmd_str!r}",
                )

                channel.sendall(prompt)

            elif char == b"\x7f":
                # Backspace
                if buf:
                    buf = buf[:-1]
                    channel.sendall(b"\x08 \x08")
            else:
                # Regular printable character — echo back
                buf += char
                channel.sendall(char)

# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------
def _handle_connection(client_sock: socket.socket, client_addr: tuple, host_key: paramiko.RSAKey) -> None:
    attacker_ip = client_addr[0]
    log.info("[connect] Incoming connection from %s", attacker_ip)

    transport: paramiko.Transport | None = None
    try:
        transport = paramiko.Transport(client_sock)
        # Spoof a realistic OpenSSH identification string instead of the default
        # "paramiko_x.y", which trivially fingerprints the honeypot as a Python
        # process. SSH_BANNER is configurable so deployments can match their fleet.
        transport.local_version = os.environ.get(
            "SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        transport.add_server_key(host_key)

        server_interface = _HoneypotServerInterface(attacker_ip)
        transport.start_server(server=server_interface)

        # Wait up to 30 seconds for the client to open a channel
        channel = transport.accept(30)
        if channel is None:
            log.warning("[connect] No channel opened by %s — dropping", attacker_ip)
            return

        # Wait for shell request (PTY + shell request set the event)
        server_interface.event.wait(10)

        _run_fake_shell(channel, attacker_ip)
        log.info("[connect] Session closed for %s", attacker_ip)

    except Exception:
        log.error("[connect] Unhandled error for %s:\n%s", attacker_ip, traceback.format_exc())
    finally:
        if transport:
            transport.close()

# ---------------------------------------------------------------------------
# Main — generate ephemeral host key and start listening
# ---------------------------------------------------------------------------
def main() -> None:
    log.info("=== ShadowMesh Fake SSH Honeypot ===")
    log.info("NODE_ID            : %s", NODE_ID)
    log.info("ATTACKER_CALLBACK  : %s", CALLBACK_ENDPOINT)
    log.info("Listening on       : %s:%d", HOST, PORT)

    # Generate a fresh RSA host key every time the container starts.
    # This is intentional: we never persist or leak a real key.
    host_key = paramiko.RSAKey.generate(2048)
    log.info("Host key generated (ephemeral, 2048-bit RSA)")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(100)
    log.info("Ready. Waiting for attackers...")

    while True:
        try:
            client_sock, client_addr = server_sock.accept()
        except KeyboardInterrupt:
            log.info("Shutting down honeypot.")
            break

        # Each connection gets its own daemon thread — honeypot never blocks
        t = threading.Thread(
            target=_handle_connection,
            args=(client_sock, client_addr, host_key),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    main()
