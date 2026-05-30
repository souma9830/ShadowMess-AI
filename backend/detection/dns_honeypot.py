import socket
import threading
import time
import asyncio
import random
from typing import Optional, Callable

try:
    from dnslib import DNSRecord, QTYPE, RR
    from dnslib import A as DNSAddrRecord
    _DNSLIB_AVAILABLE = True
except ImportError:
    _DNSLIB_AVAILABLE = False
    print('[DNS Honeypot] dnslib not installed — DNS honeypot disabled')

PLANTED_HOSTNAMES = {
    'finance-db.corp.internal':    'Finance DB canary — attacker targeting financial data',
    'hr-share.corp.internal':      'HR file share canary — attacker targeting HR data',
    'ad-dc.corp.internal':         'Active Directory DC canary — attacker targeting identity',
    'backup-server.corp.internal': 'Backup server canary — attacker targeting backups',
    'dev-gitlab.corp.internal':    'GitLab canary — attacker targeting source code',
    'vault.corp.internal':         'HashiCorp Vault canary — attacker targeting secrets',
}

FAKE_IP_POOL = ['172.20.0.11', '172.20.0.12', '172.20.0.13', '172.20.0.14', '172.20.0.15']

# Module-level singleton — set by init_dns_honeypot(), read by routes.py
_instance: Optional['DNSHoneypot'] = None


def get_instance() -> Optional['DNSHoneypot']:
    return _instance


class DNSHoneypot:
    def __init__(self, interface_ip: str, callback: Callable):
        self.interface_ip = interface_ip
        self.callback = callback
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._query_log: list = []
        self._log_lock = threading.Lock()

    def _handle_query(self, data: bytes, addr: tuple, sock: socket.socket):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip('.')

            try:
                qtype_str = QTYPE[request.q.qtype]
            except Exception:
                qtype_str = str(request.q.qtype)

            fake_ip = random.choice(FAKE_IP_POOL)

            # Build a realistic DNS A-record response
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=DNSAddrRecord(fake_ip), ttl=300))
            sock.sendto(reply.pack(), addr)

            query_info = {
                'hostname': qname,
                'query_type': qtype_str,
                'source_ip': addr[0],
                'resolved_to': fake_ip,
                'timestamp': time.time(),
                'is_planted': qname in PLANTED_HOSTNAMES,
                'canary_hint': PLANTED_HOSTNAMES.get(qname),
            }

            with self._log_lock:
                self._query_log.append(query_info)
                # Cap memory — keep last 200, return last 100
                if len(self._query_log) > 200:
                    self._query_log = self._query_log[-100:]

            if self._loop and self._loop.is_running():
                asyncio.run_coroutine_threadsafe(self.callback(query_info), self._loop)

        except Exception as e:
            print(f'[DNS Honeypot] handler error: {e}')

    def start(self, loop: asyncio.AbstractEventLoop):
        if not _DNSLIB_AVAILABLE:
            print('[DNS Honeypot] Disabled — dnslib not available. Run: pip install dnslib')
            return

        self._loop = loop
        self._running = True

        def run():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', 53))
                sock.settimeout(1.0)
                print('[DNS] Honeypot listening on UDP :53')
                while self._running:
                    try:
                        data, addr = sock.recvfrom(512)
                        threading.Thread(
                            target=self._handle_query,
                            args=(data, addr, sock),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        continue
                sock.close()
            except OSError as e:
                print(f'[DNS Honeypot] Failed to bind UDP :53 — {e}')
                print('[DNS Honeypot] Disabled. Needs root/sudo, or port 53 is taken by systemd-resolved.')
                self._running = False

        threading.Thread(target=run, daemon=True).start()

    def get_query_log(self) -> list:
        with self._log_lock:
            return list(self._query_log[-100:])

    def stop(self):
        self._running = False


def init_dns_honeypot(interface_ip: str, callback: Callable) -> 'DNSHoneypot':
    """Create the module-level singleton and return it. Call start() separately."""
    global _instance
    _instance = DNSHoneypot(interface_ip=interface_ip, callback=callback)
    return _instance
