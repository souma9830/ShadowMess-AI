import time
import socket
import struct
import requests
import argparse
import sys
import random


def print_step(msg):
    print(f"\n[*] {msg}")


def sleep_msg(seconds, msg):
    print(f"    ... {msg}")
    time.sleep(seconds)


def send_dns_query(hostname: str, dns_server: str = '127.0.0.1', port: int = 53, timeout: float = 1.0) -> bool:
    """
    Sends a minimal valid DNS A-record query via UDP.
    Returns True if a response was received (honeypot replied), False otherwise.
    """
    try:
        # Build a minimal DNS query packet manually (no external deps)
        transaction_id = random.randint(1, 65535)
        flags = 0x0100  # standard query, recursion desired
        questions = 1
        header = struct.pack('>HHHHHH', transaction_id, flags, questions, 0, 0, 0)

        # Encode hostname as DNS labels (e.g. vault.corp.internal → \x05vault\x04corp\x08internal\x00)
        labels = b''
        for part in hostname.split('.'):
            encoded = part.encode('ascii')
            labels += bytes([len(encoded)]) + encoded
        labels += b'\x00'  # root label

        qtype = struct.pack('>H', 1)   # A record
        qclass = struct.pack('>H', 1)  # IN class
        packet = header + labels + qtype + qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (dns_server, port))
        sock.recvfrom(512)  # wait for honeypot response
        sock.close()
        return True
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser(description="Simulate an APT attack against ShadowMesh.")
    parser.add_argument("--target-ip", default="192.168.1.100", help="Attacker IP to spoof in payloads")
    parser.add_argument("--backend-url", default="http://localhost:8000", help="ShadowMesh Backend URL")
    args = parser.parse_args()

    BASE_URL = args.backend_url
    ATTACKER_IP = args.target_ip

    print("="*60)
    print("[ ShadowMesh Demo — Simulated APT Attack ]")
    print("="*60)

    # We need to hit real sockets for Scapy to pick it up and trigger deception
    print_step("Phase 1 — Port Scan (Triggering Scapy ReconDetector)")
    ports = [22, 80, 443, 3306, 5432, 8080, 445, 3389, 25, 389]
    for host in range(10, 21):
        target = f"172.20.0.{host}"
        # We only scan 2 random ports per host to mimic stealth, but hit enough hosts to trigger lateral or port scan
        for port in random.sample(ports, 2):
            print(f"    Scanning {target}:{port} ...")
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                # BIND to the attacker IP so Scapy sees it if we're on a compatible interface,
                # but since we can't spoof IP over TCP handshake without raw sockets, 
                # Scapy will see our actual local IP. That's fine for the demo trigger.
                s.connect((target, port))
                s.close()
            except Exception:
                pass
            time.sleep(0.2)
    
    print_step("Phase 2 — Service Probe")
    sleep_msg(3, "Running nmap -sV -O ...")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "port_scan",
        "target_node_id": "node_unknown",
        "detail": "nmap -sV -O scan detected — 11 ports across 4 hosts",
        "timestamp": time.time()
    })

    sleep_msg(3, "Attacker mapping network...")

    # Fetch topology to get a valid node ID
    try:
        r = requests.get(f"{BASE_URL}/api/topology/current")
        topo = r.json()
        if topo.get("nodes"):
            first_node_id = topo["nodes"][0]["node_id"]
        else:
            first_node_id = "node_demo_01"
    except Exception:
        first_node_id = "node_demo_01"

    print_step("Phase 3 — Login Attempt")
    print(f"    Attempting SSH login to 172.20.0.14...")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "login_attempt",
        "target_node_id": first_node_id,
        "detail": "SSH brute force: admin/password123",
        "timestamp": time.time()
    })

    sleep_msg(2, "Brute forcing...")

    print_step("Phase 4 — Command Execution")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "command_exec",
        "target_node_id": first_node_id,
        "detail": "exec: cat /etc/passwd",
        "timestamp": time.time()
    })
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "command_exec",
        "target_node_id": first_node_id,
        "detail": "exec: ls -la /home/admin",
        "timestamp": time.time()
    })

    sleep_msg(2, "Exploring filesystem...")

    print_step("Phase 5 — Credential Theft")
    print("    Found .env file — downloading...")
    try:
        resp = requests.get(f"{BASE_URL}/api/creds/{first_node_id}/env_file", headers={"X-Forwarded-For": ATTACKER_IP})
        if resp.status_code == 200:
            print("    [CONTENT] " + resp.text[:200].replace("\n", " | "))
        else:
            print(f"    [Fallback] Credential endpoint returned {resp.status_code}")
    except Exception as e:
         print(f"    [Fallback] Could not reach creds endpoint: {e}")

    sleep_msg(1, "Parsing credentials...")

    print_step("Phase 5b — DNS Reconnaissance (populates DNS Intelligence panel)")
    dns_queries = [
        'internal-api.corp.internal',
        'dev-gitlab.corp.internal',       # planted canary
        'vault.corp.internal',            # planted canary
        'finance-db.corp.internal',       # planted canary
        'db-prod-01.corp.internal',
        'ad-dc.corp.internal',            # planted canary
    ]
    for hostname in dns_queries:
        print(f"    DNS lookup: {hostname}")
        hit = send_dns_query(hostname)
        print(f"    {'→ resolved (honeypot replied)' if hit else '→ no response (honeypot may not be running)'}")
        time.sleep(0.4)

    print_step("Phase 6 — Canary Trigger")
    print("    Following internal wiki link...")
    try:
        # Assuming teammate implemented canary in Phase 4
        # We simulate finding a canary token URL
        requests.post(f"{BASE_URL}/api/attacker/action", json={
            "attacker_ip": ATTACKER_IP,
            "action_type": "canary_trigger",
            "target_node_id": first_node_id,
            "detail": "Canary accessed: Internal Wiki — Credentials Page",
            "timestamp": time.time()
        })
    except Exception as e:
        pass
    
    sleep_msg(2, "Browsing internal wiki...")

    print_step("Phase 7 — Fingerprinting Attempt (Triggers Mutation)")
    print("    Attacker running OS fingerprinting...")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "port_scan",
        "target_node_id": first_node_id,
        "detail": "os fingerprint probe — TTL timing analysis",
        "timestamp": time.time()
    })

    sleep_msg(4, "Waiting for mutation to complete...")

    print_step("Phase 8 — Lateral Movement")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "lateral_move",
        "target_node_id": "node_unknown",
        "detail": "RDP attempt to 172.20.0.18",
        "timestamp": time.time()
    })

    print("\n[✔] Simulation complete. Dashboard should reflect all events.")

if __name__ == "__main__":
    main()
