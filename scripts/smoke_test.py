import requests
import socketio
import time
import os
import sys

print("Running ShadowMesh Smoke Test...\n")
tests_passed = 0
total_tests = 12

def check(name, success, info=""):
    global tests_passed
    if success:
        print(f"✅ {name} {info}")
        tests_passed += 1
    else:
        print(f"❌ {name} {info}")

# 1. Health
try:
    r = requests.get("http://localhost:8000/health")
    data = r.json()
    check("GET /health", data.get("status") == "ok", "(status ok)")
except Exception as e:
    check("GET /health", False, f"({e})")

# 2. Socket.IO connection
try:
    sio = socketio.Client()
    connected = False
    pong_received = False

    @sio.event
    def connect():
        global connected
        connected = True

    @sio.on('pong')
    def on_pong(data):
        global pong_received
        if data == 'test':
            pong_received = True

    sio.connect('http://localhost:8000', socketio_path='/socket.io')
    time.sleep(0.5)
    sio.emit('ping', 'test')
    time.sleep(0.5)
    
    check("Socket.IO connect & ping", connected and pong_received)
    sio.disconnect()
except Exception as e:
    check("Socket.IO connect & ping", False, f"({e})")

# 3. Detect scan (simulate ScanEvent)
try:
    r = requests.post("http://localhost:8000/api/detect/scan", json={
        "source_ip": "10.0.0.99",
        "scan_type": "port_scan",
        "ports_hit": [22, 80],
        "timestamp": time.time()
    })
    check("POST /api/detect/scan", r.status_code == 200)
except Exception as e:
    check("POST /api/detect/scan", False, f"({e})")

# 4. Topology Current
try:
    r = requests.get("http://localhost:8000/api/topology/current")
    data = r.json()
    check("GET /api/topology/current", r.status_code == 200, f"({len(data.get('nodes', []))} nodes)")
except Exception as e:
    check("GET /api/topology/current", False, f"({e})")

# 5. Attacker action
try:
    r = requests.post("http://localhost:8000/api/attacker/action", json={
        "attacker_ip": "10.0.0.99",
        "action_type": "port_scan",
        "target_node_id": "test_node",
        "detail": "test scan",
        "timestamp": time.time()
    })
    check("POST /api/attacker/action", r.status_code == 200)
except Exception as e:
    check("POST /api/attacker/action", False, f"({e})")

# 6. Attacker profile endpoint
try:
    r = requests.get("http://localhost:8000/api/attacker/profile/10.0.0.99")
    check("GET /api/attacker/profile", r.status_code in [200, 404], f"(status: {r.status_code})")
except Exception as e:
    check("GET /api/attacker/profile", False, f"({e})")

# 7. Frontend check
try:
    r = requests.get("http://localhost:5173")
    check("GET frontend :5173", r.status_code == 200)
except Exception as e:
    check("GET frontend :5173", False, f"({e})")

# 8. Neo4j check
try:
    r = requests.get("http://localhost:8000/health")
    data = r.json()
    check("Neo4j DB access", data.get("neo4j") is True)
except Exception as e:
    check("Neo4j DB access", False, f"({e})")

# 9. Docker check
try:
    import docker
    client = docker.from_env()
    client.ping()
    check("Docker daemon", True)
except Exception as e:
    check("Docker daemon", False, f"(skipped or error: {e})")

# 10. Canary endpoint
try:
    r = requests.get("http://localhost:8000/api/canary/test_token")
    check("Canary GET response", r.status_code in [403, 404])
except Exception as e:
    check("Canary GET response", False, f"({e})")

# 11. Credential endpoint
try:
    r = requests.get("http://localhost:8000/api/creds/test_node/test_cred")
    check("Fake Credential GET", r.status_code in [200, 404])
except Exception as e:
    check("Fake Credential GET", False, f"({e})")

# 12. Slack webhook
slack_url = os.getenv("SLACK_WEBHOOK_URL")
if slack_url:
    try:
        r = requests.post(slack_url, json={"text": "Smoke test message"})
        check("Slack Webhook", r.status_code == 200)
    except Exception as e:
        check("Slack Webhook", False, f"({e})")
else:
    check("Slack Webhook", True, "(skipped, SLACK_WEBHOOK_URL not set)")

print(f"\n{tests_passed}/{total_tests} checks passed.")
if tests_passed == total_tests:
    print("System ready.")
else:
    print("Some checks failed. See above.")
    sys.exit(1)
