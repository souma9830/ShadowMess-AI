import os
import sys
import requests
import pathlib

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
TARGET_DIR = pathlib.Path(__file__).parent.parent / "backend" / "mitre"
TARGET_PATH = TARGET_DIR / "enterprise-attack.json"

def download_mitre():
    print(f"[*] Ensuring directory exists: {TARGET_DIR}")
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Starting download from: {MITRE_URL}")
    response = requests.get(MITRE_URL, stream=True)
    response.raise_for_status()
    
    total_bytes = int(response.headers.get('content-length', 0))
    downloaded_bytes = 0
    
    with open(TARGET_PATH, 'wb') as f:
        for chunk in response.iter_content(chunk_size=1024 * 64):
            if chunk:
                f.write(chunk)
                downloaded_bytes += len(chunk)
                if total_bytes > 0:
                    percent = (downloaded_bytes / total_bytes) * 100
                    sys.stdout.write(f"\r[~] Downloading: {percent:.2f}% ({downloaded_bytes / (1024 * 1024):.2f} MB / {total_bytes / (1024 * 1024):.2f} MB)")
                else:
                    sys.stdout.write(f"\r[~] Downloading: {downloaded_bytes / (1024 * 1024):.2f} MB downloaded")
                sys.stdout.flush()
                
    print("\n[+] Download complete! Saved dataset to: " + str(TARGET_PATH))
    
    # Quick verification by reading technique counts using json
    import json
    print("[*] Verifying downloaded dataset content...")
    with open(TARGET_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    objects = data.get('objects', [])
    techniques = [obj for obj in objects if obj.get('type') == 'attack-pattern']
    print(f"[+] Validation Success: Found {len(techniques)} total MITRE ATT&CK techniques in STIX database.")

if __name__ == "__main__":
    try:
        download_mitre()
    except Exception as e:
        print(f"\n[ERROR] Failed to download MITRE ATT&CK dataset: {e}")
        sys.exit(1)
