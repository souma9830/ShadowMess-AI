import urllib.request
import json
from pathlib import Path
import sys

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
TARGET_DIR = Path("backend/mitre")
TARGET_FILE = TARGET_DIR / "enterprise-attack.json"

def show_progress(block_num, block_size, total_size):
    downloaded = block_num * block_size
    if total_size > 0:
        percent = min(100, downloaded * 100 / total_size)
        sys.stdout.write(f"\rDownloading: {downloaded} bytes ({percent:.1f}%)")
    else:
        sys.stdout.write(f"\rDownloading: {downloaded} bytes")
    sys.stdout.flush()

def main():
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    print("Downloading MITRE ATT&CK Enterprise STIX JSON...")
    urllib.request.urlretrieve(URL, TARGET_FILE, reporthook=show_progress)
    print("\nDownload complete.")
    
    with open(TARGET_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    techniques = [obj for obj in data.get("objects", []) if obj.get("type") == "attack-pattern"]
    print(f"Total techniques downloaded: {len(techniques)}")

if __name__ == "__main__":
    main()
