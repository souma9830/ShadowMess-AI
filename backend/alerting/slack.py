import httpx
import os
from datetime import datetime

SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')

SEVERITY_EMOJI = {
    'critical': '🚨',
    'warning':  '⚠️',
    'info':     '✅',
    'canary':   '🐦',
    'mitre':    '🎯',
}

async def send_slack_alert(message: str, severity: str = 'info', fields: dict = None) -> None:
    if not SLACK_WEBHOOK_URL:
        safe = message.encode("ascii", errors="replace").decode("ascii")
        print(f"[{severity.upper()}] Slack alert (not sent): {safe}")
        return

    emoji = SEVERITY_EMOJI.get(severity, '🔔')
    
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{emoji} *ShadowMesh Alert*\n{message}"
            }
        }
    ]
    
    if fields:
        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*{k}:*\n{v}"
                }
                for k, v in fields.items()
            ][:10] # Max 10 fields per block
        })
        
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "plain_text",
                "text": f"Severity: {severity.upper()} | {datetime.now().isoformat()}"
            }
        ]
    })
    
    payload = {"blocks": blocks}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(SLACK_WEBHOOK_URL, json=payload, timeout=3.0)
            response.raise_for_status()
            print(f"Slack alert sent: {message[:60]}")
    except Exception as e:
        print(f"Slack alert failed: {e}")

async def alert_recon_detected(attacker_ip: str, scan_type: str) -> None:
    await send_slack_alert(
        message=f"Recon detected — attacker `{attacker_ip}` running `{scan_type}`\nDeception fabric activated.",
        severity='critical',
        fields={'Attacker IP': attacker_ip, 'Scan Type': scan_type}
    )

async def alert_canary_triggered(attacker_ip: str, label: str, node_id: str) -> None:
    await send_slack_alert(
        message=f"🐦 Canary triggered — attacker `{attacker_ip}` accessed `{label}` on node `{node_id}`",
        severity='canary',
        fields={'Attacker IP': attacker_ip, 'Canary': label, 'Node': node_id}
    )

async def alert_credential_stolen(attacker_ip: str, filename: str, cred_type: str) -> None:
    await send_slack_alert(
        message=f"Fake credential accessed — attacker `{attacker_ip}` downloaded `{filename}` ({cred_type})",
        severity='warning',
        fields={'Attacker IP': attacker_ip, 'File': filename, 'Type': cred_type}
    )

async def alert_topology_mutated(generation: int) -> None:
    await send_slack_alert(
        message=f"Topology reshuffled (generation {generation}) — fingerprinting attempt neutralized.",
        severity='info'
    )
