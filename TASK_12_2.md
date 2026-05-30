# Task 12.2 — Cloud Deception Layer

## Architecture

```
backend/deception/cloud_deception.py
├── CloudCredentialGenerator
│   ├── generate_aws_credentials()      → AKIA* key + secret
│   ├── to_aws_credentials_file()       → ~/.aws/credentials format
│   ├── generate_azure_credentials()    → Service Principal JSON
│   └── generate_gcp_service_account()  → GCP SA JSON
│
├── CloudIntelManager
│   ├── record_api_call()               → classify + alert + emit + profile
│   ├── get_events()                    → all recorded API calls
│   └── get_alerts()                    → all generated alerts
│
└── Fake AWS Data
    ├── get_sts_caller_identity()       → STS response
    └── get_iam_list_users()            → 10 IAM users

backend/api/cloud_routes.py
├── GET  /fake-aws/sts/GetCallerIdentity
├── POST /fake-aws/iam/ListUsers
└── ANY  /fake-aws/{path:path}          → catch-all
```

## Credential Formats

### AWS (~/.aws/credentials)
```ini
[default]
aws_access_key_id = AKIA<16 hex chars>
aws_secret_access_key = <40 char base64>
region = us-east-1
```

### Azure (Service Principal JSON)
```json
{
  "clientId": "uuid",
  "clientSecret": "base64-secret",
  "subscriptionId": "uuid",
  "tenantId": "uuid",
  "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
  "resourceManagerEndpointUrl": "https://management.azure.com/",
  "description": "Production deployment service principal — DO NOT SHARE"
}
```

### GCP (Service Account JSON)
```json
{
  "type": "service_account",
  "project_id": "shadowmesh-prod-<hex>",
  "private_key_id": "<40 hex>",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "client_email": "deploy-sa@<project>.iam.gserviceaccount.com",
  "client_id": "<numeric>",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

## API Endpoints

### GET /fake-aws/sts/GetCallerIdentity

Response:
```json
{
  "UserId": "AIDA...",
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:user/deploy-service"
}
```

### POST /fake-aws/iam/ListUsers

Response:
```json
{
  "Users": [
    {"UserName": "admin", "UserId": "AIDA...", "Arn": "arn:aws:iam::...", ...},
    ...
  ],
  "IsTruncated": false
}
```

Includes: admin, devops-deploy, ci-cd-runner, finance-reports, backup-service, jsmith, mwilliams, terraform-prod, monitoring-agent, security-audit

### ANY /fake-aws/{path}

Catch-all that logs method, path, headers, body, and attacker IP.

Response:
```json
{"status": "success"}
```

## Alert Flow

```
Attacker calls /fake-aws/sts/GetCallerIdentity
    ↓
CloudIntelManager.record_api_call()
    ↓
_classify() → cloud_credential_used (T1552.001, severity=high)
    ↓
├── Socket.IO: "cloud_credential_used" event
├── Alert: stored + "alert" event emitted
├── Slack: "AWS credential used by attacker (from 10.0.0.5)"
└── Profile: objectives += "Cloud Access", confidence += 0.15
```

## MITRE ATT&CK Mappings

| API Call | Technique | Name | Tactic |
|----------|-----------|------|--------|
| GetCallerIdentity | T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access |
| ListUsers | T1087.004 | Account Discovery: Cloud Account | Discovery |
| Any other | T1526 | Cloud Service Discovery | Discovery |

## Profile Enrichment

| Trigger | Objective Added | Confidence |
|---------|----------------|------------|
| GetCallerIdentity | Cloud Access | +0.15 |
| ListUsers | Cloud Enumeration | +0.15 |
| 3+ API calls | Privilege Escalation | +0.15 |

Confidence capped at 1.0. Techniques accumulate in `techniques_observed`.

## Socket.IO Events

### cloud_credential_used
```json
{
  "provider": "aws",
  "api_call": "GetCallerIdentity",
  "attacker_ip": "10.0.0.5",
  "severity": "high",
  "mitre": "T1552.001",
  "timestamp": 1717200000.0
}
```

### cloud_account_discovery
```json
{
  "provider": "aws",
  "api_call": "ListUsers",
  "attacker_ip": "10.0.0.5",
  "severity": "high",
  "mitre": "T1087.004",
  "timestamp": 1717200000.0
}
```

## Testing Instructions

```bash
pytest tests/test_cloud_deception.py -v
```

## Expected Outputs

| Test | Expected |
|------|----------|
| AWS credential generation | AKIA prefix, 20-char key, 12-digit account |
| Azure credential generation | All fields present, DO NOT SHARE in description |
| GCP service account | Valid structure, .iam.gserviceaccount.com email |
| STS endpoint | UserId, Account, Arn fields |
| IAM endpoint | 10 users including admin/devops/ci-cd/finance/backup |
| GetCallerIdentity detection | T1552.001, severity=high |
| ListUsers detection | T1087.004, severity=high |
| Catch-all detection | T1526, severity=medium |
| Profile escalation | 3+ calls → "Privilege Escalation" objective |
| Slack failure | Graceful handling, detection still returned |
