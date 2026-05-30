# Task 12.1C — Fake Auth LDAP Integration

## Integration Architecture

```
docker/fake-auth/server.py (Flask, port 389)
├── Startup:
│   ├── FakeActiveDirectory("corp.internal")  →  50 users, 20 computers, 7 groups
│   └── LDAPSearchEngine(fake_ad)             →  indexed search engine
│
├── /ldap/bind    [POST]   →  Always succeeds, logs credentials
├── /ldap/search  [GET]    →  Filter-based search via LDAPSearchEngine
├── /ldap/users   [GET]    →  Paginated user enumeration
├── /ldap/groups  [GET]    →  All groups
├── /ldap/computers [GET]  →  All computers
│
├── /sso/metadata [GET]    →  SAML metadata (preserved from 4.2D)
├── /sso/login    [POST]   →  Always fails with 500ms delay
│
└── Middleware:
    ├── Server: Microsoft-IIS/10.0
    └── X-Powered-By: ASP.NET
```

All LDAP endpoints fire async callbacks to `ATTACKER_CALLBACK_URL` with action telemetry.

## LDAP Endpoints

### POST /ldap/bind

Request:
```json
{"username": "admin", "password": "P@ssw0rd"}
```

Response (always 200):
```json
{"resultCode": 0, "message": "Bind successful"}
```

Credentials are logged and reported via callback.

### GET /ldap/search

Query params:
- `filter` — LDAP filter string (default: `(objectClass=user)`)
- `attributes` — Comma-separated attribute list (optional)

Success response:
```json
{
  "resultCode": 0,
  "entries": [
    {
      "dn": "CN=John Smith,OU=IT,DC=corp,DC=internal",
      "objectClass": "user",
      "attributes": {
        "sAMAccountName": "jsmith",
        "displayName": "John Smith",
        "objectGUID": "a1b2c3d4-...",
        "whenCreated": "20210801083000.0Z",
        "whenChanged": "20220115083000.0Z",
        ...
      }
    }
  ]
}
```

No results response:
```json
{"resultCode": 32, "message": "No such object"}
```

### GET /ldap/users

Query params:
- `page` — Page number (default: 1)
- `size` — Page size (default: 25, max: 100)

Response:
```json
{
  "total": 50,
  "page": 1,
  "size": 25,
  "users": [...]
}
```

### GET /ldap/groups

Response:
```json
{
  "resultCode": 0,
  "entries": [...]
}
```

### GET /ldap/computers

Response:
```json
{
  "resultCode": 0,
  "entries": [...]
}
```

## Response Schema

Every LDAP entry includes these enrichment fields:

| Field | Source |
|-------|--------|
| `distinguishedName` | From AD object |
| `objectClass` | `user` / `computer` / `group` |
| `objectGUID` | Deterministic UUID derived from DN |
| `whenCreated` | Synthetic timestamp (2021–2024 range) |
| `whenChanged` | whenCreated + 30–330 days |

## Pagination Behavior

- `/ldap/users` supports `page` and `size` params
- Page 1 is the first page (not zero-indexed)
- Size is clamped to [1, 100]
- Response includes `total` count for client-side pagination UI
- Other endpoints return all results (groups=7, computers=20)

## Testing Instructions

```bash
pytest tests/test_fake_auth_ad.py -v
```

## Example Queries

```bash
# Bind
curl -X POST http://localhost:389/ldap/bind \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}'

# Search all users
curl "http://localhost:389/ldap/search?filter=(objectClass=user)"

# Find Domain Admins
curl "http://localhost:389/ldap/search?filter=(memberOf=Domain Admins)"

# Find service account
curl "http://localhost:389/ldap/search?filter=(sAMAccountName=svc_backup)"

# Search with attribute filter
curl "http://localhost:389/ldap/search?filter=(objectClass=user)&attributes=displayName,mail"

# Paginated users
curl "http://localhost:389/ldap/users?page=1&size=10"

# All groups
curl "http://localhost:389/ldap/groups"

# All computers
curl "http://localhost:389/ldap/computers"
```
