# Task 12.1A — Fake Active Directory Data Generator

## Architecture

```
FakeActiveDirectory(domain_name="corp.internal")
├── __init__()  →  auto-generates all objects
├── self.users      = generate_users(50)
├── self.computers  = generate_computers(20)
└── self.groups     = generate_groups()
```

The class uses a seeded `random.Random` instance derived from the domain name, ensuring deterministic output across instantiations with the same domain.

## Object Model

### Users (50 default)

| Field | Description |
|-------|-------------|
| sAMAccountName | Login name (e.g., `jsmith`) |
| distinguishedName | Full LDAP DN with OU placement |
| mail | Corporate email |
| displayName | Full name |
| memberOf | List of group DNs |
| userAccountControl | UAC flags (512=normal, 66048=no-expire) |
| pwdLastSet | Windows FILETIME of last password change |
| lastLogon | Windows FILETIME of last logon |
| description | Department info or deception payload |

### Computers (20 default)

| Field | Description |
|-------|-------------|
| dNSHostName | FQDN (e.g., `CORP-WS-001.corp.internal`) |
| operatingSystem | OS name string |
| operatingSystemVersion | Version string |
| lastLogonTimestamp | Windows FILETIME |

### Groups (7 built-in)

- Domain Admins
- Enterprise Admins
- IT Staff
- Finance Users
- Engineering
- Backup Operators
- Remote Desktop Users

## User Generation Strategy

1. Names drawn from 60 first + 60 last name pools, shuffled deterministically.
2. Users distributed across 4 departments: IT Staff, Finance, Engineering, HR.
3. Special users injected at fixed indices:
   - **Index 1**: Service account `svc_backup` with password in description.
   - **Index 2**: Regular user with leaked password in description.
   - **Indices 3–9**: 2–3 randomly selected as Domain Admins.
4. sAMAccountName collision avoidance via numeric suffix.

## Group Generation Strategy

Groups are populated by scanning the generated users list for matching `memberOf` entries. This ensures referential integrity — every group member exists as a user object.

## Test Instructions

Run from project root:

```bash
pytest tests/test_fake_ad.py -v
```

Tests verify:
1. User count (50)
2. Computer count (20)
3. All 7 groups generated
4. Domain Admin count (2–3)
5. Service account `svc_backup` exists with password in description
6. Password-leak user exists (non-service-account with `Password:` in description)
7. All required fields present on users and computers
8. Servers and workstations both present
9. Group members reference valid users
10. Deterministic output (same domain → same data)
