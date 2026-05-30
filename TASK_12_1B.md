# Task 12.1B — LDAP Search Engine

## Supported LDAP Filters

| Filter | Behavior |
|--------|----------|
| `(objectClass=user)` | All users |
| `(objectClass=computer)` | All computers |
| `(objectClass=group)` | All groups |
| `(memberOf=Domain Admins)` | Users with Domain Admins in memberOf |
| `(memberOf=Enterprise Admins)` | Users with Enterprise Admins in memberOf |
| `(sAMAccountName=username)` | Exact user lookup via index |
| `(cn=value)` | Match CN across users/groups/computers |
| `(cn=*admin*)` | Wildcard CN search (case-insensitive) |
| `(description=*Password*)` | Wildcard description search |
| `(&(filter1)(filter2))` | Compound AND — intersection of sub-filters |

## Search Architecture

```
LDAPSearchEngine(ad: FakeActiveDirectory)
├── Indexes (O(1) exact lookups):
│   ├── user_index:     sAMAccountName → user dict
│   ├── group_index:    group name → group dict
│   └── _computer_index: hostname CN → computer dict
│
├── to_ldap_response(search_filter, attributes=None)
│   ├── _evaluate_filter(filter)  →  raw object list
│   │   ├── _filter_by_object_class()
│   │   ├── _filter_by_member_of()
│   │   ├── _filter_by_sam()        ← uses user_index
│   │   ├── _filter_by_cn()
│   │   ├── _filter_by_description()
│   │   ├── _filter_by_generic_attr()
│   │   └── _evaluate_compound()    ← AND intersection
│   └── _format_entry(obj, attributes)  →  LDAP response dict
│
├── search_users()      → convenience wrapper
├── search_groups()     → convenience wrapper
└── search_computers()  → convenience wrapper
```

### Filter Parsing

Filters are parsed with regex. Compound `(&...)` filters are split by balanced parentheses, each sub-filter evaluated independently, then results intersected by DN.

### Wildcard Matching

Uses Python's `fnmatch` for glob-style patterns (`*admin*`). All matching is case-insensitive.

## LDAP Response Schema

Each result entry:

```json
{
  "dn": "CN=John Smith,OU=IT,DC=corp,DC=internal",
  "objectClass": "user",
  "attributes": {
    "sAMAccountName": "jsmith",
    "displayName": "John Smith",
    "mail": "jsmith@corp.internal",
    ...
  }
}
```

- `dn`: Distinguished name (or dNSHostName for computers)
- `objectClass`: `"user"` | `"computer"` | `"group"`
- `attributes`: Full attribute set, or filtered subset if `attributes` param provided

### Attribute Filtering

When `attributes=["displayName", "mail"]` is passed, only those keys appear in the `attributes` dict. The `dn` and `objectClass` envelope fields are always present.

## Test Instructions

```bash
pytest tests/test_ldap_search.py -v
```

## Expected Outputs

| Test | Expected |
|------|----------|
| `(objectClass=user)` | 50 results |
| `(objectClass=computer)` | 20 results |
| `(objectClass=group)` | 7 results |
| `(memberOf=Domain Admins)` | 2–3 results |
| `(sAMAccountName=svc_backup)` | 1 result with password in description |
| `(description=*Password*)` | ≥2 results (svc_backup + leak user) |
| `(cn=*admin*)` | ≥1 result (Domain Admins group, etc.) |
| `(&(objectClass=user)(memberOf=Domain Admins))` | 2–3 results, all users |
| Attribute filter `["displayName","mail"]` | Only those 2 keys in attributes |
