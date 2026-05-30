"""
ShadowMesh - Task 12.1A: Fake Active Directory Data Generator
=============================================================
Generates realistic Active Directory objects (users, computers, groups) for
deception purposes. These objects look like a real corporate AD environment
to lure attackers into interacting with honeypot LDAP services.

Architecture:
  FakeActiveDirectory(domain_name="corp.internal")
      __init__() auto-generates:
          self.users     = generate_users(50)
          self.computers = generate_computers(20)
          self.groups    = generate_groups()

Object model:
  - Users: sAMAccountName, distinguishedName, mail, displayName, memberOf,
           userAccountControl, pwdLastSet, lastLogon, description
  - Computers: dNSHostName, operatingSystem, operatingSystemVersion,
               lastLogonTimestamp
  - Groups: name, distinguishedName, members

Deception artifacts:
  - 2-3 Domain Admins (high-value targets for attacker enumeration)
  - 1 Service Account with password in description field
  - 1 Regular user with password leaked in description field
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import random
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

log = logging.getLogger("fake_ad")

_FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael",
    "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
    "Charles", "Lisa", "Daniel", "Nancy", "Matthew", "Betty", "Anthony",
    "Margaret", "Mark", "Sandra", "Donald", "Ashley", "Steven", "Dorothy",
    "Andrew", "Kimberly", "Paul", "Emily", "Joshua", "Donna", "Kenneth",
    "Michelle", "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa",
    "Timothy", "Deborah", "Ronald", "Stephanie", "Edward", "Rebecca",
    "Jason", "Sharon", "Jeffrey", "Laura", "Ryan", "Cynthia",
]

_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King",
    "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green",
    "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Chen", "Patel", "Kumar", "Singh", "Yamamoto",
    "Tanaka", "Muller", "Schmidt", "Weber", "Fischer",
]

_DEPARTMENTS = ["IT Staff", "Finance", "Engineering", "HR"]

_DEPARTMENT_OUS = {
    "IT Staff": "OU=IT,DC=corp,DC=internal",
    "Finance": "OU=Finance,DC=corp,DC=internal",
    "Engineering": "OU=Engineering,DC=corp,DC=internal",
    "HR": "OU=HR,DC=corp,DC=internal",
}

_WORKSTATION_OS_VERSIONS = [
    ("Windows 10 Enterprise", "10.0 (19045)"),
    ("Windows 11 Enterprise", "10.0 (22631)"),
    ("Windows 11 Enterprise", "10.0 (22621)"),
]

_SERVER_OS_VERSIONS = [
    ("Windows Server 2019 Standard", "10.0 (17763)"),
    ("Windows Server 2022 Standard", "10.0 (20348)"),
    ("Windows Server 2016 Standard", "10.0 (14393)"),
]

_SERVER_NAMES = [
    "CORP-SRV-DB01", "CORP-SRV-DB02", "CORP-SRV-WEB01", "CORP-SRV-WEB02",
    "CORP-SRV-APP01", "CORP-SRV-FILE01", "CORP-SRV-MAIL01", "CORP-SRV-DC01",
    "CORP-SRV-EXCH01", "CORP-SRV-SCCM01",
]

# UAC flags
_UAC_NORMAL = 512
_UAC_DISABLED = 514
_UAC_DONT_EXPIRE_PASSWORD = 66048


def _windows_filetime(dt: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    return int(delta.total_seconds() * 10_000_000)


class FakeActiveDirectory:

    def __init__(self, domain_name: str = "corp.internal"):
        self.domain_name = domain_name
        self._rng = random.Random(hashlib.sha256(domain_name.encode()).hexdigest())
        self.users: List[Dict] = self.generate_users(50)
        self.computers: List[Dict] = self.generate_computers(20)
        self.groups: List[Dict] = self.generate_groups()

    def _base_dn(self) -> str:
        parts = self.domain_name.split(".")
        return ",".join(f"DC={p}" for p in parts)

    def _random_timestamp(self, days_back_min: int = 1, days_back_max: int = 90) -> int:
        days = self._rng.randint(days_back_min, days_back_max)
        hours = self._rng.randint(0, 23)
        dt = datetime.now(timezone.utc) - timedelta(days=days, hours=hours)
        return _windows_filetime(dt)

    def generate_users(self, count: int = 50) -> List[Dict]:
        users: List[Dict] = []
        used_names: set = set()

        first_names = list(_FIRST_NAMES)
        last_names = list(_LAST_NAMES)
        self._rng.shuffle(first_names)
        self._rng.shuffle(last_names)

        domain_admins_indices = self._rng.sample(range(3, min(count, 10)), k=self._rng.randint(2, 3))
        svc_account_index = 1
        password_leak_index = 2

        for i in range(count):
            if i == svc_account_index:
                user = self._generate_service_account()
                users.append(user)
                continue

            if i == password_leak_index:
                user = self._generate_password_leak_user(first_names, last_names, used_names)
                users.append(user)
                continue

            first = first_names[i % len(first_names)]
            last = last_names[i % len(last_names)]

            sam = f"{first[0].lower()}{last.lower()}"
            while sam in used_names:
                sam += str(self._rng.randint(1, 99))
            used_names.add(sam)

            department = _DEPARTMENTS[i % len(_DEPARTMENTS)]
            ou = _DEPARTMENT_OUS[department]
            dn = f"CN={first} {last},{ou}"

            is_domain_admin = i in domain_admins_indices
            member_of = [f"CN={department},OU=Groups,{self._base_dn()}"]
            if is_domain_admin:
                member_of.append(f"CN=Domain Admins,CN=Users,{self._base_dn()}")

            user = {
                "sAMAccountName": sam,
                "distinguishedName": dn,
                "mail": f"{sam}@{self.domain_name}",
                "displayName": f"{first} {last}",
                "memberOf": member_of,
                "userAccountControl": _UAC_NORMAL,
                "pwdLastSet": self._random_timestamp(30, 180),
                "lastLogon": self._random_timestamp(1, 30),
                "description": f"{department} - {first} {last}",
            }
            users.append(user)

        return users

    def _generate_service_account(self) -> Dict:
        sam = "svc_backup"
        dn = f"CN=Backup Service,OU=Service Accounts,{self._base_dn()}"
        return {
            "sAMAccountName": sam,
            "distinguishedName": dn,
            "mail": f"{sam}@{self.domain_name}",
            "displayName": "Backup Service",
            "memberOf": [
                f"CN=Backup Operators,CN=Builtin,{self._base_dn()}",
                f"CN=IT Staff,OU=Groups,{self._base_dn()}",
            ],
            "userAccountControl": _UAC_DONT_EXPIRE_PASSWORD,
            "pwdLastSet": self._random_timestamp(180, 365),
            "lastLogon": self._random_timestamp(1, 7),
            "description": "Backup Service - Password: Backup2025!",
        }

    def _generate_password_leak_user(
        self, first_names: List[str], last_names: List[str], used_names: set
    ) -> Dict:
        first = first_names[self._rng.randint(0, len(first_names) - 1)]
        last = last_names[self._rng.randint(0, len(last_names) - 1)]
        sam = f"{first[0].lower()}{last.lower()}"
        while sam in used_names:
            sam += str(self._rng.randint(1, 99))
        used_names.add(sam)

        department = self._rng.choice(_DEPARTMENTS)
        ou = _DEPARTMENT_OUS[department]
        dn = f"CN={first} {last},{ou}"

        return {
            "sAMAccountName": sam,
            "distinguishedName": dn,
            "mail": f"{sam}@{self.domain_name}",
            "displayName": f"{first} {last}",
            "memberOf": [f"CN={department},OU=Groups,{self._base_dn()}"],
            "userAccountControl": _UAC_NORMAL,
            "pwdLastSet": self._random_timestamp(60, 120),
            "lastLogon": self._random_timestamp(1, 14),
            "description": f"Temp account - Password: Summer2025!",
        }

    def generate_computers(self, count: int = 20) -> List[Dict]:
        computers: List[Dict] = []
        server_count = min(len(_SERVER_NAMES), count // 3)
        workstation_count = count - server_count

        for i in range(server_count):
            name = _SERVER_NAMES[i]
            os_name, os_ver = self._rng.choice(_SERVER_OS_VERSIONS)
            computers.append({
                "dNSHostName": f"{name}.{self.domain_name}",
                "operatingSystem": os_name,
                "operatingSystemVersion": os_ver,
                "lastLogonTimestamp": self._random_timestamp(1, 14),
            })

        for i in range(1, workstation_count + 1):
            name = f"CORP-WS-{i:03d}"
            os_name, os_ver = self._rng.choice(_WORKSTATION_OS_VERSIONS)
            computers.append({
                "dNSHostName": f"{name}.{self.domain_name}",
                "operatingSystem": os_name,
                "operatingSystemVersion": os_ver,
                "lastLogonTimestamp": self._random_timestamp(1, 30),
            })

        return computers

    def generate_groups(self) -> List[Dict]:
        base_dn = self._base_dn()
        admin_users = [
            u["sAMAccountName"] for u in self.users
            if any("Domain Admins" in m for m in u["memberOf"])
        ]
        it_users = [
            u["sAMAccountName"] for u in self.users
            if any("IT Staff" in m for m in u["memberOf"])
        ]
        finance_users = [
            u["sAMAccountName"] for u in self.users
            if any("Finance" in m for m in u["memberOf"])
        ]
        engineering_users = [
            u["sAMAccountName"] for u in self.users
            if any("Engineering" in m for m in u["memberOf"])
        ]
        backup_users = [
            u["sAMAccountName"] for u in self.users
            if any("Backup Operators" in m for m in u["memberOf"])
        ]

        groups = [
            {
                "name": "Domain Admins",
                "distinguishedName": f"CN=Domain Admins,CN=Users,{base_dn}",
                "members": admin_users,
            },
            {
                "name": "Enterprise Admins",
                "distinguishedName": f"CN=Enterprise Admins,CN=Users,{base_dn}",
                "members": admin_users[:2] if len(admin_users) >= 2 else admin_users,
            },
            {
                "name": "IT Staff",
                "distinguishedName": f"CN=IT Staff,OU=Groups,{base_dn}",
                "members": it_users,
            },
            {
                "name": "Finance Users",
                "distinguishedName": f"CN=Finance Users,OU=Groups,{base_dn}",
                "members": finance_users,
            },
            {
                "name": "Engineering",
                "distinguishedName": f"CN=Engineering,OU=Groups,{base_dn}",
                "members": engineering_users,
            },
            {
                "name": "Backup Operators",
                "distinguishedName": f"CN=Backup Operators,CN=Builtin,{base_dn}",
                "members": backup_users if backup_users else ["svc_backup"],
            },
            {
                "name": "Remote Desktop Users",
                "distinguishedName": f"CN=Remote Desktop Users,CN=Builtin,{base_dn}",
                "members": self._rng.sample(
                    [u["sAMAccountName"] for u in self.users],
                    k=min(8, len(self.users)),
                ),
            },
        ]

        return groups


# ---------------------------------------------------------------------------
# LDAP Search Engine (Task 12.1B)
# ---------------------------------------------------------------------------

class LDAPSearchEngine:

    def __init__(self, ad: FakeActiveDirectory):
        self.ad = ad
        self.user_index: Dict[str, Dict] = {u["sAMAccountName"]: u for u in ad.users}
        self.group_index: Dict[str, Dict] = {g["name"]: g for g in ad.groups}
        self._computer_index: Dict[str, Dict] = {}
        for c in ad.computers:
            cn = c["dNSHostName"].split(".")[0]
            self._computer_index[cn.lower()] = c

    def to_ldap_response(
        self, search_filter: str, attributes: Optional[List[str]] = None
    ) -> List[Dict]:
        objects = self._evaluate_filter(search_filter)
        return [self._format_entry(obj, attributes) for obj in objects]

    def _evaluate_filter(self, search_filter: str) -> List[Dict]:
        search_filter = search_filter.strip()

        compound = re.match(r"^\(&(.+)\)$", search_filter)
        if compound:
            return self._evaluate_compound(compound.group(1))

        m = re.match(r"^\(([^=]+)=([^)]+)\)$", search_filter)
        if not m:
            return []

        attr = m.group(1).strip()
        value = m.group(2).strip()

        if attr == "objectClass":
            return self._filter_by_object_class(value)
        if attr == "memberOf":
            return self._filter_by_member_of(value)
        if attr == "sAMAccountName":
            return self._filter_by_sam(value)
        if attr == "cn":
            return self._filter_by_cn(value)
        if attr == "description":
            return self._filter_by_description(value)

        return self._filter_by_generic_attr(attr, value)

    def _evaluate_compound(self, inner: str) -> List[Dict]:
        parts: List[str] = []
        depth = 0
        current = ""
        for ch in inner:
            if ch == "(":
                depth += 1
                current += ch
            elif ch == ")":
                depth -= 1
                current += ch
                if depth == 0:
                    parts.append(current)
                    current = ""
            else:
                current += ch

        if not parts:
            return []

        result_sets = [set() for _ in parts]
        results_by_dn: Dict[str, Dict] = {}

        for i, part in enumerate(parts):
            objects = self._evaluate_filter(part)
            for obj in objects:
                dn = self._get_dn(obj)
                results_by_dn[dn] = obj
                result_sets[i].add(dn)

        intersection = result_sets[0]
        for s in result_sets[1:]:
            intersection &= s

        return [results_by_dn[dn] for dn in intersection]

    def _filter_by_object_class(self, value: str) -> List[Dict]:
        v = value.lower()
        if v == "user":
            return list(self.ad.users)
        if v == "computer":
            return list(self.ad.computers)
        if v == "group":
            return list(self.ad.groups)
        return []

    def _filter_by_member_of(self, value: str) -> List[Dict]:
        target = value.lower()
        results = []
        seen_sams: set = set()

        for user in self.ad.users:
            for membership in user.get("memberOf", []):
                if target in membership.lower():
                    results.append(user)
                    seen_sams.add(user["sAMAccountName"])
                    break

        for group in self.ad.groups:
            if target in group["name"].lower():
                for member_sam in group["members"]:
                    if member_sam not in seen_sams:
                        user = self.user_index.get(member_sam)
                        if user:
                            results.append(user)
                            seen_sams.add(member_sam)

        return results

    def _filter_by_sam(self, value: str) -> List[Dict]:
        if "*" in value:
            return self._wildcard_match_users("sAMAccountName", value)
        user = self.user_index.get(value)
        return [user] if user else []

    def _filter_by_cn(self, value: str) -> List[Dict]:
        results: List[Dict] = []
        is_wildcard = "*" in value

        for user in self.ad.users:
            cn = self._extract_cn(user.get("distinguishedName", ""))
            if self._matches(cn, value, is_wildcard):
                results.append(user)

        for group in self.ad.groups:
            if self._matches(group["name"], value, is_wildcard):
                results.append(group)

        for comp in self.ad.computers:
            cn = comp["dNSHostName"].split(".")[0]
            if self._matches(cn, value, is_wildcard):
                results.append(comp)

        return results

    def _filter_by_description(self, value: str) -> List[Dict]:
        is_wildcard = "*" in value
        results: List[Dict] = []
        for user in self.ad.users:
            desc = user.get("description", "")
            if self._matches(desc, value, is_wildcard):
                results.append(user)
        return results

    def _filter_by_generic_attr(self, attr: str, value: str) -> List[Dict]:
        is_wildcard = "*" in value
        results: List[Dict] = []
        for user in self.ad.users:
            if attr in user and self._matches(str(user[attr]), value, is_wildcard):
                results.append(user)
        for comp in self.ad.computers:
            if attr in comp and self._matches(str(comp[attr]), value, is_wildcard):
                results.append(comp)
        for group in self.ad.groups:
            if attr in group and self._matches(str(group[attr]), value, is_wildcard):
                results.append(group)
        return results

    def _wildcard_match_users(self, attr: str, pattern: str) -> List[Dict]:
        results = []
        for user in self.ad.users:
            val = user.get(attr, "")
            if self._matches(val, pattern, True):
                results.append(user)
        return results

    @staticmethod
    def _matches(text: str, pattern: str, is_wildcard: bool) -> bool:
        if is_wildcard:
            return fnmatch.fnmatch(text.lower(), pattern.lower())
        return text.lower() == pattern.lower()

    @staticmethod
    def _extract_cn(dn: str) -> str:
        if dn.startswith("CN="):
            return dn[3:].split(",")[0]
        return dn

    def _get_dn(self, obj: Dict) -> str:
        if "distinguishedName" in obj:
            return obj["distinguishedName"]
        if "dNSHostName" in obj:
            return obj["dNSHostName"]
        return str(id(obj))

    def _format_entry(self, obj: Dict, attributes: Optional[List[str]]) -> Dict:
        dn = self._get_dn(obj)
        object_class = self._detect_object_class(obj)

        if attributes:
            filtered_attrs = {k: v for k, v in obj.items() if k in attributes}
        else:
            filtered_attrs = dict(obj)

        return {
            "dn": dn,
            "objectClass": object_class,
            "attributes": filtered_attrs,
        }

    def _detect_object_class(self, obj: Dict) -> str:
        if "sAMAccountName" in obj:
            return "user"
        if "dNSHostName" in obj:
            return "computer"
        if "members" in obj:
            return "group"
        return "unknown"

    def search_users(self) -> List[Dict]:
        return self.to_ldap_response("(objectClass=user)")

    def search_groups(self) -> List[Dict]:
        return self.to_ldap_response("(objectClass=group)")

    def search_computers(self) -> List[Dict]:
        return self.to_ldap_response("(objectClass=computer)")
