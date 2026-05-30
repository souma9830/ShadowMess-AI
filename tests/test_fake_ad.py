import pytest
from backend.deception.fake_ad import FakeActiveDirectory


@pytest.fixture
def ad():
    return FakeActiveDirectory(domain_name="corp.internal")


def test_user_count(ad):
    assert len(ad.users) == 50


def test_computer_count(ad):
    assert len(ad.computers) == 20


def test_groups_generated(ad):
    group_names = [g["name"] for g in ad.groups]
    expected = [
        "Domain Admins",
        "Enterprise Admins",
        "IT Staff",
        "Finance Users",
        "Engineering",
        "Backup Operators",
        "Remote Desktop Users",
    ]
    for name in expected:
        assert name in group_names, f"Missing group: {name}"


def test_domain_admin_count(ad):
    domain_admin_group = next(g for g in ad.groups if g["name"] == "Domain Admins")
    assert 2 <= len(domain_admin_group["members"]) <= 3


def test_service_account_exists(ad):
    svc_users = [u for u in ad.users if u["sAMAccountName"] == "svc_backup"]
    assert len(svc_users) == 1
    svc = svc_users[0]
    assert "Backup Service" in svc["displayName"]
    assert "Password:" in svc["description"]
    assert "Backup2025!" in svc["description"]


def test_password_in_description_user_exists(ad):
    leak_users = [
        u for u in ad.users
        if "Password:" in u.get("description", "")
        and u["sAMAccountName"] != "svc_backup"
    ]
    assert len(leak_users) >= 1
    assert "Summer2025!" in leak_users[0]["description"]


def test_user_fields_complete(ad):
    required_fields = [
        "sAMAccountName", "distinguishedName", "mail", "displayName",
        "memberOf", "userAccountControl", "pwdLastSet", "lastLogon",
        "description",
    ]
    for user in ad.users:
        for field in required_fields:
            assert field in user, f"User {user.get('sAMAccountName', '?')} missing field: {field}"


def test_computer_fields_complete(ad):
    required_fields = [
        "dNSHostName", "operatingSystem", "operatingSystemVersion",
        "lastLogonTimestamp",
    ]
    for comp in ad.computers:
        for field in required_fields:
            assert field in comp, f"Computer missing field: {field}"


def test_computers_include_servers_and_workstations(ad):
    hostnames = [c["dNSHostName"] for c in ad.computers]
    has_server = any("SRV" in h for h in hostnames)
    has_workstation = any("WS" in h for h in hostnames)
    assert has_server, "No servers found in computers"
    assert has_workstation, "No workstations found in computers"


def test_group_members_reference_real_users(ad):
    all_sams = {u["sAMAccountName"] for u in ad.users}
    for group in ad.groups:
        for member in group["members"]:
            assert member in all_sams, f"Group '{group['name']}' references unknown user: {member}"


def test_deterministic_generation():
    ad1 = FakeActiveDirectory(domain_name="corp.internal")
    ad2 = FakeActiveDirectory(domain_name="corp.internal")
    assert [u["sAMAccountName"] for u in ad1.users] == [u["sAMAccountName"] for u in ad2.users]
    assert [c["dNSHostName"] for c in ad1.computers] == [c["dNSHostName"] for c in ad2.computers]
