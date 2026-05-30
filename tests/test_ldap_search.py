import pytest
from backend.deception.fake_ad import FakeActiveDirectory, LDAPSearchEngine


@pytest.fixture
def engine():
    ad = FakeActiveDirectory(domain_name="corp.internal")
    return LDAPSearchEngine(ad)


def test_search_all_users(engine):
    results = engine.to_ldap_response("(objectClass=user)")
    assert len(results) == 50
    for r in results:
        assert r["objectClass"] == "user"
        assert "dn" in r
        assert "attributes" in r


def test_search_all_computers(engine):
    results = engine.to_ldap_response("(objectClass=computer)")
    assert len(results) == 20
    for r in results:
        assert r["objectClass"] == "computer"


def test_search_all_groups(engine):
    results = engine.to_ldap_response("(objectClass=group)")
    assert len(results) == 7
    group_names = [r["attributes"]["name"] for r in results]
    assert "Domain Admins" in group_names
    assert "Enterprise Admins" in group_names
    assert "Remote Desktop Users" in group_names


def test_domain_admin_lookup(engine):
    results = engine.to_ldap_response("(memberOf=Domain Admins)")
    assert 2 <= len(results) <= 3
    for r in results:
        assert r["objectClass"] == "user"
        member_of = r["attributes"]["memberOf"]
        assert any("Domain Admins" in m for m in member_of)


def test_service_account_lookup(engine):
    results = engine.to_ldap_response("(sAMAccountName=svc_backup)")
    assert len(results) == 1
    assert results[0]["attributes"]["sAMAccountName"] == "svc_backup"
    assert "Backup2025!" in results[0]["attributes"]["description"]


def test_password_description_lookup(engine):
    results = engine.to_ldap_response("(description=*Password*)")
    assert len(results) >= 2
    for r in results:
        assert "Password" in r["attributes"]["description"]


def test_wildcard_cn_search(engine):
    results = engine.to_ldap_response("(cn=*admin*)")
    assert len(results) >= 1
    for r in results:
        dn = r["dn"]
        name = r["attributes"].get("name", "")
        hostname = r["attributes"].get("dNSHostName", "")
        cn_part = dn.split(",")[0] if "CN=" in dn else hostname.split(".")[0]
        assert "admin" in cn_part.lower() or "admin" in name.lower()


def test_attribute_filtering(engine):
    results = engine.to_ldap_response("(objectClass=user)", attributes=["displayName", "mail"])
    assert len(results) == 50
    for r in results:
        attrs = r["attributes"]
        assert "displayName" in attrs
        assert "mail" in attrs
        assert "userAccountControl" not in attrs
        assert "pwdLastSet" not in attrs


def test_compound_filter(engine):
    results = engine.to_ldap_response("(&(objectClass=user)(memberOf=Domain Admins))")
    assert 2 <= len(results) <= 3
    for r in results:
        assert r["objectClass"] == "user"
        assert any("Domain Admins" in m for m in r["attributes"]["memberOf"])


def test_exact_sam_not_found(engine):
    results = engine.to_ldap_response("(sAMAccountName=nonexistent_user_xyz)")
    assert results == []


def test_search_users_helper(engine):
    results = engine.search_users()
    assert len(results) == 50


def test_search_groups_helper(engine):
    results = engine.search_groups()
    assert len(results) == 7


def test_search_computers_helper(engine):
    results = engine.search_computers()
    assert len(results) == 20


def test_enterprise_admins_lookup(engine):
    results = engine.to_ldap_response("(memberOf=Enterprise Admins)")
    assert len(results) >= 1
