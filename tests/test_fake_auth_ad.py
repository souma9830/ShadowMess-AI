import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "docker"))

from fake_auth_test_helper import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_ldap_bind_success(client):
    resp = client.post("/ldap/bind", json={"username": "admin", "password": "test123"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resultCode"] == 0
    assert data["message"] == "Bind successful"


def test_ldap_search_users(client):
    resp = client.get("/ldap/search?filter=(objectClass=user)")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resultCode"] == 0
    assert len(data["entries"]) == 50
    entry = data["entries"][0]
    assert "dn" in entry
    assert "objectClass" in entry
    assert "attributes" in entry
    assert "objectGUID" in entry["attributes"]
    assert "whenCreated" in entry["attributes"]
    assert "whenChanged" in entry["attributes"]


def test_ldap_search_groups(client):
    resp = client.get("/ldap/search?filter=(objectClass=group)")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resultCode"] == 0
    assert len(data["entries"]) == 7


def test_ldap_search_computers(client):
    resp = client.get("/ldap/search?filter=(objectClass=computer)")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resultCode"] == 0
    assert len(data["entries"]) == 20


def test_ldap_search_domain_admins(client):
    resp = client.get("/ldap/search?filter=(memberOf=Domain Admins)")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resultCode"] == 0
    assert 2 <= len(data["entries"]) <= 3


def test_ldap_search_service_account(client):
    resp = client.get("/ldap/search?filter=(sAMAccountName=svc_backup)")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resultCode"] == 0
    assert len(data["entries"]) == 1
    assert "Backup2025!" in data["entries"][0]["attributes"]["description"]


def test_ldap_search_no_results(client):
    resp = client.get("/ldap/search?filter=(sAMAccountName=nonexistent_xyz_999)")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resultCode"] == 32
    assert data["message"] == "No such object"


def test_ldap_users_pagination(client):
    resp = client.get("/ldap/users?page=1&size=10")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 50
    assert data["page"] == 1
    assert data["size"] == 10
    assert len(data["users"]) == 10

    resp2 = client.get("/ldap/users?page=2&size=10")
    data2 = resp2.get_json()
    assert data2["page"] == 2
    assert len(data2["users"]) == 10
    assert data["users"][0]["dn"] != data2["users"][0]["dn"]


def test_ldap_users_default_pagination(client):
    resp = client.get("/ldap/users")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 50
    assert data["page"] == 1
    assert data["size"] == 25
    assert len(data["users"]) == 25


def test_ldap_groups_endpoint(client):
    resp = client.get("/ldap/groups")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resultCode"] == 0
    assert len(data["entries"]) == 7


def test_ldap_computers_endpoint(client):
    resp = client.get("/ldap/computers")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resultCode"] == 0
    assert len(data["entries"]) == 20


def test_response_headers(client):
    resp = client.get("/ldap/groups")
    assert resp.headers.get("Server") == "Microsoft-IIS/10.0"
    assert resp.headers.get("X-Powered-By") == "ASP.NET"
