"""HTTP-level tests of the real MCP SDK OAuth routes, using synthetic credentials."""
import base64
import hashlib
import importlib
import json
import re
import sqlite3
import sys
from urllib.parse import parse_qs, urlsplit

import pytest
from argon2 import PasswordHasher
from starlette.testclient import TestClient

from local_oauth import CLIENT_ID, SUBJECT

ORIGIN = "https://omnigent-mcp.example.test"
RESOURCE = ORIGIN + "/mcp"
REDIRECT = "https://chatgpt.com/connector/oauth/test-callback"
SECRET = "test-only-secret-" + "x" * 48
PASSWORD = "test-only-owner-password"
VERIFIER = "x" * 64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")


@pytest.fixture
def env(tmp_path, monkeypatch):
    config = tmp_path / "owner.json"
    config.write_text(json.dumps({
        "redirect_uri": REDIRECT, "client_secret": SECRET,
        "password_hash": PasswordHasher().hash(PASSWORD),
    }))
    config.chmod(0o600)
    db = tmp_path / "oauth.sqlite3"
    for key, value in {
        "MCP_AUTH_MODE": "local-oauth", "MCP_HOST": "0.0.0.0",
        "MCP_ISSUER_URL": ORIGIN, "MCP_RESOURCE_URL": RESOURCE,
        "MCP_OAUTH_DB": str(db), "MCP_OAUTH_CONFIG": str(config),
        "OMNIGENT_URL": "http://127.0.0.1:6767",
        "OMNIGENT_TOKEN_FILE": str(tmp_path / "device.json"),
    }.items():
        monkeypatch.setenv(key, value)
    sys.modules.pop("server", None)
    module = importlib.import_module("server")
    with TestClient(module.app, base_url=ORIGIN, follow_redirects=False) as http:
        yield http, db, module
    sys.modules.pop("server", None)


def auth_params(**overrides):
    return dict({
        "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "response_type": "code",
        "code_challenge": CHALLENGE, "code_challenge_method": "S256",
        "scope": "omnigent:read", "state": "test-state", "resource": RESOURCE,
    }, **overrides)


def start(http, **overrides):
    response = http.get("/authorize", params=auth_params(**overrides))
    assert response.status_code == 302, response.text
    assert response.headers["location"].startswith(ORIGIN + "/consent?")
    handle = parse_qs(urlsplit(response.headers["location"]).query)["request"][0]
    page = http.get(response.headers["location"])
    assert page.status_code == 200
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    return {"request": handle, "csrf": csrf, "password": PASSWORD, "decision": "approve"}


def approve(http, form):
    response = http.post("/consent", data=form, headers={"Origin": ORIGIN})
    assert response.status_code == 303, response.text
    loc = urlsplit(response.headers["location"])
    assert loc.scheme + "://" + loc.netloc + loc.path == REDIRECT
    params = parse_qs(loc.query)
    assert params["state"] == ["test-state"]
    return params["code"][0]


def exchange(http, code, **overrides):
    return http.post("/token", data=dict({
        "grant_type": "authorization_code", "client_id": CLIENT_ID, "client_secret": SECRET,
        "code": code, "code_verifier": VERIFIER, "redirect_uri": REDIRECT, "resource": RESOURCE,
    }, **overrides))


def refresh(http, token, **overrides):
    return http.post("/token", data=dict({
        "grant_type": "refresh_token", "client_id": CLIENT_ID, "client_secret": SECRET,
        "refresh_token": token, "resource": RESOURCE,
    }, **overrides))


def rpc(http, token=None, method="tools/list", params=None):
    headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"}
    if token:
        headers["Authorization"] = "Bearer " + token
    return http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, headers=headers)


def result(response):
    assert response.status_code == 200, response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        return json.loads(next(x[6:] for x in response.text.splitlines() if x.startswith("data: ")))
    return response.json()


def test_discovery_and_unauthenticated_denial(env):
    http, _, _ = env
    meta = http.get("/.well-known/oauth-authorization-server").json()
    prm = http.get("/.well-known/oauth-protected-resource/mcp").json()
    assert meta["issuer"] == prm["authorization_servers"][0]
    assert prm["resource"] == RESOURCE
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert meta["token_endpoint_auth_methods_supported"] == ["client_secret_post"]
    assert set(prm["scopes_supported"]) == {"omnigent:read", "omnigent:write"}
    assert not meta.get("registration_endpoint")
    assert http.post("/register", json={}).status_code in (404, 405)
    response = rpc(http)
    assert response.status_code == 401
    assert "resource_metadata" in response.headers.get("www-authenticate", "")


def test_authorize_rejects_wrong_client_redirect_resource_pkce(env):
    http, _, _ = env
    for overrides in [
        {"client_id": "unknown"}, {"redirect_uri": REDIRECT + "/wrong"},
        {"resource": ORIGIN + "/wrong"}, {"code_challenge_method": "plain"},
        {"code_challenge": "short"},
    ]:
        r = http.get("/authorize", params=auth_params(**overrides))
        assert not r.headers.get("location", "").startswith(ORIGIN + "/consent?")
        assert r.status_code in (302, 400, 401)


def test_consent_requires_password_origin_and_csrf(env):
    http, _, _ = env
    form = start(http)
    assert http.post("/consent", data=form).status_code == 403
    assert http.post("/consent", data=dict(form, csrf="bad"), headers={"Origin": ORIGIN}).status_code == 403
    assert http.post("/consent", data=dict(form, password="wrong"), headers={"Origin": ORIGIN}).status_code == 403
    code = approve(http, form)
    assert code
    assert http.post("/consent", data=form, headers={"Origin": ORIGIN}).status_code in (400, 403)


def test_pkce_code_exchange_and_scope_enforcement(env):
    http, db, _ = env
    code = approve(http, start(http))
    assert exchange(http, code, code_verifier="y"*64).status_code == 400
    assert exchange(http, code, redirect_uri=REDIRECT+"/wrong").status_code == 400
    assert exchange(http, code, resource=RESOURCE+"/wrong").status_code == 400
    assert exchange(http, code, client_secret="wrong").status_code == 401
    response = exchange(http, code)
    assert response.status_code == 200, response.text
    tokens = response.json()
    assert tokens["scope"] == "omnigent:read"
    assert exchange(http, code).status_code == 400
    access = tokens["access_token"]
    tools = result(rpc(http, access))["result"]["tools"]
    assert len(tools) == 15
    assert next(t for t in tools if t['name'] == 'read_api_operation')['_meta']['securitySchemes'][0]['scopes'] == ['omnigent:read']
    assert next(t for t in tools if t['name'] == 'write_api_operation')['_meta']['securitySchemes'][0]['scopes'] == ['omnigent:write']
    assert next(t for t in tools if t["name"] == "get_profile")["_meta"]["openai/profile"] is True
    profile = result(rpc(http, access, "tools/call", {"name":"get_profile","arguments":{}}))["result"]
    assert SUBJECT in json.dumps(profile)
    denied = result(rpc(http, access, "tools/call", {"name":"send_message","arguments":{"session_id":"fake","message":"test"}}))
    assert "error" in denied or denied.get("result", {}).get("isError") is True
    with sqlite3.connect(db) as c:
        rows = c.execute("SELECT id FROM tokens").fetchall()
    assert all(row[0] not in tokens.values() for row in rows)
    assert len(rows) == 2


def test_rotation_revocation_and_restart_persistence(env):
    http, db, module = env
    first = exchange(http, approve(http, start(http))).json()
    old = first["refresh_token"]
    assert refresh(http, old, resource=RESOURCE+"/wrong").status_code == 400
    assert refresh(http, old, scope="omnigent:write").status_code == 400
    r = refresh(http, old)
    assert r.status_code == 200, r.text
    second = r.json()
    assert second["refresh_token"] != old
    assert rpc(http, first["access_token"]).status_code == 401
    assert rpc(http, second["access_token"]).status_code == 200
    # Replayed refresh token revokes its entire family.
    assert refresh(http, old).status_code == 400
    assert rpc(http, second["access_token"]).status_code == 401
    third = exchange(http, approve(http, start(http))).json()
    # Recreate the SDK application against the same database (simulated restart).
    restarted = importlib.reload(module)
    with TestClient(restarted.app, base_url=ORIGIN, follow_redirects=False) as new_http:
        assert rpc(new_http, third["access_token"]).status_code == 200
        revoke = new_http.post("/revoke", data={"client_id":CLIENT_ID,"client_secret":SECRET,"token":third["refresh_token"],"token_type_hint":"refresh_token"})
        assert revoke.status_code == 200, revoke.text
        assert rpc(new_http, third["access_token"]).status_code == 401
        assert refresh(new_http, third["refresh_token"]).status_code == 400
