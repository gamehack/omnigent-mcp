import json
import stat

import httpx
import pytest

from client import (
    DeviceAuthorizationRequired,
    Omnigent,
    OmnigentError,
    identifier,
)


def make_api(tmp_path, handler, *, secret=None, refresh_token="refresh-old"):
    token_file = tmp_path / "device-token.json"
    if refresh_token:
        token_file.write_text(json.dumps({"refresh_token": refresh_token}), encoding="utf-8")
        token_file.chmod(0o600)
    api = Omnigent(
        "https://omnigent.example.test",
        "omnigent-mcp",
        token_file,
        device_client_secret=secret,
        transport=httpx.MockTransport(handler),
    )
    return api, token_file


def test_refresh_rotates_and_get_uses_bearer(tmp_path):
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/oauth/token":
            assert request.content.decode().find("grant_type=refresh_token") >= 0
            return httpx.Response(
                200,
                json={"access_token": "access-1", "refresh_token": "refresh-new", "expires_in": 3600},
            )
        assert request.headers["authorization"] == "Bearer access-1"
        return httpx.Response(200, json={"data": [{"id": "ag_1"}]})

    api, token_file = make_api(tmp_path, handler)
    result = api.list_agents()

    assert result["data"][0]["id"] == "ag_1"
    assert json.loads(token_file.read_text())["refresh_token"] == "refresh-new"
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert len([r for r in seen if r.url.path == "/oauth/token"]) == 1


def test_device_authorization_polls_and_persists_rotated_refresh(tmp_path, monkeypatch):
    monkeypatch.setattr("client.time.sleep", lambda _: None)
    poll_count = 0
    seen_headers = []

    def handler(request):
        nonlocal poll_count
        if request.url.path == "/oauth/device/authorize":
            seen_headers.append(request.headers.get("x-omnigent-client-secret"))
            return httpx.Response(
                200,
                json={
                    "device_code": "device-secret",
                    "user_code": "ABCD-EFGH",
                    "verification_uri_complete": "https://omnigent.example.test/oauth/device?user_code=ABCD-EFGH",
                    "expires_in": 600,
                    "interval": 1,
                },
            )
        if request.url.path == "/oauth/token":
            poll_count += 1
            seen_headers.append(request.headers.get("x-omnigent-client-secret"))
            if poll_count == 1:
                return httpx.Response(400, json={"error": "authorization_pending"})
            return httpx.Response(
                200,
                json={"access_token": "device-access", "refresh_token": "device-refresh", "expires_in": 3600},
            )
        raise AssertionError(request.url.path)

    api, token_file = make_api(tmp_path, handler, secret="shared-device-secret", refresh_token=None)
    authorization = api.request_device_authorization()
    assert authorization["user_code"] == "ABCD-EFGH"
    assert authorization["verification_uri_complete"].startswith("https://")
    api.poll_device_authorization(
        authorization["device_code"],
        authorization["interval"],
        authorization["expires_in"],
    )

    assert json.loads(token_file.read_text())["refresh_token"] == "device-refresh"
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert poll_count == 2
    assert seen_headers == ["shared-device-secret"] * 3


def test_write_401_is_not_replayed(tmp_path):
    event_posts = 0

    def handler(request):
        nonlocal event_posts
        if request.url.path == "/oauth/token":
            return httpx.Response(
                200,
                json={"access_token": "access-1", "refresh_token": "refresh-new", "expires_in": 3600},
            )
        if request.url.path.endswith("/events"):
            event_posts += 1
            return httpx.Response(401, json={"detail": "expired"})
        raise AssertionError(request.url.path)

    api, _ = make_api(tmp_path, handler)
    with pytest.raises(OmnigentError):
        api.interrupt("conv_1")
    assert event_posts == 1


def test_session_paths_and_pagination(tmp_path):
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/oauth/token":
            return httpx.Response(
                200,
                json={"access_token": "access-1", "refresh_token": "refresh-new", "expires_in": 3600},
            )
        return httpx.Response(200, json={"data": [], "last_id": "conv_2", "has_more": True})

    api, _ = make_api(tmp_path, handler)
    api.history("conv_1", limit=25, after="msg_1")
    api.child_sessions("conv_1", limit=10, after="conv_child_1")
    api.list_sessions(limit=15, after="conv_2", search_query="deploy")

    history = next(r for r in seen if r.url.path == "/v1/sessions/conv_1/items")
    children = next(r for r in seen if r.url.path == "/v1/sessions/conv_1/child_sessions")
    sessions = next(r for r in seen if r.url.path == "/v1/sessions")

    assert history.url.params["after"] == "msg_1"
    assert children.url.params["after"] == "conv_child_1"
    assert sessions.url.params["sort_by"] == "updated_at"
    assert sessions.url.params["search_query"] == "deploy"


def test_validation_rejects_bad_ids_and_limits(tmp_path):
    def handler(request):
        raise AssertionError("No HTTP request should be made")

    api, _ = make_api(tmp_path, handler)
    with pytest.raises(ValueError):
        identifier("../admin")
    with pytest.raises(ValueError):
        api.list_sessions(0)
    with pytest.raises(ValueError):
        api.create("ag_1", "host_1", "relative/path", "test")
