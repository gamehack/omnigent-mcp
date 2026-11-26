import json

import pytest
from mcp.server.auth.provider import AccessToken

from access_policy import AccessPolicy


def token(subject="user-1", client_id="chatgpt-client"):
    return AccessToken(
        token="opaque",
        client_id=client_id,
        subject=subject,
        resource="https://omnigent-mcp.qjai.org/mcp",
        expires_at=9999999999,
        scopes=["openid"],
        claims={},
    )


def test_exact_subject_client_grant(tmp_path):
    path = tmp_path / "access-policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "grants": [
                    {
                        "subject": "user-1",
                        "client_id": "chatgpt-client",
                        "scopes": ["agents:read", "sessions:read"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    policy = AccessPolicy.load(path)
    assert policy.scopes_for(token()) == frozenset({"agents:read", "sessions:read"})


def test_unknown_client_is_denied(tmp_path):
    path = tmp_path / "access-policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "grants": [
                    {
                        "subject": "user-1",
                        "client_id": "chatgpt-client",
                        "scopes": ["agents:read"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    policy = AccessPolicy.load(path)
    with pytest.raises(PermissionError):
        policy.scopes_for(token(client_id="other-client"))


def test_wildcards_are_rejected():
    with pytest.raises(ValueError):
        AccessPolicy.load_from = None
        AccessPolicy(
            [
                type("Grant", (), {
                    "subject": "*",
                    "client_id": "client",
                    "scopes": frozenset({"agents:read"}),
                })()
            ]
        )
