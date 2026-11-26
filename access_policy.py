"""Server-owned tool permissions keyed by exact Supabase subject and OAuth client."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken


@dataclass(frozen=True)
class AccessGrant:
    subject: str
    client_id: str
    scopes: frozenset[str]


class AccessPolicy:
    """Fail-closed allowlist. OAuth scopes alone never grant tool permissions."""

    def __init__(self, grants: list[AccessGrant]) -> None:
        self._grants: dict[tuple[str, str], AccessGrant] = {}
        for grant in grants:
            if not grant.subject or not grant.client_id or not grant.scopes:
                raise ValueError("access grants require subject, client_id and scopes")
            if any(
                not value or value == "*"
                for value in (grant.subject, grant.client_id, *grant.scopes)
            ):
                raise ValueError("wildcard or empty access grants are forbidden")
            key = (grant.subject, grant.client_id)
            if key in self._grants:
                raise ValueError("duplicate subject/client access grant")
            self._grants[key] = grant

    @classmethod
    def load(cls, file_path: str | Path) -> "AccessPolicy":
        data = json.loads(Path(file_path).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("grants"), list):
            raise ValueError("access policy must contain a grants array")

        grants: list[AccessGrant] = []
        for item in data["grants"]:
            if not isinstance(item, dict):
                raise ValueError("invalid access grant")
            if not isinstance(item.get("subject"), str):
                raise ValueError("grant subject must be a string")
            if not isinstance(item.get("client_id"), str):
                raise ValueError("grant client_id must be a string")
            scopes = item.get("scopes")
            if not isinstance(scopes, list) or not all(
                isinstance(scope, str) for scope in scopes
            ):
                raise ValueError("grant scopes must be an array of strings")
            grants.append(
                AccessGrant(
                    subject=item["subject"],
                    client_id=item["client_id"],
                    scopes=frozenset(scopes),
                )
            )
        return cls(grants)

    def scopes_for(self, token: AccessToken | None) -> frozenset[str]:
        if token is None or not token.subject or not token.client_id:
            raise PermissionError("verified OAuth identity is required")
        grant = self._grants.get((token.subject, token.client_id))
        if grant is None:
            raise PermissionError("this OAuth subject/client is not approved for Omnigent")
        return grant.scopes

    def require(self, scope: str) -> None:
        token = get_access_token()
        scopes = self.scopes_for(token)
        if scope not in scopes:
            raise PermissionError(f"Omnigent permission required: {scope}")
