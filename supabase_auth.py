"""Supabase OAuth resource-server JWT verification.

This module validates the access token issued by the existing Supabase OAuth
server. It is not an authorization server. Authorization to use individual MCP
tools is granted separately by the local AccessPolicy.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
import jwt
from jwt.exceptions import PyJWTError
from mcp.server.auth.provider import AccessToken


def _https_url(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("OAuth URLs must be absolute HTTPS URLs without credentials or query strings")
    return value.rstrip("/")


@dataclass(frozen=True)
class SupabaseOAuthSettings:
    project_url: str
    resource_url: str

    def __post_init__(self) -> None:
        _https_url(self.project_url)
        _https_url(self.resource_url)

    @property
    def issuer(self) -> str:
        return f"{self.project_url.rstrip('/')}/auth/v1"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"


class SupabaseJWTVerifier:
    """Verify issuer, exact resource audience, asymmetric signature and identity.

    Supabase's default authenticated audience is intentionally rejected. The
    OAuth Custom Access Token Hook must issue a token whose aud contains this
    MCP server's exact resource URL.
    """

    def __init__(self, settings: SupabaseOAuthSettings) -> None:
        self.settings = settings
        self._keys: dict[str, object] = {}
        self._refresh_after = 0.0
        self._refresh_lock = asyncio.Lock()

    async def _fetch_jwks(self) -> dict:
        async with httpx.AsyncClient(
            timeout=8, follow_redirects=False, trust_env=False
        ) as client:
            response = await client.get(self.settings.jwks_url)
            response.raise_for_status()
            return response.json()

    async def _get_key(self, kid: str, algorithm: str):
        if time.monotonic() < self._refresh_after:
            return self._keys.get(kid)

        async with self._refresh_lock:
            if time.monotonic() < self._refresh_after:
                return self._keys.get(kid)

            jwks = await self._fetch_jwks()
            raw_keys = jwks.get("keys", [])
            if not isinstance(raw_keys, list):
                raise ValueError("invalid JWKS response")

            verified: dict[str, object] = {}
            for item in raw_keys:
                if not isinstance(item, dict) or not isinstance(item.get("kid"), str):
                    continue
                if item.get("alg") not in (None, algorithm):
                    continue
                if item.get("use") not in (None, "sig"):
                    continue
                expected_kty = "RSA" if algorithm == "RS256" else "EC"
                if item.get("kty") != expected_kty:
                    continue
                verified[item["kid"]] = jwt.PyJWK.from_dict(
                    item, algorithm=algorithm
                ).key

            self._keys = verified
            self._refresh_after = time.monotonic() + 300
            return self._keys.get(kid)

    async def verify_token(self, raw_token: str) -> AccessToken | None:
        try:
            header = jwt.get_unverified_header(raw_token)
            algorithm = header.get("alg")
            kid = header.get("kid")
            if algorithm not in ("RS256", "ES256") or not isinstance(kid, str):
                return None

            key = await self._get_key(kid, algorithm)
            if key is None:
                return None

            claims = jwt.decode(
                raw_token,
                key,
                algorithms=[algorithm],
                issuer=self.settings.issuer,
                audience=self.settings.resource_url,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
                leeway=30,
            )
        except (PyJWTError, ValueError, OSError, httpx.HTTPError, TypeError):
            # Never log exception messages: they can contain untrusted claims.
            return None

        subject = claims.get("sub")
        client_id = claims.get("client_id")
        if (
            not isinstance(subject, str)
            or not subject.strip()
            or not isinstance(client_id, str)
            or not client_id.strip()
            or claims.get("is_anonymous") is True
            or claims.get("role") != "authenticated"
        ):
            return None

        raw_scopes = claims.get("scope", "")
        if isinstance(raw_scopes, str):
            scopes = raw_scopes.split()
        elif isinstance(raw_scopes, list) and all(
            isinstance(scope, str) for scope in raw_scopes
        ):
            scopes = raw_scopes
        else:
            return None

        return AccessToken(
            token=raw_token,
            client_id=client_id,
            subject=subject,
            resource=self.settings.resource_url,
            expires_at=claims["exp"],
            scopes=scopes,
            claims=claims,
        )
