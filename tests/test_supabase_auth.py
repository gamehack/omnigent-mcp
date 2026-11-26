import asyncio
import base64
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from supabase_auth import SupabaseJWTVerifier, SupabaseOAuthSettings


def b64url(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class TestVerifier(SupabaseJWTVerifier):
    def __init__(self, settings, jwks):
        super().__init__(settings)
        self.jwks = jwks

    async def _fetch_jwks(self):
        return self.jwks


def make_verifier():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": "test-key",
        "use": "sig",
        "alg": "RS256",
        "n": b64url(public.n),
        "e": b64url(public.e),
    }
    settings = SupabaseOAuthSettings(
        project_url="https://project.example.test",
        resource_url="https://omnigent-mcp.qjai.org/mcp",
    )
    return private, TestVerifier(settings, {"keys": [jwk]}), settings


def issue(private, settings, *, audience=None, role="authenticated"):
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "aud": audience or settings.resource_url,
        "sub": "user-1",
        "client_id": "chatgpt-client",
        "role": role,
        "is_anonymous": False,
        "iat": now,
        "exp": now + 3600,
        "scope": "openid profile",
    }
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "test-key"})


def test_valid_supabase_token_is_verified():
    private, verifier, settings = make_verifier()
    result = asyncio.run(verifier.verify_token(issue(private, settings)))
    assert result is not None
    assert result.subject == "user-1"
    assert result.client_id == "chatgpt-client"
    assert result.resource == settings.resource_url


def test_wrong_resource_audience_is_rejected():
    private, verifier, settings = make_verifier()
    raw = issue(private, settings, audience="https://mcp.qjai.org/mcp")
    assert asyncio.run(verifier.verify_token(raw)) is None


def test_non_authenticated_role_is_rejected():
    private, verifier, settings = make_verifier()
    raw = issue(private, settings, role="service_role")
    assert asyncio.run(verifier.verify_token(raw)) is None
