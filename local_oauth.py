"""Single-owner OAuth provider. MCP SDK handles OAuth protocol endpoints."""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
    OAuthAuthorizationServerProvider, RefreshToken, TokenError, construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

SCOPES = ["omnigent:read", "omnigent:write"]
CLIENT_ID = "omnigent-chatgpt"
SUBJECT = "omnigent-owner"
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
CODE_TTL = 60
PENDING_TTL = 600
HEADERS = {
    "Cache-Control": "no-store", "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def valid_redirect(value: str) -> bool:
    # Exact URI provisioned from the ChatGPT management page. No wildcard.
    return bool(re.fullmatch(r"https://chatgpt\.com/(?:connector_platform_oauth_redirect|connector/oauth/[A-Za-z0-9_-]+)", value))


class LocalOAuth(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, issuer: str, resource: str, db: str, config: str):
        u = urlsplit(issuer)
        if u.scheme != "https" or not u.netloc or u.username or u.password or u.path or u.query or u.fragment:
            raise ValueError("issuer must be the canonical HTTPS origin without trailing slash")
        if resource != issuer + "/mcp":
            raise ValueError("resource must be issuer + /mcp")
        self.issuer, self.resource, self.db = issuer, resource, Path(db)
        self.config = None
        path = Path(config)
        if path.exists():
            if path.stat().st_mode & 0o077:
                raise RuntimeError("OAuth configuration must be mode 0600")
            self.config = json.loads(path.read_text())
            if not valid_redirect(self.config["redirect_uri"]):
                raise RuntimeError("invalid ChatGPT callback URI")
            if len(self.config["client_secret"]) < 32 or not self.config["password_hash"].startswith("$argon2id$"):
                raise RuntimeError("invalid owner configuration")
        self.generation = digest(self.config["client_secret"] + self.config["redirect_uri"]) if self.config else "disabled"
        self.db.parent.mkdir(parents=True, exist_ok=True)
        if not self.db.exists():
            fd = os.open(self.db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        if self.db.stat().st_mode & 0o077:
            raise RuntimeError("OAuth database must be mode 0600")
        with self.tx() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, payload TEXT NOT NULL, expiry INTEGER NOT NULL, gen TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS codes (id TEXT PRIMARY KEY, payload TEXT NOT NULL, expiry INTEGER NOT NULL, gen TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY, kind TEXT NOT NULL, family TEXT NOT NULL, scopes TEXT NOT NULL,
              expiry INTEGER NOT NULL, family_expiry INTEGER NOT NULL, gen TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS token_family ON tokens(family);
            CREATE TABLE IF NOT EXISTS attempts (at INTEGER NOT NULL);
            """)

    @contextmanager
    def tx(self):
        c = sqlite3.connect(self.db, timeout=5, isolation_level=None)
        c.row_factory = sqlite3.Row
        try:
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def cleanup(self, c, now):
        c.execute("DELETE FROM pending WHERE expiry <= ?", (now,))
        c.execute("DELETE FROM codes WHERE expiry <= ?", (now,))
        c.execute("DELETE FROM tokens WHERE family_expiry <= ?", (now,))
        c.execute("DELETE FROM attempts WHERE at <= ?", (now-60,))

    async def get_client(self, client_id):
        if not self.config or client_id != CLIENT_ID:
            return None
        return OAuthClientInformationFull(client_id=CLIENT_ID, client_secret=self.config["client_secret"],
            client_name="ChatGPT (owner)", redirect_uris=[self.config["redirect_uri"]],
            token_endpoint_auth_method="client_secret_post", grant_types=["authorization_code", "refresh_token"],
            response_types=["code"], scope=" ".join(SCOPES))

    async def register_client(self, client_info):
        raise NotImplementedError("Dynamic registration is disabled")

    async def authorize(self, client, params: AuthorizationParams):
        if not self.config or client.client_id != CLIENT_ID or str(params.redirect_uri) != self.config["redirect_uri"]:
            raise AuthorizeError("unauthorized_client")
        if params.resource != self.resource:
            raise AuthorizeError("invalid_target")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge):
            raise AuthorizeError("invalid_request", "S256 PKCE required")
        scopes = params.scopes or SCOPES
        if not set(scopes).issubset(SCOPES):
            raise AuthorizeError("invalid_scope")
        params = params.model_copy(update={"scopes": scopes})
        handle = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.tx() as c:
            self.cleanup(c, now)
            if c.execute("SELECT count(*) FROM pending").fetchone()[0] >= 100:
                raise AuthorizeError("temporarily_unavailable")
            c.execute("INSERT INTO pending VALUES (?,?,?,?)",
                (digest(handle), params.model_dump_json(), now+PENDING_TTL, self.generation))
        return self.issuer + "/consent?request=" + handle

    def pending(self, c, handle):
        row = c.execute("SELECT * FROM pending WHERE id=? AND gen=? AND expiry>?",
            (digest(handle), self.generation, int(time.time()))).fetchone()
        return AuthorizationParams.model_validate_json(row["payload"]) if row else None

    async def consent(self, request: Request):
        if not self.config:
            return HTMLResponse("Owner setup required.", 503, headers=HEADERS)
        if request.method == "GET":
            handle = request.query_params.get("request", "")
            with self.tx() as c:
                params = self.pending(c, handle)
            if not params:
                return HTMLResponse("Authorization request expired.", 400, headers=HEADERS)
            nonce = secrets.token_urlsafe(32)
            body = (
                '<!doctype html><html lang="en"><meta charset="utf-8"><title>Omnigent MCP</title>'
                '<h1>Authorize ChatGPT</h1><p>Allow this connection to access your Omnigent sessions.</p>'
                '<p>Requested permissions: ' + html.escape(", ".join(params.scopes or [])) + '</p>'
                '<form method="post" action="/consent">'
                '<input type="hidden" name="request" value="' + html.escape(handle, quote=True) + '">'
                '<input type="hidden" name="csrf" value="' + nonce + '">'
                '<label>Owner password <input type="password" name="password" autocomplete="current-password" required></label>'
                '<button name="decision" value="approve">Authorize</button>'
                '<button name="decision" value="deny" formnovalidate>Cancel</button></form></html>'
            )
            response = HTMLResponse(body, headers=HEADERS)
            response.set_cookie("oauth_csrf", nonce, max_age=PENDING_TTL, secure=True, httponly=True, samesite="strict", path="/consent")
            return response
        if request.headers.get("origin") != self.issuer:
            return HTMLResponse("Invalid request origin.", 403, headers=HEADERS)
        form = await request.form()
        handle, nonce = str(form.get("request", "")), str(form.get("csrf", ""))
        cookie = request.cookies.get("oauth_csrf", "")
        if not nonce or not cookie or not secrets.compare_digest(nonce.encode(), cookie.encode()):
            return HTMLResponse("Invalid authorization request.", 403, headers=HEADERS)
        decision = form.get("decision")
        now = int(time.time())
        if decision not in ("approve", "deny"):
            return HTMLResponse("Invalid decision.", 400, headers=HEADERS)
        with self.tx() as c:
            self.cleanup(c, now)
            params = self.pending(c, handle)
            if not params:
                return HTMLResponse("Authorization request expired.", 400, headers=HEADERS)
            if decision == "approve":
                if c.execute("SELECT count(*) FROM attempts").fetchone()[0] >= 5:
                    return HTMLResponse("Too many attempts. Try again later.", 429, headers=HEADERS)
                c.execute("INSERT INTO attempts VALUES (?)", (now,))
        if decision == "approve":
            password = str(form.get("password", ""))
            try:
                verified = len(password) <= 1024 and PasswordHasher().verify(self.config["password_hash"], password)
            except (VerificationError, InvalidHashError):
                verified = False
            if not verified:
                return HTMLResponse("Invalid owner password. Restart authorization.", 403, headers=HEADERS)
        with self.tx() as c:
            params = self.pending(c, handle)
            if not params or c.execute("DELETE FROM pending WHERE id=?", (digest(handle),)).rowcount != 1:
                return HTMLResponse("Authorization request expired.", 400, headers=HEADERS)
            if decision == "deny":
                target = construct_redirect_uri(str(params.redirect_uri), error="access_denied", state=params.state)
            else:
                raw = secrets.token_urlsafe(32)
                code = AuthorizationCode(code=digest(raw), scopes=params.scopes or [], expires_at=time.time()+CODE_TTL,
                    client_id=CLIENT_ID, code_challenge=params.code_challenge, redirect_uri=params.redirect_uri,
                    redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                    resource=self.resource, subject=SUBJECT)
                c.execute("INSERT INTO codes VALUES (?,?,?,?)",
                    (digest(raw), code.model_dump_json(), int(code.expires_at), self.generation))
                target = construct_redirect_uri(str(params.redirect_uri), code=raw, state=params.state)
        response = RedirectResponse(target, 303, headers=HEADERS)
        response.delete_cookie("oauth_csrf", path="/consent", secure=True, httponly=True, samesite="strict")
        return response

    async def load_authorization_code(self, client, authorization_code):
        if not self.config or client.client_id != CLIENT_ID:
            return None
        with self.tx() as c:
            row = c.execute("SELECT payload FROM codes WHERE id=? AND gen=? AND expiry>?",
                (digest(authorization_code), self.generation, time.time())).fetchone()
        if not row:
            return None
        code = AuthorizationCode.model_validate_json(row["payload"])
        return code.model_copy(update={"code": authorization_code})

    def mint(self, c, scopes, family, family_expiry):
        now = int(time.time())
        ttl = min(ACCESS_TTL, family_expiry-now)
        if ttl <= 0:
            raise TokenError("invalid_grant")
        a, r = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        for raw, kind, expiry in [(a, "access", now+ttl), (r, "refresh", family_expiry)]:
            c.execute("INSERT INTO tokens(id,kind,family,scopes,expiry,family_expiry,gen) VALUES (?,?,?,?,?,?,?)",
                (digest(raw), kind, family, json.dumps(scopes), expiry, family_expiry, self.generation))
        return OAuthToken(access_token=a, refresh_token=r, token_type="Bearer", expires_in=ttl, scope=" ".join(scopes))

    async def exchange_authorization_code(self, client, authorization_code):
        with self.tx() as c:
            now = int(time.time())
            if c.execute("DELETE FROM codes WHERE id=? AND gen=? AND expiry>?",
                (digest(authorization_code.code), self.generation, now)).rowcount != 1:
                raise TokenError("invalid_grant")
            return self.mint(c, authorization_code.scopes, secrets.token_hex(16), now+REFRESH_TTL)

    async def load_access_token(self, token):
        if not self.config:
            return None
        with self.tx() as c:
            row = c.execute("SELECT * FROM tokens WHERE id=? AND kind='access' AND used=0 AND gen=? AND expiry>?",
                (digest(token), self.generation, time.time())).fetchone()
        if row:
            return AccessToken(token=token, client_id=CLIENT_ID, scopes=json.loads(row["scopes"]),
                expires_at=row["expiry"], resource=self.resource, subject=SUBJECT, claims={"iss":self.issuer})
        return None

    async def load_refresh_token(self, client, refresh_token):
        if not self.config or client.client_id != CLIENT_ID:
            return None
        with self.tx() as c:
            row = c.execute("SELECT * FROM tokens WHERE id=? AND kind='refresh' AND gen=? AND expiry>?",
                (digest(refresh_token), self.generation, time.time())).fetchone()
            if row and row["used"]:
                c.execute("DELETE FROM tokens WHERE family=?", (row["family"],))
                return None
        if row:
            return RefreshToken(token=refresh_token, client_id=CLIENT_ID, scopes=json.loads(row["scopes"]),
                expires_at=row["expiry"], resource=self.resource, subject=SUBJECT)
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        result = None
        with self.tx() as c:
            row = c.execute("SELECT * FROM tokens WHERE id=? AND kind='refresh' AND gen=? AND expiry>?",
                (digest(refresh_token.token), self.generation, time.time())).fetchone()
            if row and row["used"]:
                c.execute("DELETE FROM tokens WHERE family=?", (row["family"],))
            elif row and set(scopes).issubset(json.loads(row["scopes"])):
                c.execute("UPDATE tokens SET used=1 WHERE family=?", (row["family"],))
                result = self.mint(c, scopes, row["family"], row["family_expiry"])
        if result is None:
            raise TokenError("invalid_grant")
        return result

    async def revoke_token(self, token):
        with self.tx() as c:
            row = c.execute("SELECT family FROM tokens WHERE id=? AND gen=?", (digest(token.token), self.generation)).fetchone()
            if row:
                c.execute("DELETE FROM tokens WHERE family=?", (row["family"],))


class OAuthRequestGuard:
    """Supplement SDK 2.3 checks: strict resource and S256, bounded request bodies.

    SDK validates the client, authorization code, redirect URI and verifier.
    """
    def __init__(self, app, resource):
        self.app, self.resource = app, resource

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] not in ("/authorize", "/token", "/consent", "/revoke"):
            return await self.app(scope, receive, send)
        path, method = scope["path"], scope["method"]
        async def reject(error, status=400):
            await JSONResponse({"error": error}, status, headers=HEADERS)(scope, receive, send)
        if method == "GET":
            raw = scope.get("query_string", b"")
            if len(raw) > 16384:
                return await reject("invalid_request")
            replay = receive
        elif method == "POST":
            headers = dict(scope["headers"])
            if headers.get(b"content-type", b"").split(b";")[0] != b"application/x-www-form-urlencoded":
                return await reject("invalid_request")
            chunks = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunks.extend(message.get("body", b""))
                if len(chunks) > 16384:
                    return await reject("invalid_request", 413)
                if not message.get("more_body"):
                    break
            raw = bytes(chunks)
            delivered = False
            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type":"http.request", "body":raw, "more_body":False}
                return await receive()
        else:
            return await self.app(scope, receive, send)
        try:
            q = parse_qs(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=32)
            if any(len(v) != 1 for v in q.values()):
                return await reject("invalid_request")
            val = lambda name: q.get(name, [""])[0]
            if path == "/authorize":
                if val("resource") != self.resource:
                    return await reject("invalid_target")
                if val("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", val("code_challenge")) or not val("redirect_uri"):
                    return await reject("invalid_request")
            if path == "/token":
                if val("grant_type") == "authorization_code":
                    if val("resource") != self.resource:
                        return await reject("invalid_target")
                    if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", val("code_verifier")):
                        return await reject("invalid_grant")
                elif val("resource") and val("resource") != self.resource:
                    return await reject("invalid_target")
        except (ValueError, UnicodeError):
            return await reject("invalid_request")
        return await self.app(scope, replay, send)
