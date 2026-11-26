from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx


class OmnigentError(RuntimeError):
    pass


class DeviceAuthorizationRequired(OmnigentError):
    pass


def identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", value):
        raise ValueError("Invalid Omnigent identifier")
    return value


class Omnigent:
    """Omnigent API client authenticated by a user-approved device grant.

    Only the rotating refresh token is persisted. Access tokens stay in memory.
    """

    DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

    def __init__(
        self,
        base_url: str,
        device_client_id: str,
        token_file: str | Path,
        device_client_secret: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base = base_url.rstrip("/")
        parsed = urlsplit(self.base)
        internal_http_hosts = {"omnigent", "omnigent-omnigent-1", "localhost", "127.0.0.1", "::1"}
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("Invalid OMNIGENT_URL")
        if parsed.scheme == "http" and parsed.hostname not in internal_http_hosts:
            raise ValueError("Use HTTPS except for the private Docker/loopback Omnigent API")
        if not device_client_id or len(device_client_id) > 100:
            raise ValueError("OMNIGENT_DEVICE_CLIENT_ID is required")
        self.device_client_id = device_client_id
        self.device_client_secret = device_client_secret
        self.token_file = Path(token_file)
        self.http = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(20, connect=5),
            follow_redirects=False,
            trust_env=False,
        )
        self._lock = threading.RLock()
        self._refresh_token: str | None = None
        self._access_token: str | None = None
        self._access_expires_at = 0.0
        self._load_refresh_token()

    def _load_refresh_token(self) -> None:
        if not self.token_file.exists():
            return
        mode = stat.S_IMODE(self.token_file.stat().st_mode)
        if mode & 0o077:
            raise OmnigentError("Omnigent token file permissions must be 0600")
        try:
            payload = json.loads(self.token_file.read_text(encoding="utf-8"))
            token = payload.get("refresh_token")
            if not isinstance(token, str) or not token:
                raise ValueError("missing refresh token")
            self._refresh_token = token
        except (OSError, ValueError, TypeError):
            raise OmnigentError("Omnigent token file is invalid") from None

    def _persist_refresh_token(self, token: str) -> None:
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"refresh_token": token}, separators=(",", ":"))
        fd, temp_name = tempfile.mkstemp(
            prefix=self.token_file.name + ".",
            suffix=".tmp",
            dir=str(self.token_file.parent),
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.token_file)
            os.chmod(self.token_file, 0o600)
            dir_fd = os.open(self.token_file.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def _device_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.device_client_secret:
            headers["X-Omnigent-Client-Secret"] = self.device_client_secret
        return headers

    def request_device_authorization(self) -> dict:
        try:
            response = self.http.post(
                self.base + "/oauth/device/authorize",
                json={"client_id": self.device_client_id},
                headers=self._device_headers(),
            )
            data = response.json()
        except (httpx.HTTPError, ValueError):
            raise OmnigentError("Could not start Omnigent device authorization") from None
        if not response.is_success:
            raise OmnigentError(
                f"Omnigent device authorization failed (HTTP {response.status_code})"
            )
        required = ("device_code", "user_code", "verification_uri_complete", "expires_in")
        if any(not data.get(key) for key in required):
            raise OmnigentError("Omnigent returned an incomplete device authorization response")
        return {
            "device_code": data["device_code"],
            "user_code": data["user_code"],
            "verification_uri_complete": data["verification_uri_complete"],
            "expires_in": int(data["expires_in"]),
            "interval": max(1, int(data.get("interval", 5))),
        }

    def poll_device_authorization(
        self, device_code: str, interval: int, expires_in: int
    ) -> None:
        if not device_code:
            raise ValueError("device_code is required")
        wait = max(1, int(interval))
        deadline = time.monotonic() + max(1, int(expires_in))
        while time.monotonic() < deadline:
            try:
                response = self.http.post(
                    self.base + "/oauth/token",
                    data={
                        "grant_type": self.DEVICE_GRANT_TYPE,
                        "device_code": device_code,
                    },
                    headers=self._device_headers(),
                )
                payload = response.json()
            except (httpx.HTTPError, ValueError):
                raise OmnigentError("Omnigent device-token polling failed") from None

            if response.is_success:
                access = payload.get("access_token")
                refresh = payload.get("refresh_token")
                expires = int(payload.get("expires_in", 0))
                if not isinstance(access, str) or not isinstance(refresh, str) or expires <= 0:
                    raise OmnigentError("Omnigent returned an incomplete device token response")
                with self._lock:
                    # Persist the rotated refresh token before accepting the access token.
                    self._persist_refresh_token(refresh)
                    self._refresh_token = refresh
                    self._access_token = access
                    self._access_expires_at = time.time() + expires
                return

            error = payload.get("error") if isinstance(payload, dict) else None
            if error == "authorization_pending":
                time.sleep(wait)
                continue
            if error == "slow_down":
                wait += 5
                time.sleep(wait)
                continue
            if error == "access_denied":
                raise DeviceAuthorizationRequired("Omnigent device authorization was denied")
            if error in ("expired_token", "invalid_grant"):
                raise DeviceAuthorizationRequired("Omnigent device code expired; start again")
            raise OmnigentError(
                f"Omnigent device authorization failed (HTTP {response.status_code})"
            )

        raise DeviceAuthorizationRequired("Omnigent device code expired; start again")

    def _refresh_locked(self) -> str:
        if not self._refresh_token:
            raise DeviceAuthorizationRequired(
                "Omnigent is not authorized; run python bootstrap_device.py start"
            )
        try:
            response = self.http.post(
                self.base + "/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self._refresh_token,
                },
                headers={"Accept": "application/json"},
            )
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            raise OmnigentError("Omnigent token refresh failed") from None

        if not response.is_success:
            error = payload.get("error") if isinstance(payload, dict) else None
            if error in ("invalid_grant", "expired_token", "revoked_token"):
                raise DeviceAuthorizationRequired(
                    "Omnigent authorization expired or was revoked; reauthorize the MCP client"
                )
            raise OmnigentError(f"Omnigent token refresh failed (HTTP {response.status_code})")

        access = payload.get("access_token")
        refresh = payload.get("refresh_token")
        expires = int(payload.get("expires_in", 0))
        if not isinstance(access, str) or not isinstance(refresh, str) or expires <= 0:
            raise OmnigentError("Omnigent returned an incomplete refresh response")

        # Refresh tokens rotate. Persist the new token before using it.
        self._persist_refresh_token(refresh)
        self._refresh_token = refresh
        self._access_token = access
        self._access_expires_at = time.time() + expires
        return access

    def _token(self) -> str:
        with self._lock:
            if self._access_token and self._access_expires_at > time.time() + 60:
                return self._access_token
            return self._refresh_locked()

    def request(self, method: str, path: str, *, params: dict | None = None, body: dict | None = None):
        token = self._token()
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        kwargs = {"params": params, "headers": headers}
        if body is not None:
            kwargs["json"] = body
        try:
            response = self.http.request(method, self.base + path, **kwargs)
            # Retry reads once after a rejected access token. Never replay writes.
            if response.status_code == 401 and method.upper() == "GET":
                with self._lock:
                    self._access_token = None
                    self._access_expires_at = 0
                    token = self._refresh_locked()
                headers["Authorization"] = "Bearer " + token
                response = self.http.request(method, self.base + path, **kwargs)
            if not response.is_success:
                raise OmnigentError(
                    f"Omnigent API returned HTTP {response.status_code}; check authorization and session state"
                )
            if not response.content:
                return {}
            return response.json()
        except httpx.HTTPError:
            raise OmnigentError(
                "Omnigent network failure; check the internal Docker network before retrying writes"
            ) from None
        except ValueError:
            raise OmnigentError("Omnigent returned invalid JSON") from None

    def session_path(self, session_id: str, suffix: str = "") -> str:
        return "/v1/sessions/" + identifier(session_id) + suffix

    def list_agents(self) -> dict:
        return self.request("GET", "/v1/agents")

    def list_hosts(self) -> dict:
        return self.request("GET", "/v1/hosts")

    def list_sessions(
        self, limit: int = 20, after: str | None = None, search_query: str | None = None
    ) -> dict:
        if not 1 <= limit <= 50:
            raise ValueError("limit must be 1–50")
        params = {
            "limit": limit,
            "sort_by": "updated_at",
            "order": "desc",
            "visibility": "all",
            "kind": "default",
        }
        if after:
            params["after"] = after
        if search_query:
            params["search_query"] = search_query
        return self.request("GET", "/v1/sessions", params=params)

    def get_session(self, session_id: str) -> dict:
        return self.request(
            "GET",
            self.session_path(session_id),
            params={"include_items": "false", "include_usage": "false"},
        )

    def history(self, session_id: str, limit: int = 50, after: str | None = None) -> dict:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be 1–100")
        params = {"limit": limit, "order": "asc"}
        if after:
            params["after"] = after
        return self.request("GET", self.session_path(session_id, "/items"), params=params)

    def child_sessions(
        self, session_id: str, limit: int = 20, after: str | None = None
    ) -> dict:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be 1–100")
        params = {"limit": limit, "order": "desc"}
        if after:
            params["after"] = after
        return self.request(
            "GET", self.session_path(session_id, "/child_sessions"), params=params
        )

    def create(self, agent_id: str, host_id: str, workspace: str, title: str) -> dict:
        if not workspace or not workspace.startswith("/") or not title or len(title) > 200:
            raise ValueError("An absolute workspace path and title (max 200 chars) are required")
        data = self.request(
            "POST",
            "/v1/sessions",
            body={
                "agent_id": identifier(agent_id),
                "host_id": identifier(host_id),
                "workspace": workspace,
                "title": title,
            },
        )
        session_id = data.get("id") or data.get("session_id")
        if not isinstance(session_id, str):
            raise OmnigentError("Omnigent did not return a session ID")
        return {"session_id": session_id, "session": data}

    def send(self, session_id: str, message: str) -> dict:
        if not isinstance(message, str) or not message.strip() or len(message) > 32000:
            raise ValueError("Message must contain 1–32000 characters")
        result = self.request(
            "POST",
            self.session_path(session_id, "/events"),
            body={
                "type": "message",
                "data": {
                    "role": "user",
                    "content": [{"type": "input_text", "text": message}],
                },
            },
        )
        return {
            "accepted": True,
            "session_id": session_id,
            "result": result,
            "note": "Accepted by Omnigent; this does not mean the task has completed",
        }

    def interrupt(self, session_id: str) -> dict:
        result = self.request(
            "POST",
            self.session_path(session_id, "/events"),
            body={"type": "interrupt"},
        )
        return {
            "session_id": session_id,
            "result": result,
            "note": "Interrupt requested; query get_session to confirm the resulting state",
        }
