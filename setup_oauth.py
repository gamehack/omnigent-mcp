"""Provision the single owner from a trusted local terminal, not through HTTP."""
import getpass
import json
import os
import secrets
from pathlib import Path

from argon2 import PasswordHasher
from local_oauth import CLIENT_ID, valid_redirect


def main():
    path = Path(os.getenv("MCP_OAUTH_CONFIG", "/data/oauth-owner.json"))
    if path.exists():
        raise SystemExit("Owner already configured; do not overwrite credentials while connected.")
    uri = input("Exact ChatGPT redirect URI from the MCP management page: ").strip()
    if not valid_redirect(uri):
        raise SystemExit("Invalid ChatGPT redirect URI.")
    password = getpass.getpass("New dedicated owner password (at least 16 characters): ")
    if len(password) < 16 or password != getpass.getpass("Repeat password: "):
        raise SystemExit("Password too short or does not match.")
    secret = secrets.token_urlsafe(48)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"redirect_uri": uri, "client_secret": secret,
                   "password_hash": PasswordHasher().hash(password)}, f)
        f.flush()
        os.fsync(f.fileno())
    print("Client ID:", CLIENT_ID)
    print("Client secret (save securely, never paste into chat):", secret)
    print("Restart only the MCP container to load this configuration.")


if __name__ == "__main__":
    main()
