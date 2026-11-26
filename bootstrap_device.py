"""One-time Omnigent device authorization bootstrap.

Run inside the MCP container:
  python bootstrap_device.py start
  # Open the printed verification URL and approve in Omnigent.
  python bootstrap_device.py poll

The device_code is written only to a mode-0600 pending file and is never
printed. The rotated refresh token is stored in the persistent token file.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from client import Omnigent


def _write_private(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(payload, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def _api() -> Omnigent:
    return Omnigent(
        base_url=os.environ["OMNIGENT_URL"],
        device_client_id=os.getenv("OMNIGENT_DEVICE_CLIENT_ID", "omnigent-mcp"),
        token_file=os.getenv("OMNIGENT_TOKEN_FILE", "/data/device-token.json"),
        device_client_secret=os.getenv("OMNIGENT_DEVICE_CLIENT_SECRET") or None,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Omnigent device authorization")
    parser.add_argument("action", choices=("start", "poll"))
    parser.add_argument(
        "--pending-file",
        default=os.getenv("OMNIGENT_PENDING_FILE", "/data/device-pending.json"),
    )
    args = parser.parse_args()
    pending_path = Path(args.pending_file)
    api = _api()

    if args.action == "start":
        auth = api.request_device_authorization()
        pending = {
            "device_code": auth["device_code"],
            "interval": auth["interval"],
            "expires_in": auth["expires_in"],
        }
        _write_private(pending_path, pending)
        print(
            json.dumps(
                {
                    "verification_uri_complete": auth["verification_uri_complete"],
                    "user_code": auth["user_code"],
                    "expires_in": auth["expires_in"],
                    "interval": auth["interval"],
                },
                ensure_ascii=False,
            )
        )
        return

    if not pending_path.exists():
        raise SystemExit("No pending device authorization; run the start action first")
    if pending_path.stat().st_mode & 0o077:
        raise SystemExit("Pending authorization file permissions must be 0600")
    pending = json.loads(pending_path.read_text(encoding="utf-8"))
    api.poll_device_authorization(
        device_code=pending["device_code"],
        interval=int(pending["interval"]),
        expires_in=int(pending["expires_in"]),
    )
    pending_path.unlink(missing_ok=True)
    print("Omnigent device authorization completed; refresh token stored securely.")


if __name__ == "__main__":
    main()
