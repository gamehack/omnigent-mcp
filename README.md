# Omnigent MCP

An independent Model Context Protocol server for controlling Omnigent through its official REST API. It runs as a separate Docker service on the Silicon Valley host; it is not an n8n workflow and does not modify the Omnigent application code.

## Architecture

ChatGPT -> Supabase OAuth-protected MCP (Streamable HTTP) -> Omnigent MCP -> Omnigent REST API -> connected Hosts and Harnesses.

The MCP service joins the existing Docker networks:
- `omnigent_omnigent_default` to reach the Omnigent API at `http://omnigent:8000`.
- `traefik_default` to receive HTTPS traffic from Traefik.

No host port is published. Traefik routes `https://omnigent-mcp.qjai.org/mcp` to container port 8787.

## MCP tools

Read-only:
- `list_agents` — list available Agents.
- `list_hosts` — list connected execution Hosts.
- `list_sessions` — list recent top-level sessions with pagination and search.
- `get_session` — inspect status and runner readiness.
- `get_history` — read paginated conversation items.
- `list_child_sessions` — list sub-agent sessions.

Actions:
- `create_session` — create a persistent session on an explicitly selected Agent and Host.
- `send_message` — send a task or follow-up instruction.
- `interrupt_session` — request cancellation of active work.

A successful send or interrupt response means Omnigent accepted the request, not that execution completed. Poll `get_session` and read `get_history` to verify the outcome. No generic shell, arbitrary HTTP, filesystem, deletion, sharing, or admin tools are exposed.

## Two independent authentication layers

### ChatGPT -> Omnigent MCP

The MCP server is a Supabase OAuth resource server:
- Supabase OAuth 2.1 is the authorization server.
- JWT signatures are verified against the project's public JWKS.
- Issuer, expiry, authenticated role, exact resource audience, subject and OAuth client ID are checked.
- The server-owned access policy grants individual tool scopes to an exact subject/client-ID pair.
- An empty access policy denies every tool call.

The resource URL must be exactly:

`https://omnigent-mcp.qjai.org/mcp`

The Supabase Custom Access Token Hook must map the ChatGPT OAuth client ID to that resource audience. Do not reuse the old `mcp.qjai.org/mcp` audience for this endpoint.

The existing consent UI is hosted at `https://oauth.qjai.org`. Supabase Auth's global Site URL must point to that UI, and the Authorization URL Path must match its deployed route. This is a project-wide Auth setting: audit other sign-in, email confirmation and password-recovery redirects before changing it. Do not change it automatically.

### Omnigent MCP -> Omnigent Server

The service uses an Omnigent Device Authorization Grant, not an administrator password and not a long-lived admin API token.

The running Omnigent server must have device authorization enabled with `OMNIGENT_DEVICE_GRANT_ENABLED=1`. This setting is currently disabled on the existing deployment and enabling it requires an Omnigent container restart. Do not restart the production Omnigent container without explicit approval.

The device flow is:
1. The bootstrap command requests a device code.
2. The operator opens the returned verification URL in the already-authenticated Omnigent browser and approves the client.
3. The bootstrap command exchanges the approved device code for an access token and refresh token.
4. Only the rotating refresh token is persisted, in a mode-0600 file under `./data`.
5. The service refreshes access tokens automatically. If authorization is revoked or expires, the device flow must be repeated.

An optional shared device-client secret can be configured on both Omnigent and this service to restrict device authorization requests.

## Local development

Python 3.11+:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt pytest
cp .env.example .env
chmod 600 .env
```

For unauthenticated local-only Inspector testing, set `MCP_AUTH_MODE=private` and `MCP_HOST=127.0.0.1`. Private mode refuses to bind to a non-loopback address.

## Silicon Valley Docker deployment

1. Clone this repository into `/opt/omnigent-mcp`.
2. Copy `.env.example` to `.env`, set the Supabase project URL and resource URL, then chmod 600.
3. Copy `config/access-policy.example.json` to `config/access-policy.json`. Leave `grants` empty until the ChatGPT OAuth client and user subject have been approved.
4. Create the persistent data directory owned by UID/GID 10001:
   `install -d -o 10001 -g 10001 -m 0700 data`.
5. Validate and build:
   `docker compose -f compose.yaml config`
   `docker compose -f compose.yaml build`
6. Start the independent MCP container:
   `docker compose -f compose.yaml up -d`
7. Verify `docker compose ps`, `/health`, Traefik routing and the protected-resource metadata endpoint.
8. After the Omnigent device grant is enabled, run:
   `docker compose exec omnigent-mcp python bootstrap_device.py start`
   Open the returned verification URL and approve it in Omnigent, then run:
   `docker compose exec omnigent-mcp python bootstrap_device.py poll`
9. Complete the Supabase OAuth client-to-resource mapping and add the exact subject/client ID to `config/access-policy.json` with only the required scopes:
   - `agents:read`
   - `hosts:read`
   - `sessions:read`
   - `sessions:write`
   - `sessions:cancel`
10. Restart only the MCP container after access-policy changes.

## Environment variables

See `.env.example`. Secrets and runtime state must never be committed. The Docker image excludes `.env`, `data/` and the production access-policy file.

## Security properties

- Non-root container, read-only root filesystem, no Linux capabilities, no-new-privileges.
- No host port publishing; only Traefik reaches port 8787.
- Dedicated Docker networks; Omnigent API traffic stays inside Docker.
- Supabase JWT signature and exact resource-audience verification.
- Exact subject/client-ID allowlist; no wildcard grants.
- Separate read and write scopes.
- Device refresh token stored only in a mode-0600 persistent file.
- No arbitrary command execution or generic HTTP tool.

## Current validation status

- REST client, JWT verifier and access policy have unit tests.
- GitHub Actions checks Python 3.11 and 3.12, imports the MCP server, and runs tests.
- Live Omnigent device authorization, Supabase production consent, public DNS/TLS, and ChatGPT end-to-end connection are deployment-stage checks and are not claimed complete until verified.

## References

- Omnigent Programmatic Usage: https://omnigent.ai/docs/programmatic
- Omnigent v0.23.0 source: https://github.com/omnigent-ai/omnigent/tree/v0.23.0
- Supabase OAuth Server: https://supabase.com/docs/guides/auth/oauth-server
- OpenAI MCP server guide: https://developers.openai.com/plugins/build/mcp-server
