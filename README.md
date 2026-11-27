# Omnigent MCP

A standalone, single-owner MCP server for connecting ChatGPT to Omnigent agents and execution hosts. It runs as an independent non-root Docker container. It does not require Supabase, a separate identity provider, an n8n workflow, or changes to the Omnigent application source.

## Architecture

ChatGPT -- HTTPS / OAuth authorization code + PKCE S256 --> Omnigent MCP -- Omnigent Device Authorization Grant / REST --> Omnigent agents and hosts.

The embedded authorization server uses MCP SDK 2.3.0 protocol endpoints. SQLite persists hashed authorization codes and opaque tokens in the private data directory. Only one pre-registered confidential OAuth client is accepted; there is no public registration endpoint.

## Tools

Read scope (`omnigent:read`): `get_profile`, `list_agents`, `list_hosts`, `list_sessions`, `get_session`, `get_history`, `list_child_sessions`.

Write scope (`omnigent:write`): `create_session`, `send_message`, `interrupt_session`.

A successful send or interrupt response means Omnigent accepted the request, not that execution completed. Poll session status and history to verify.

### Full business API catalog (v0.3.0)

The 10 core tools remain stable. Five additional tools expose a source-derived allowlist of 212 candidate HTTP operations in 11 domains, without loading hundreds of individual MCP tool definitions:

| Tool | Purpose |
|---|---|
| list_api_operations | Paginated search by domain, name, read/write mode; optional live availability check |
| describe_api_operation | Live upstream request schemas, parameters and multipart contract |
| get_api_coverage | Compare the catalog with live OpenAPI and list explicit exclusions |
| read_api_operation | Execute an allowlisted GET with read scope |
| write_api_operation | Execute an allowlisted mutation with write scope and explicit user authorization |

Domains: agents, hosts/harnesses, sessions, scheduled tasks/workflows, projects, files/resources, GitHub, MCP/skills/extensions, permissions/policies/elicitation, memory/comments/inbox, and server/settings/integrations.

Example workflow:
1. Call list_api_operations with domain "automation" and search "scheduled_task".
2. Call describe_api_operation with operation_id "create_scheduled_task".
3. After explicit user authorization, call write_api_operation with that operation ID, confirm=true and a body matching the returned schema.
4. Use read_api_operation with operation_id "get_scheduled_task" or "list_scheduled_task_runs" and the required path arguments to verify the result.

The upstream OpenAPI 3.1 document must be accessible with the authenticated Omnigent account. The catalog is pinned to v0.23.0 source; each operation must also be advertised by the running server. A route in the catalog is not a promise that the installed feature flags, runner, host, or account support it. Use get_api_coverage(live=true) to see actual advertised coverage. Unknown routes are never automatically callable.

The adapter validates path parameters and documented schemas, bounds requests/results, supports reviewed multipart uploads (2 MiB decoded total), and returns JSON, text or base64 data. GETs and writes have separate scopes; mutations are never automatically retried. Sensitive structured response fields are redacted. Some request fields manually parsed by the upstream server are described rather than schema-modeled; final validation is performed by Omnigent.

Explicit exclusions include arbitrary shell/RPC/MCP proxies, token vending, secret credential entry, sign-in bearer links, native UI/browser callbacks, OAuth callbacks, terminal and tunnel transport, and unbounded SSE/WebSocket streams. Manage credentials and provider OAuth in the native UI, and use snapshots/history rather than long-lived streams. The exclusions are documented in operations.json. This is business-management coverage, not a raw unrestricted API proxy.

## Deploy

The included Compose file is configured for the Silicon Valley installation and its existing Docker networks:
- `omnigent_omnigent_default`: REST API at `http://omnigent:8000`.
- `traefik_default`: HTTPS routing to port 8787 without publishing a host port.

For a new installation, adjust the domain, network names, Traefik labels, issuer and resource together. The issuer is the HTTPS origin (no trailing slash), and the resource is exactly issuer + `/mcp`.

```sh
cd /opt/omnigent-mcp
# Only on first installation; preserve any existing data and configuration.
cp -n .env.example .env
chmod 600 .env
sudo install -d -o 10001 -g 10001 -m 0700 data
docker compose config --quiet
docker compose build
docker compose up -d --no-deps omnigent-mcp
```

The service starts in a fail-closed unprovisioned state: discovery and health work, but no OAuth client or access token is accepted. Check:

```sh
curl -fsS https://omnigent-mcp.qjai.org/health
curl -fsS https://omnigent-mcp.qjai.org/.well-known/oauth-authorization-server
curl -fsS https://omnigent-mcp.qjai.org/.well-known/oauth-protected-resource/mcp
```

## Connect ChatGPT (one-time provisioning)

1. In ChatGPT's developer-mode app/connector creation UI, use MCP URL `https://omnigent-mcp.qjai.org/mcp` and OAuth authentication. Select the option to provide an existing OAuth client ID and secret.
2. Copy the exact callback URI shown for this MCP connection. Do not assume the legacy shared URI or use a wildcard. This server accepts either the legacy shared ChatGPT callback or the connection-specific callback, **only when explicitly provisioned**.
3. From a trusted interactive SSH terminal (not an agent, CI log, or chat), run:

   ```sh
   cd /opt/omnigent-mcp
   docker compose exec omnigent-mcp python setup_oauth.py
   docker compose restart omnigent-mcp
   ```

   Enter the exact callback URI and a new dedicated strong owner password. The script prints a generated client secret once. Store it securely and enter it directly into ChatGPT; the client ID is `omnigent-chatgpt`. Never paste the password, client secret or tokens into chat, logs, or GitHub. Client authentication uses `client_secret_post`.
4. Complete the OAuth authorization in ChatGPT and enter the dedicated owner password on the consent page served by the MCP domain. Check the requested scopes before authorizing.
5. Verify `get_profile` returns the local owner identity. Then verify Omnigent access using `list_hosts` after completing the separate device grant below.

OAuth discovery, authorization, token exchange and revocation use the SDK. Access tokens last up to one hour. Refresh tokens rotate with an absolute 30-day family lifetime. Reuse of an old refresh token revokes its family; reconnect when authorization expires or is revoked. The owner config is mode 0600 and stored in `data/oauth-owner.json`; the SQLite database is mode 0600 and stored in `data/oauth.sqlite3`. Back up both only to protected storage. The password is Argon2id-hashed; the OAuth client secret is stored in the private config to support SDK client verification. Existing Supabase tokens are not accepted.

## Omnigent API authorization (separate from ChatGPT)

Omnigent Device Authorization Grant is still required for real agent tools. If not enabled, set `OMNIGENT_DEVICE_GRANT_ENABLED=1` on the **Omnigent server** only during an approved maintenance window; restarting that service is a separate operation.

```sh
docker compose exec omnigent-mcp python bootstrap_device.py start
# Open the printed verification URL in the authenticated Omnigent browser and approve it.
docker compose exec omnigent-mcp python bootstrap_device.py poll
docker compose restart omnigent-mcp
```

The MCP server stores the rotating Omnigent refresh token in its protected data directory; it does not store the Omnigent administrator password. The incoming ChatGPT OAuth tokens are not passed to Omnigent.

## Upgrade and rollback

For an existing deployment, preserve `.env`, `data/`, and any old access-policy configuration until the new version has been validated. The refactor does not modify the Supabase project or its global Auth settings. Old Supabase environment variables can be removed after verification; they are not used by the new server. Build and recreate only the MCP container. If rolling back, restore the previous code and its configuration, then rebuild and recreate only the MCP container.

## Development and validation

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt pytest
python -m pytest -q
```

CI checks Python 3.11 and 3.12, the SDK's real HTTP OAuth endpoints, exact callbacks, PKCE, consent/CSRF, resource binding, code replay, token rotation/revocation, read/write scopes, persistence, REST client, catalog integrity, schema validation, path injection rejection, multipart, response size limits, and permission boundaries. These are automated local tests, not a claim that a live ChatGPT connector or Omnigent device grant has already been authorized.

Private mode is available for local-only development (`MCP_AUTH_MODE=private`, `MCP_HOST=127.0.0.1`). Never expose it through a proxy.

## Security

Non-root container, read-only root filesystem, no Linux capabilities, no-new-privileges, no host port publishing. Exact HTTPS issuer/resource/callback, a pre-registered confidential client, mandatory PKCE S256, explicit owner consent, CSRF protection, bounded OAuth bodies and rate-limited password checks. Token secrets remain separate from upstream Omnigent authorization. The design is intentionally single-owner, not a general-purpose multi-user identity provider.

## References

- OpenAI OAuth guidance: https://developers.openai.com/plugins/build/auth
- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk/tree/v2.3.0
- Omnigent v0.23.0: https://github.com/omnigent-ai/omnigent/tree/v0.23.0
