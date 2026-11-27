# Omnigent MCP

A standalone, single-owner MCP server for connecting ChatGPT to Omnigent agents and execution hosts. It runs as an independent non-root Docker container. It does not require Supabase, a separate identity provider, an n8n workflow, or changes to the Omnigent application source.

## Architecture

ChatGPT -- HTTPS / OAuth authorization code + PKCE S256 --> Omnigent MCP -- Omnigent Device Authorization Grant / REST --> Omnigent agents and hosts.

The embedded authorization server uses MCP SDK 2.3.0 protocol endpoints. SQLite persists hashed authorization codes and opaque tokens in the private data directory. Only one pre-registered confidential OAuth client is accepted; there is no public registration endpoint.

## Tools

Read scope (`omnigent:read`): `get_profile`, `list_agents`, `list_hosts`, `list_sessions`, `get_session`, `get_history`, `list_child_sessions`.

Write scope (`omnigent:write`): `create_session`, `send_message`, `interrupt_session`.

A successful send or interrupt response means Omnigent accepted the request, not that execution completed. Poll session status and history to verify. No generic shell, arbitrary HTTP, filesystem, deletion, sharing, or admin tools are exposed.

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

CI checks Python 3.11 and 3.12, the SDK's real HTTP OAuth endpoints, exact callbacks, PKCE, consent/CSRF, resource binding, code replay, token rotation/revocation, read/write scopes, persistence, and the REST client. These are automated local tests, not a claim that a live ChatGPT connector or Omnigent device grant has already been authorized.

Private mode is available for local-only development (`MCP_AUTH_MODE=private`, `MCP_HOST=127.0.0.1`). Never expose it through a proxy.

## Security

Non-root container, read-only root filesystem, no Linux capabilities, no-new-privileges, no host port publishing. Exact HTTPS issuer/resource/callback, a pre-registered confidential client, mandatory PKCE S256, explicit owner consent, CSRF protection, bounded OAuth bodies and rate-limited password checks. Token secrets remain separate from upstream Omnigent authorization. The design is intentionally single-owner, not a general-purpose multi-user identity provider.

## References

- OpenAI OAuth guidance: https://developers.openai.com/plugins/build/auth
- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk/tree/v2.3.0
- Omnigent v0.23.0: https://github.com/omnigent-ai/omnigent/tree/v0.23.0
