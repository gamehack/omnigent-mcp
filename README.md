# Omnigent MCP (MVP)

An independent MCP server for controlling Omnigent through its official REST API. It is a separate service, not an n8n workflow. It uses a dedicated Omnigent machine client and deliberately does not expose a generic shell, filesystem, arbitrary HTTP, deletion, sharing, or administrator tool.

## Architecture

ChatGPT -> authenticated MCP (Streamable HTTP) -> Omnigent REST API -> connected Host -> Harness.

## Included tools

Read-only:
- `list_agents` — list available agents and IDs.
- `list_hosts` — list connected hosts and IDs.
- `list_sessions` — list sessions with pagination and optional search.
- `get_session` — inspect a session and runner readiness.
- `get_history` — read paginated conversation items.
- `list_child_sessions` — list child sessions.

Actions:
- `create_session` — create a session on an explicitly selected host.
- `send_message` — send a task to an online session.
- `interrupt_session` — request cancellation of active work.

The server returns acceptance for message and interrupt requests; it does not claim that work has completed. Poll `get_session` and read `get_history` to verify progress and results.

## Omnigent authentication

1. Enable machine access in Omnigent.
2. Create a dedicated machine client ID and secret with the minimum permissions needed.
3. Verify that the machine identity can see only the intended agents, hosts, runners, and sessions.

Machine tokens support agent, host, runner, and session APIs. They cannot access scheduled-task APIs. Use a user identity if scheduled-task management is added in a future version.

## Local setup

Python 3.11+ is recommended.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
# Edit .env locally; never commit credentials.
set -a; . ./.env; set +a
python server.py
```

The example assumes Omnigent is listening on `http://127.0.0.1:6767` on the same machine. If it runs elsewhere, set `OMNIGENT_URL` to the reachable server URL. `OMNIGENT_PUBLIC_URL` controls the session links returned to ChatGPT; set it to the browser-accessible Omnigent URL when different from the API URL.

## MCP endpoint security

The default `MCP_AUTH_MODE=private` binds to loopback and has no application-level MCP authentication. It is for local development only. Do not publish it or reverse-proxy it to the internet.

For remote access, use an authenticated private tunnel supported by the deployment environment, or configure `MCP_AUTH_MODE=oauth` with an external OAuth authorization server. The OAuth mode in this project is a resource-server verifier; it is not an authorization server. The external provider must support the OAuth flow required by the MCP client and an introspection endpoint compatible with RFC 7662. Configure the issuer, resource URL, introspection credentials, allowed subject, and required scope. The resource URL must be the final HTTPS MCP endpoint. Verify OAuth discovery and callback behavior through the reverse proxy before connecting ChatGPT.

The verifier checks active status, expiry, exact resource audience, required scope, and one allowed subject. Do not expose the endpoint until unauthenticated requests and wrong audience, scope, subject, and expired tokens have been rejected. Tool annotations are descriptive hints, not an authorization boundary. Omnigent machine-token permissions remain the backend authorization boundary.

## Test

```sh
pip install pytest
python -m pytest -q
python -m compileall -q client.py server.py tests
npx @modelcontextprotocol/inspector@latest
```

For local Inspector testing, select Streamable HTTP and use `http://127.0.0.1:8787/mcp`. Verify all nine tools. Use a disposable session and a designated test host for write tests; do not test against production work.

## Current validation status

- Six mocked REST-client tests pass.
- Python source syntax compilation passes.
- MCP SDK installation, MCP handshake, OAuth discovery/introspection integration, real Omnigent API compatibility, machine-token permissions, and ChatGPT connection have not yet been validated in the deployment environment.
- No production Omnigent service has been changed or deployed by this repository commit.

## References

- Omnigent Programmatic Usage: https://omnigent.ai/docs/programmatic
- OpenAI MCP server guide: https://developers.openai.com/plugins/build/mcp-server
- OpenAI MCP authentication: https://developers.openai.com/plugins/build/auth
- OpenAI ChatGPT connector deployment: https://developers.openai.com/plugins/deploy/connect-chatgpt
