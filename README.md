# AgentSentinel

A runtime security monitoring layer for MCP-based agentic systems. AgentSentinel
sits transparently between an MCP client and an MCP server, intercepts every
`tool_call`, runs a modular threat-detection pipeline over the request/response,
builds a per-session **trust graph**, and streams threats live to a dark-theme
security dashboard.

## Architecture

```
MCP client ──► sentinel /proxy (8001) ──► MCP server (mock on 9000)
                     │
                     ├─ detectors pipeline (prompt injection, identity spoofing,
                     │                       data exfiltration, privilege escalation)
                     ├─ SQLite session store (sentinel.db)
                     ├─ trust graph (networkx, per session)
                     └─ SSE live threat stream  ──►  React dashboard (3000)
```

## Components

| Path | Purpose |
| --- | --- |
| `sentinel/proxy.py` | Transparent JSON-RPC proxy. Forwards to `MCP_TARGET_URL`, intercepts payloads, zero-latency passthrough. |
| `sentinel/detectors.py` | Detector pipeline returning structured `{threat_type, severity, confidence, evidence}`. |
| `sentinel/trust_graph.py` | In-memory networkx graph per session (agents / tools / domains). |
| `sentinel/storage.py` | SQLite persistence + aggregate threat scoring. |
| `sentinel/event_bus.py` | In-process pub/sub powering the SSE stream. |
| `sentinel/main.py` | FastAPI app and all REST/SSE endpoints. |
| `mock_mcp_server/main.py` | Predictable MCP server for the demo. |
| `demo/attacks.py` | Simulates 4 realistic attacks (one session each). |
| `frontend/` | React 18 + Tailwind + D3 dashboard. |

## API

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/proxy` | MCP proxy endpoint (set header `X-Session-ID` to group calls). |
| GET | `/api/sessions` | All monitored sessions + aggregate stats. |
| GET | `/api/session/{id}/events` | All events for a session with detector results. |
| GET | `/api/graph/{session_id}` | Trust graph JSON for D3 force rendering. |
| GET | `/api/threats/live` | SSE stream of real-time threat events. |
| POST | `/api/agents/register` | Register a trusted agent identity. |
| POST | `/api/events/{id}/mark-safe` | Triage: mark an event safe. |
| POST | `/api/tools/block` | Triage: block a tool. |

## Run with Docker Compose (recommended)

```bash
docker compose up --build
```

Then open the dashboard at http://localhost:3000 and, in another terminal, fire
the attacks:

```bash
python demo/attacks.py
```

Services: `sentinel-backend` (8001), `frontend` (3000), `mock-mcp-server` (9000).

## Run locally (no Docker)

```bash
pip install -r requirements.txt

# terminal 1 - mock MCP server
python -m uvicorn mock_mcp_server.main:app --port 9000

# terminal 2 - sentinel backend (point it at the mock)
#   on Windows PowerShell: $env:MCP_TARGET_URL='http://127.0.0.1:9000'
MCP_TARGET_URL=http://127.0.0.1:9000 python -m uvicorn sentinel.main:app --port 8001

# terminal 3 - frontend
cd frontend && npm install && npm run dev

# terminal 4 - run the demo attacks
python demo/attacks.py
```

> If port 9000 is already in use, run the mock on another port and point
> `MCP_TARGET_URL` at it (the demo only talks to the proxy on 8001).

## Demo attacks

| Attack | Tool | Detected as |
| --- | --- | --- |
| 1. Prompt injection via web tool | `fetch_url` | PROMPT_INJECTION — HIGH (HTML comment) + **CRITICAL** (base64 block) |
| 2. Agent identity spoofing | `echo` | IDENTITY_SPOOFING — MEDIUM (unregistered `TrustedOrchestrator`) |
| 3. Privilege escalation chain | `list_files → read_file → http_request` | DATA_EXFILTRATION + PRIVILEGE_ESCALATION — HIGH |
| 4. Unicode injection | `unicode_response` | PROMPT_INJECTION — HIGH (RLO override char) |

Each attack runs in its own session (Attack 3 is a single multi-step session) so
the dashboard's session panel shows four clean, focused threat stories.

## Deploy a public demo (single URL)

For a shareable demo link, `Dockerfile.web` builds **one** image that serves the
React frontend, the API + SSE stream, and bundles the mock MCP server — so the
whole thing runs on a single port/URL. Open the link and click **“Run demo
attacks”** in the header to populate the dashboard live (no local scripts).

### Render (recommended, free)

1. Push this repo to GitHub (already at `niharjoshi2003/agentsentinel`).
2. Render Dashboard → **New → Blueprint** → connect the repo. Render reads
   [`render.yaml`](./render.yaml) and provisions the Docker web service.
3. Wait for the build; your link is `https://agentsentinel.onrender.com` (free
   instances cold-start after idle — first hit can take ~50s).

Or without the blueprint: New → **Web Service** → Docker → Dockerfile path
`./Dockerfile.web`. Render injects `PORT`; the app binds to it automatically.

### Build/run the single image anywhere

```bash
docker build -f Dockerfile.web -t agentsentinel .
docker run -p 8001:8001 agentsentinel
# open http://localhost:8001  →  click "Run demo attacks"
```

Works the same on Azure Container Apps, Fly.io, Railway, or any container host.

## Configuration files

- `agents.json` — registry of trusted agent identities (empty by default).
- `tool_permissions.json` — permitted tool-to-tool call sequences.
