#!/bin/sh
# Single-container entrypoint: run the mock MCP server in the background,
# then the AgentSentinel app (which also serves the built frontend) on $PORT.
set -e

python -m uvicorn mock_mcp_server.main:app --host 127.0.0.1 --port 9000 &

exec python -m uvicorn sentinel.main:app --host 0.0.0.0 --port "${PORT:-8001}"
