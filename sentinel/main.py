from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from sentinel.detectors import AgentRegistry
from sentinel.event_bus import threat_bus
from sentinel.proxy import router as proxy_router
from sentinel.storage import store
from sentinel.trust_graph import trust_graph


app = FastAPI(title="AgentSentinel", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(proxy_router)

blocked_tools: set[str] = set()


class AgentRegistration(BaseModel):
    name: str = Field(min_length=3)
    aliases: list[str] = Field(default_factory=list)
    role: str | None = None
    public_key: str | None = None


class BlockToolRequest(BaseModel):
    tool_name: str = Field(min_length=1)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/sessions")
async def list_sessions() -> dict[str, Any]:
    sessions = store.list_sessions()
    return {"sessions": sessions, "stats": store.global_stats()}


@app.get("/api/stats")
async def stats() -> dict[str, Any]:
    return store.global_stats()


@app.get("/api/session/{session_id}/events")
async def session_events(session_id: str) -> dict[str, Any]:
    return {"session_id": session_id, "events": store.list_events(session_id)}


@app.get("/api/graph/{session_id}")
async def graph(session_id: str) -> dict[str, Any]:
    current = trust_graph.get_graph(session_id)
    if current["nodes"]:
        return current
    return trust_graph.hydrate_from_events(session_id, store.list_events(session_id))


@app.get("/api/threats/live")
async def live_threats() -> StreamingResponse:
    async def event_stream():
        async with threat_bus.subscribe() as queue:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {json.dumps(event, default=str, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/agents/register")
async def register_agent(payload: AgentRegistration) -> dict[str, Any]:
    registry = AgentRegistry()
    record = registry.register(
        payload.name,
        payload.aliases,
        role=payload.role,
        public_key=payload.public_key,
    )
    return {"agent": record, "registered_agents": registry.all_agents()}


@app.post("/api/events/{event_id}/mark-safe")
async def mark_safe(event_id: int) -> dict[str, Any]:
    try:
        return store.mark_safe(event_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/tools/block")
async def block_tool(payload: BlockToolRequest) -> dict[str, Any]:
    blocked_tools.add(payload.tool_name)
    return {"blocked_tools": sorted(blocked_tools)}
