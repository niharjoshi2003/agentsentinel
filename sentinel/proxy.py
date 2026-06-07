from __future__ import annotations

import json
import os
import uuid
from typing import Any

import httpx
from fastapi import APIRouter, Header, Request
from fastapi.responses import Response

from sentinel.detectors import DetectorPipeline
from sentinel.event_bus import threat_bus
from sentinel.storage import store
from sentinel.trust_graph import trust_graph


DEFAULT_TARGET_URL = "http://localhost:9000"

router = APIRouter()
pipeline = DetectorPipeline()


class MCPProxyInterceptor:
    def __init__(self, target_url: str | None = None) -> None:
        self.target_url = (target_url or os.getenv("MCP_TARGET_URL") or DEFAULT_TARGET_URL).rstrip("/")

    async def forward(self, request: Request, x_session_id: str | None = Header(default=None)) -> Response:
        body = await request.body()
        payload = self._decode_payload(body)
        session_id = self._session_id(payload, x_session_id)
        target_headers = self._forward_headers(request)

        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            upstream = await client.post(self.target_url, content=body, headers=target_headers)

        await self._intercept(payload, upstream.text, session_id)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    async def _intercept(self, payload: Any, raw_response: str, session_id: str) -> None:
        response_payload = self._decode_payload(raw_response.encode("utf-8"))
        requests = payload if isinstance(payload, list) else [payload]
        responses_by_id = self._responses_by_id(response_payload)

        for item in requests:
            tool_call = self._extract_tool_call(item)
            if tool_call is None:
                continue

            response_text = self._response_text_for(item, response_payload, responses_by_id, raw_response)
            context = {
                "previous_responses": store.recent_responses(session_id),
                "tool_sequence": store.tool_sequence(session_id),
                "expected_agent": self._extract_expected_agent(item),
            }
            detector_results = pipeline.run(
                tool_call["tool_name"],
                tool_call["arguments"],
                response_text,
                context,
            )
            event = store.log_event(
                session_id=session_id,
                tool_name=tool_call["tool_name"],
                arguments=tool_call["arguments"],
                raw_response=response_text,
                detector_results=detector_results,
            )
            trust_graph.add_event(event)
            if detector_results:
                await threat_bus.publish(event)

    @staticmethod
    def _decode_payload(body: bytes) -> Any:
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _forward_headers(request: Request) -> dict[str, str]:
        blocked = {"host", "content-length", "connection"}
        headers = {key: value for key, value in request.headers.items() if key.lower() not in blocked}
        headers.setdefault("content-type", "application/json")
        return headers

    @staticmethod
    def _session_id(payload: Any, header_session_id: str | None) -> str:
        if header_session_id:
            return header_session_id

        candidate = payload[0] if isinstance(payload, list) and payload else payload
        if isinstance(candidate, dict):
            params = candidate.get("params") or {}
            if isinstance(params, dict):
                for key in ("session_id", "sessionId"):
                    if params.get(key):
                        return str(params[key])
        return f"session-{uuid.uuid4().hex[:12]}"

    @staticmethod
    def _extract_tool_call(item: Any) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        method = str(item.get("method", ""))
        params = item.get("params") if isinstance(item.get("params"), dict) else {}

        tool_name = (
            params.get("name")
            or params.get("tool_name")
            or params.get("tool")
            or (method.split("/", 1)[1] if method.startswith("tool/") else None)
        )
        if method not in {"tools/call", "tool_call"} and not tool_name:
            return None
        if not tool_name:
            return None

        arguments = params.get("arguments") or params.get("args") or {}
        if not isinstance(arguments, dict):
            arguments = {"value": arguments}
        for identity_key in ("from_agent", "agent", "agent_name", "source_agent", "orchestrator"):
            if identity_key in params and identity_key not in arguments:
                arguments[identity_key] = params[identity_key]

        return {"tool_name": str(tool_name), "arguments": arguments}

    @staticmethod
    def _responses_by_id(response_payload: Any) -> dict[Any, Any]:
        if not isinstance(response_payload, list):
            return {}
        return {item.get("id"): item for item in response_payload if isinstance(item, dict) and "id" in item}

    @staticmethod
    def _response_text_for(item: Any, response_payload: Any, responses_by_id: dict[Any, Any], raw_response: str) -> str:
        selected = None
        if isinstance(item, dict) and item.get("id") in responses_by_id:
            selected = responses_by_id[item["id"]]
        elif isinstance(response_payload, dict):
            selected = response_payload
        return json.dumps(selected, ensure_ascii=False, default=str) if selected is not None else raw_response

    @staticmethod
    def _extract_expected_agent(item: Any) -> str | None:
        if not isinstance(item, dict):
            return None
        params = item.get("params") if isinstance(item.get("params"), dict) else {}
        for key in ("expected_agent", "session_agent", "registered_agent"):
            if params.get(key):
                return str(params[key])
        return None


proxy_interceptor = MCPProxyInterceptor()


@router.post("/proxy")
async def proxy_endpoint(request: Request, x_session_id: str | None = Header(default=None)) -> Response:
    return await proxy_interceptor.forward(request, x_session_id)
