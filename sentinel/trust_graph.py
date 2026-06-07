from __future__ import annotations

import json
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import networkx as nx


class TrustGraphManager:
    def __init__(self) -> None:
        self._graphs: dict[str, nx.DiGraph] = defaultdict(nx.DiGraph)

    def add_event(self, event: dict[str, Any]) -> None:
        session_id = str(event["session_id"])
        graph = self._graphs[session_id]
        arguments = event.get("arguments", {})
        tool_name = str(event["tool_name"])
        agent_name = self._extract_agent(arguments)
        threat_score = int(event.get("threat_score", 0) or 0)
        payload_size = len(json.dumps(arguments, default=str).encode("utf-8"))

        self._add_node(graph, f"agent:{agent_name}", label=agent_name, type="agent", threat_score=0)
        self._add_node(graph, f"tool:{tool_name}", label=tool_name, type="tool", threat_score=threat_score)
        self._increment_edge(
            graph,
            f"agent:{agent_name}",
            f"tool:{tool_name}",
            payload_size=payload_size,
            threat_score=threat_score,
        )

        for domain in self._extract_domains(arguments):
            self._add_node(graph, f"domain:{domain}", label=domain, type="domain", threat_score=threat_score)
            self._increment_edge(
                graph,
                f"tool:{tool_name}",
                f"domain:{domain}",
                payload_size=payload_size,
                threat_score=threat_score,
            )

    def get_graph(self, session_id: str) -> dict[str, Any]:
        graph = self._graphs.get(session_id)
        if graph is None:
            return {"nodes": [], "links": []}

        nodes = [{"id": node_id, **data} for node_id, data in graph.nodes(data=True)]
        links = [{"source": source, "target": target, **data} for source, target, data in graph.edges(data=True)]
        return {"nodes": nodes, "links": links}

    def hydrate_from_events(self, session_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        graph = nx.DiGraph()
        self._graphs[session_id] = graph
        for event in events:
            self.add_event(event)
        return self.get_graph(session_id)

    @staticmethod
    def _add_node(graph: nx.DiGraph, node_id: str, **attrs: Any) -> None:
        existing = graph.nodes[node_id] if node_id in graph else {}
        threat_score = max(int(existing.get("threat_score", 0) or 0), int(attrs.get("threat_score", 0) or 0))
        graph.add_node(node_id, **{**existing, **attrs, "threat_score": threat_score})

    @staticmethod
    def _increment_edge(graph: nx.DiGraph, source: str, target: str, payload_size: int, threat_score: int) -> None:
        existing = graph.get_edge_data(source, target, default={})
        graph.add_edge(
            source,
            target,
            call_frequency=int(existing.get("call_frequency", 0)) + 1,
            payload_size=int(existing.get("payload_size", 0)) + payload_size,
            threat_score=max(int(existing.get("threat_score", 0) or 0), threat_score),
        )

    @staticmethod
    def _extract_agent(arguments: dict[str, Any]) -> str:
        for key in ("from_agent", "agent", "agent_name", "source_agent", "orchestrator"):
            value = arguments.get(key)
            if value:
                return str(value)
        return "unknown-agent"

    def _extract_domains(self, value: Any) -> set[str]:
        domains: set[str] = set()
        if isinstance(value, dict):
            for nested in value.values():
                domains |= self._extract_domains(nested)
        elif isinstance(value, list):
            for nested in value:
                domains |= self._extract_domains(nested)
        elif isinstance(value, str):
            for match in value.split():
                parsed = urlparse(match.strip("\"'(),"))
                if parsed.scheme in {"http", "https"} and parsed.netloc:
                    domains.add(parsed.netloc.lower())
        return domains


trust_graph = TrustGraphManager()
