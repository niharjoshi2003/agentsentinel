from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


SEVERITY_SCORE = {
    "LOW": 15,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 95,
}

DEFAULT_OUTBOUND_TOOLS = {"http_request", "fetch_url", "send_email", "write_file"}
DEFAULT_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "agents.json"
DEFAULT_PERMISSIONS_PATH = Path(__file__).resolve().parent.parent / "tool_permissions.json"


@dataclass(slots=True)
class DetectionResult:
    threat_type: str
    severity: str
    confidence: float
    evidence: str
    detector: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["score"] = SEVERITY_SCORE.get(self.severity, 0)
        return data


class AgentRegistry:
    """JSON-backed registry of trusted agent identities."""

    def __init__(self, path: Path | str = DEFAULT_REGISTRY_PATH) -> None:
        self.path = Path(path)
        self._agents: dict[str, dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            self._agents = {}
            return

        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self._agents = {}
            return

        records = raw.get("agents", raw if isinstance(raw, list) else [])
        agents: dict[str, dict[str, Any]] = {}
        for record in records:
            if isinstance(record, str):
                agents[record.lower()] = {"name": record, "aliases": []}
                continue
            if not isinstance(record, dict) or not record.get("name"):
                continue
            name = str(record["name"])
            aliases = [str(alias) for alias in record.get("aliases", [])]
            normalized = {name.lower(), *(alias.lower() for alias in aliases)}
            for identity in normalized:
                agents[identity] = {"name": name, "aliases": aliases, **record}
        self._agents = agents

    def register(self, name: str, aliases: Iterable[str] | None = None, **metadata: Any) -> dict[str, Any]:
        aliases = [str(alias) for alias in aliases or []]
        self.path.parent.mkdir(parents=True, exist_ok=True)

        current: list[dict[str, Any]]
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                current = raw.get("agents", []) if isinstance(raw, dict) else []
            except json.JSONDecodeError:
                current = []
        else:
            current = []

        remaining = [
            agent
            for agent in current
            if isinstance(agent, dict) and str(agent.get("name", "")).lower() != name.lower()
        ]
        record = {"name": name, "aliases": aliases, **metadata}
        remaining.append(record)
        self.path.write_text(json.dumps({"agents": remaining}, indent=2), encoding="utf-8")
        self.reload()
        return record

    def canonical_name(self, identity: str | None) -> str | None:
        if not identity:
            return None
        record = self._agents.get(identity.lower())
        return str(record["name"]) if record else None

    def is_registered(self, identity: str | None) -> bool:
        return self.canonical_name(identity) is not None

    def all_agents(self) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for record in self._agents.values():
            seen[str(record["name"]).lower()] = record
        return list(seen.values())


class BaseDetector:
    threat_type = "UNKNOWN"

    def detect(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        response_text: str,
        context: dict[str, Any] | None = None,
    ) -> list[DetectionResult]:
        raise NotImplementedError


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except TypeError:
        return str(value)


def _walk_values(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key)
            yield from _walk_values(nested)
    elif isinstance(value, list | tuple | set):
        for nested in value:
            yield from _walk_values(nested)
    elif value is not None:
        yield str(value)


def _truncate(value: str, limit: int = 240) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


class PromptInjectionDetector(BaseDetector):
    threat_type = "PROMPT_INJECTION"

    _patterns = [
        (re.compile(r"\bignore\s+(all\s+)?previous\b", re.I), "Instruction override: ignore previous"),
        (re.compile(r"\bnew\s+instructions?\b", re.I), "New instruction block"),
        (re.compile(r"\byou\s+are\s+now\b", re.I), "Role reassignment"),
        (re.compile(r"\bdisregard\b", re.I), "Instruction discard directive"),
        (re.compile(r"\bsystem\s+prompt\b", re.I), "System prompt reference"),
    ]
    _unicode_directionals = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
    _base64_token = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")
    _markdown_link = re.compile(r"\[([^\]]{0,300})\]\(([^)]{0,1000})\)", re.I)
    _html_comment = re.compile(r"<!--(.*?)-->", re.S)

    def detect(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        response_text: str,
        context: dict[str, Any] | None = None,
    ) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        text = response_text or ""

        for pattern, label in self._patterns:
            match = pattern.search(text)
            if match:
                results.append(
                    DetectionResult(
                        threat_type=self.threat_type,
                        severity="HIGH" if "system" in match.group(0).lower() else "MEDIUM",
                        confidence=0.84,
                        evidence=f"{label}: `{_truncate(match.group(0))}`",
                        detector=self.__class__.__name__,
                    )
                )

        if self._unicode_directionals.search(text):
            results.append(
                DetectionResult(
                    threat_type=self.threat_type,
                    severity="HIGH",
                    confidence=0.9,
                    evidence="Hidden unicode directionality character detected in tool response.",
                    detector=self.__class__.__name__,
                    metadata={"unicode_directionality": True},
                )
            )

        for match in self._html_comment.finditer(text):
            comment = match.group(1)
            if self._looks_like_instruction(comment):
                results.append(
                    DetectionResult(
                        threat_type=self.threat_type,
                        severity="HIGH",
                        confidence=0.88,
                        evidence=f"Instruction-like content inside HTML comment: `{_truncate(comment.strip())}`",
                        detector=self.__class__.__name__,
                        metadata={"vector": "html_comment"},
                    )
                )

        for match in self._markdown_link.finditer(text):
            label, href = match.groups()
            combined = f"{label} {href}"
            if self._looks_like_instruction(combined):
                results.append(
                    DetectionResult(
                        threat_type=self.threat_type,
                        severity="MEDIUM",
                        confidence=0.76,
                        evidence=f"Instruction-like content embedded in markdown link: `{_truncate(combined)}`",
                        detector=self.__class__.__name__,
                        metadata={"vector": "markdown_link"},
                    )
                )

        for token in self._base64_token.findall(text):
            decoded = self._decode_base64(token)
            if decoded and self._looks_like_instruction(decoded):
                results.append(
                    DetectionResult(
                        threat_type=self.threat_type,
                        severity="CRITICAL",
                        confidence=0.93,
                        evidence=f"Base64-encoded instruction block decoded to: `{_truncate(decoded)}`",
                        detector=self.__class__.__name__,
                        metadata={"vector": "base64", "encoded_sample": _truncate(token, 80)},
                    )
                )

        return _dedupe_results(results)

    def _looks_like_instruction(self, text: str) -> bool:
        return any(pattern.search(text) for pattern, _ in self._patterns)

    @staticmethod
    def _decode_base64(token: str) -> str | None:
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return None
        if not decoded:
            return None
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return None
        printable_ratio = sum(char.isprintable() or char.isspace() for char in text) / max(len(text), 1)
        return text if printable_ratio > 0.85 else None


class IdentitySpoofingDetector(BaseDetector):
    threat_type = "IDENTITY_SPOOFING"

    _claim_patterns = [
        re.compile(r"\bI\s+am\s+([A-Z][A-Za-z0-9_.:-]{2,80})", re.I),
        re.compile(r"\bas\s+the\s+([A-Za-z0-9_.:-]{3,80})", re.I),
        re.compile(r"\bacting\s+as\s+([A-Za-z0-9_.:-]{3,80})", re.I),
    ]
    _identity_keys = {
        "from_agent",
        "agent",
        "agent_id",
        "agent_name",
        "identity",
        "acting_as",
        "sender",
        "source_agent",
        "orchestrator",
    }

    def __init__(self, registry: AgentRegistry | None = None) -> None:
        self.registry = registry or AgentRegistry()

    def detect(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        response_text: str,
        context: dict[str, Any] | None = None,
    ) -> list[DetectionResult]:
        context = context or {}
        self.registry.reload()
        claims = self._extract_claims(arguments, response_text)
        expected_agent = context.get("expected_agent") or context.get("session_agent")
        results: list[DetectionResult] = []

        for claim in claims:
            identity = claim["identity"]
            canonical = self.registry.canonical_name(identity)
            if expected_agent and canonical and canonical.lower() != str(expected_agent).lower():
                results.append(
                    DetectionResult(
                        threat_type=self.threat_type,
                        severity="CRITICAL",
                        confidence=0.91,
                        evidence=f"Claimed registered identity `{identity}` does not match expected session agent `{expected_agent}`.",
                        detector=self.__class__.__name__,
                        metadata=claim,
                    )
                )
            elif not canonical:
                results.append(
                    DetectionResult(
                        threat_type=self.threat_type,
                        severity="MEDIUM",
                        confidence=0.78,
                        evidence=f"Unregistered agent identity claim `{identity}` found in {claim['source']}.",
                        detector=self.__class__.__name__,
                        metadata=claim,
                    )
                )

        return _dedupe_results(results)

    def _extract_claims(self, arguments: dict[str, Any], response_text: str) -> list[dict[str, str]]:
        claims: list[dict[str, str]] = []

        def visit(value: Any, key: str | None = None) -> None:
            if isinstance(value, dict):
                for nested_key, nested_value in value.items():
                    visit(nested_value, str(nested_key))
            elif isinstance(value, list):
                for nested_value in value:
                    visit(nested_value, key)
            elif value is not None and key and key.lower() in self._identity_keys:
                claims.append({"identity": str(value), "source": f"arguments.{key}"})

        visit(arguments)
        for text in _walk_values(arguments):
            claims.extend(self._regex_claims(text, "arguments"))
        claims.extend(self._regex_claims(response_text or "", "response"))

        unique: dict[tuple[str, str], dict[str, str]] = {}
        for claim in claims:
            identity = claim["identity"].strip().strip("\"'`.,")
            if len(identity) >= 3:
                unique[(identity.lower(), claim["source"])] = {**claim, "identity": identity}
        return list(unique.values())

    def _regex_claims(self, text: str, source: str) -> list[dict[str, str]]:
        return [{"identity": match.group(1), "source": source} for pattern in self._claim_patterns for match in pattern.finditer(text)]


class DataExfiltrationDetector(BaseDetector):
    threat_type = "DATA_EXFILTRATION"

    def __init__(self, outbound_tools: set[str] | None = None, large_payload_threshold: int = 10 * 1024) -> None:
        self.outbound_tools = outbound_tools or DEFAULT_OUTBOUND_TOOLS
        self.large_payload_threshold = large_payload_threshold

    def detect(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        response_text: str,
        context: dict[str, Any] | None = None,
    ) -> list[DetectionResult]:
        context = context or {}
        results: list[DetectionResult] = []
        serialized_args = _safe_json(arguments)
        payload_size = len(serialized_args.encode("utf-8"))

        if tool_name in self.outbound_tools and payload_size > self.large_payload_threshold:
            results.append(
                DetectionResult(
                    threat_type=self.threat_type,
                    severity="MEDIUM",
                    confidence=0.8,
                    evidence=f"Outbound `{tool_name}` call contains unusually large arguments ({payload_size} bytes).",
                    detector=self.__class__.__name__,
                    metadata={"payload_size": payload_size, "threshold": self.large_payload_threshold},
                )
            )

        if tool_name not in self.outbound_tools:
            return results

        previous_responses = [str(item) for item in context.get("previous_responses", []) if item]
        matches = self._matching_previous_content(serialized_args, previous_responses)
        for match in matches[:3]:
            results.append(
                DetectionResult(
                    threat_type=self.threat_type,
                    severity="HIGH",
                    confidence=0.87,
                    evidence=f"Outbound `{tool_name}` arguments reuse prior tool response content: `{_truncate(match)}`",
                    detector=self.__class__.__name__,
                    metadata={"payload_size": payload_size, "laundering_pattern": True},
                )
            )

        return _dedupe_results(results)

    @staticmethod
    def _matching_previous_content(serialized_args: str, previous_responses: list[str]) -> list[str]:
        normalized_args = re.sub(r"\s+", " ", serialized_args)
        matches: list[str] = []
        for response in previous_responses:
            normalized_response = re.sub(r"\s+", " ", response)
            if len(normalized_response) < 32:
                continue
            if normalized_response[:200] in normalized_args:
                matches.append(normalized_response[:200])
                continue
            for chunk in DataExfiltrationDetector._candidate_chunks(response):
                if chunk in serialized_args:
                    matches.append(chunk)
                    break
        return matches

    @staticmethod
    def _candidate_chunks(response: str) -> list[str]:
        values: list[str] = []
        try:
            parsed = json.loads(response)
        except json.JSONDecodeError:
            parsed = response

        def collect(value: Any) -> None:
            if isinstance(value, dict):
                for nested in value.values():
                    collect(nested)
            elif isinstance(value, list):
                for nested in value:
                    collect(nested)
            elif value is not None:
                values.append(str(value))

        collect(parsed)

        chunks: list[str] = []
        for value in values:
            chunks.extend(line.strip() for line in re.split(r"[\n\r]+", value) if len(line.strip()) >= 24)
            chunks.extend(match.strip() for match in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}=.{12,}", value))
        return sorted(set(chunks), key=len, reverse=True)


class PrivilegeEscalationDetector(BaseDetector):
    threat_type = "PRIVILEGE_ESCALATION"

    high_risk_chains = [
        ("read_file", "execute_code", "http_request"),
        ("list_files", "read_file", "http_request"),
        ("read_file", "http_request"),
    ]

    def __init__(self, permissions_path: Path | str = DEFAULT_PERMISSIONS_PATH) -> None:
        self.permissions_path = Path(permissions_path)

    def detect(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        response_text: str,
        context: dict[str, Any] | None = None,
    ) -> list[DetectionResult]:
        context = context or {}
        sequence = [str(tool) for tool in context.get("tool_sequence", []) if tool]
        candidate = [*sequence, tool_name]
        results: list[DetectionResult] = []

        for chain in self.high_risk_chains:
            if self._ends_with_chain(candidate, chain):
                results.append(
                    DetectionResult(
                        threat_type=self.threat_type,
                        severity="HIGH",
                        confidence=0.9,
                        evidence=f"High-risk tool chain observed: {' -> '.join(chain)}.",
                        detector=self.__class__.__name__,
                        metadata={"chain": list(chain)},
                    )
                )

        matrix = self._load_permissions()
        if sequence and matrix:
            previous_tool = sequence[-1]
            allowed_next = matrix.get(previous_tool)
            if allowed_next is not None and tool_name not in allowed_next:
                results.append(
                    DetectionResult(
                        threat_type=self.threat_type,
                        severity="HIGH",
                        confidence=0.82,
                        evidence=f"`{previous_tool}` is not permitted to be followed by `{tool_name}`.",
                        detector=self.__class__.__name__,
                        metadata={"previous_tool": previous_tool, "tool_name": tool_name},
                    )
                )

        return _dedupe_results(results)

    def _load_permissions(self) -> dict[str, list[str]]:
        if not self.permissions_path.exists():
            return {}
        try:
            raw = json.loads(self.permissions_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        matrix = raw.get("permissions", raw)
        if not isinstance(matrix, dict):
            return {}
        return {str(tool): [str(allowed) for allowed in allowed_next] for tool, allowed_next in matrix.items() if isinstance(allowed_next, list)}

    @staticmethod
    def _ends_with_chain(sequence: list[str], chain: tuple[str, ...]) -> bool:
        if len(sequence) < len(chain):
            return False
        return tuple(sequence[-len(chain) :]) == chain


class DetectorPipeline:
    def __init__(self, detectors: list[BaseDetector] | None = None) -> None:
        registry = AgentRegistry()
        self.detectors = detectors or [
            PromptInjectionDetector(),
            IdentitySpoofingDetector(registry),
            DataExfiltrationDetector(),
            PrivilegeEscalationDetector(),
        ]

    def run(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        response_text: str,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        results: list[DetectionResult] = []
        for detector in self.detectors:
            results.extend(detector.detect(tool_name, arguments, response_text, context))
        return [result.to_dict() for result in _dedupe_results(results)]


def _dedupe_results(results: list[DetectionResult]) -> list[DetectionResult]:
    deduped: dict[tuple[str, str, str], DetectionResult] = {}
    for result in results:
        key = (result.threat_type, result.severity, result.evidence)
        deduped[key] = result
    return list(deduped.values())
