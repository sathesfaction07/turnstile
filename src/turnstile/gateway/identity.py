"""Agent identities: who may call which tool, see which fields, how often.

Each agent team gets its own client identity and token. The registry stores only SHA-256
hashes of tokens. Scopes map to tools; the PII level decides which personal fields leave the
gateway at all.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

PII_LEVELS = ("none", "masked", "full")
TOOL_SCOPES = {
    "search_policies": "policy:read",
    "get_policy": "policy:read",
    "list_claims": "claims:read",
    "prepare_claim": "claims:write",
    "submit_claim": "claims:write",
    "prepare_address_change": "address:write",
    "submit_address_change": "address:write",
}


@dataclass(frozen=True)
class Agent:
    client_id: str
    scopes: frozenset[str]
    pii: str
    requests_per_minute: int
    description: str = ""

    def may(self, tool: str) -> bool:
        return TOOL_SCOPES.get(tool, "") in self.scopes


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Registry:
    def __init__(self, agents: dict[str, Agent]) -> None:
        self._by_hash = agents

    @classmethod
    def from_json(cls, path: Path) -> Registry:
        raw = json.loads(path.read_text(encoding="utf-8"))
        agents = {}
        for entry in raw["agents"]:
            if entry["pii"] not in PII_LEVELS:
                raise ValueError(f"{entry['client_id']}: pii must be one of {PII_LEVELS}")
            unknown = set(entry["scopes"]) - set(TOOL_SCOPES.values())
            if unknown:
                raise ValueError(f"{entry['client_id']}: unknown scopes {sorted(unknown)}")
            agents[entry["token_sha256"]] = Agent(
                client_id=entry["client_id"],
                scopes=frozenset(entry["scopes"]),
                pii=entry["pii"],
                requests_per_minute=int(entry["requests_per_minute"]),
                description=entry.get("description", ""),
            )
        return cls(agents)

    @classmethod
    def from_tokens(cls, entries: dict[str, Agent]) -> Registry:
        """Build from plaintext tokens (tests and local demos)."""
        return cls({token_hash(token): agent for token, agent in entries.items()})

    def verify(self, token: str) -> Agent | None:
        return self._by_hash.get(token_hash(token))

    def agents(self) -> list[Agent]:
        return list(self._by_hash.values())
