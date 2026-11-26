"""An ADK agent using the gateway through McpToolset, driven by a scripted model.

The script stands in for Gemini so the test needs no key: it calls prepare_claim, reads the
confirmation id out of the tool result the way a model would, then submits. Everything below
the model is real: ADK's MCP client, HTTP, auth, the gateway and the legacy system.
"""

import asyncio
import json
from collections.abc import AsyncGenerator
from typing import Any

import pytest

adk = pytest.importorskip("google.adk")

from google.adk.models._capabilities import LlmCapabilities  # noqa: E402
from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_request import LlmRequest  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.runners import Runner  # noqa: E402
from google.adk.sessions import InMemorySessionService  # noqa: E402
from google.genai import types  # noqa: E402
from pydantic import Field  # noqa: E402

from turnstile.agent import build_claims_agent  # noqa: E402
from turnstile.attacks import serving  # noqa: E402
from turnstile.stack import local_stack  # noqa: E402


def _last_result(req: LlmRequest) -> dict[str, Any]:
    for content in reversed(req.contents):
        for part in content.parts or []:
            if part.function_response:
                response = part.function_response.response or {}
                text = response.get("result", response)
                if isinstance(text, dict) and "content" in text:
                    text = "".join(c.get("text", "") for c in text["content"])
                return json.loads(text) if isinstance(text, str) else text
    return {}


class ScriptedClaims(BaseLlm):
    policy_number: str
    tools_seen: list[str] = Field(default_factory=list)
    step: int = 0

    @property
    def capabilities(self) -> LlmCapabilities:
        return LlmCapabilities(output_schema_and_tools=True)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        self.tools_seen = sorted(llm_request.tools_dict)
        self.step += 1
        if self.step == 1:
            part = types.Part(
                function_call=types.FunctionCall(
                    name="prepare_claim",
                    args={
                        "policy_number": self.policy_number,
                        "loss_date": "2025-05-03",
                        "description": "Rear-ended at a stop light",
                        "amount": "1800.00",
                    },
                )
            )
        elif self.step == 2:
            summary = _last_result(llm_request)
            part = types.Part(text=f"Please confirm: {summary.get('summary')}")
            self.confirmation = summary.get("confirmation_id", "")
        elif self.step == 3:
            part = types.Part(
                function_call=types.FunctionCall(
                    name="submit_claim", args={"confirmation_id": self.confirmation}
                )
            )
        else:
            done = _last_result(llm_request)
            part = types.Part(text=f"Your claim number is {done.get('claim_number')}.")
        yield LlmResponse(content=types.Content(role="model", parts=[part]))

    confirmation: str = ""


async def _conversation(url: str, token: str, policy_number: str):
    model = ScriptedClaims(model="scripted", policy_number=policy_number)
    agent = build_claims_agent(model, url, token)
    sessions = InMemorySessionService()
    runner = Runner(app_name="claims", agent=agent, session_service=sessions)
    session = await sessions.create_session(app_name="claims", user_id="u")
    said = []
    for message in ("I was rear-ended yesterday.", "Yes, that's right."):
        async for event in runner.run_async(
            user_id="u",
            session_id=session.id,
            new_message=types.Content(role="user", parts=[types.Part(text=message)]),
        ):
            for part in (event.content.parts if event.content else None) or []:
                if part.text:
                    said.append(part.text)
    await runner.close()
    return model, said


def test_an_adk_agent_files_a_claim_through_the_gateway():
    st = local_stack()
    p = next(x for x in st.legacy.policies.values() if x.status == "A")
    before = len(p.claims)
    with serving(st) as url:
        model, said = asyncio.run(_conversation(url, "dev-claims-token", p.policy_no))
    assert "prepare_claim" in model.tools_seen and "prepare_address_change" in model.tools_seen
    assert len(p.claims) == before + 1 and p.claims[-1].amount_cents == 180000
    assert p.claims[-1].claim_no in said[-1]
    agents = {e["agent"] for e in st.gateway.audit.entries}
    assert agents == {"claims-intake-agent"}  # identity came from the token, not the model


def test_the_same_agent_with_a_read_only_token_cannot_file():
    st = local_stack()
    p = next(x for x in st.legacy.policies.values() if x.status == "A")
    before = len(p.claims)
    with serving(st) as url:
        asyncio.run(_conversation(url, "dev-analytics-token", p.policy_no))
    assert len(p.claims) == before
    refused = [e for e in st.gateway.audit.entries if e["tool"] == "prepare_claim"]
    assert refused and refused[0]["code"] == "denied"
