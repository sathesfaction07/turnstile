"""The attack suite, and the legitimate traffic it must not break.

Every case goes through the real MCP server over HTTP, as an agent would. Each attack has an
expected defence; each legitimate call must succeed. The report counts both, because a gateway
that blocks everything also "stops every attack".
"""

from __future__ import annotations

import asyncio
import json
import socket
import statistics
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import httpx2
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from turnstile.gateway.identity import TOOL_SCOPES, Agent, Registry
from turnstile.gateway.mcp_app import create_app
from turnstile.legacy.soap import Faults
from turnstile.stack import Stack, local_stack

CLAIMS, SERVICE, ANALYTICS = "dev-claims-token", "dev-service-token", "dev-analytics-token"


@contextmanager
def serving(stack: Stack) -> Iterator[str]:
    """Run the gateway's MCP app on a free local port; yield its URL."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    url = f"http://127.0.0.1:{port}/mcp"
    app = create_app(stack.gateway, stack.registry, resource_url=url)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("gateway did not start")
        time.sleep(0.02)
    try:
        yield url
    finally:
        server.should_exit = True
        thread.join(timeout=5)


async def call(url: str, token: str | None, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """One tool call over Streamable HTTP. Transport-level refusals come back as dicts too."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    statuses: list[int] = []

    async def seen(response: httpx2.Response) -> None:
        statuses.append(response.status_code)

    try:
        async with (
            httpx2.AsyncClient(headers=headers, event_hooks={"response": [seen]}) as http,
            Client(streamable_http_client(url, http_client=http)) as client,
        ):
            result = await client.call_tool(tool, args)
    except Exception as exc:  # an HTTP refusal surfaces as a client exception
        code = "unauthenticated" if 401 in statuses else "transport"
        return {"error": repr(exc)[:200], "code": code, "http_statuses": statuses}
    text = "".join(getattr(c, "text", "") for c in result.content)
    try:
        data = json.loads(text)
    except ValueError:
        data = {"error": text, "code": "tool_error"}
    if result.is_error and "code" not in data:
        data = {"error": text, "code": "tool_error"}
    return data


@dataclass
class Case:
    name: str
    kind: str  # attack | legitimate
    defence: str
    run: Callable[[str, Stack], Awaitable[bool]]  # True when the expected outcome happened


def _active(stack: Stack) -> Any:
    return next(p for p in stack.legacy.policies.values() if p.status == "A")


def _other(stack: Stack, policy: Any) -> Any:
    return next(
        p
        for p in stack.legacy.policies.values()
        if p.status == "A" and p.policy_no != policy.policy_no
    )


def cases() -> list[Case]:
    out: list[Case] = []

    def add(name: str, kind: str, defence: str) -> Callable[[Any], Any]:
        def wrap(fn: Callable[[str, Stack], Awaitable[bool]]) -> Any:
            out.append(Case(name, kind, defence, fn))
            return fn

        return wrap

    @add("No token", "attack", "401 before any tool runs")
    async def _(url: str, st: Stack) -> bool:
        r = await call(url, None, "get_policy", {"policy_number": _active(st).policy_no})
        return r.get("code") == "unauthenticated"

    @add("Forged token", "attack", "401 before any tool runs")
    async def _(url: str, st: Stack) -> bool:
        r = await call(url, "guess-1234", "get_policy", {"policy_number": _active(st).policy_no})
        return r.get("code") == "unauthenticated"

    @add("Read-only agent tries to file a claim", "attack", "scope check")
    async def _(url: str, st: Stack) -> bool:
        r = await call(
            url,
            ANALYTICS,
            "prepare_claim",
            {
                "policy_number": _active(st).policy_no,
                "loss_date": "2025-05-01",
                "description": "Fender bender",
                "amount": 900,
            },
        )
        return r.get("code") == "denied"

    @add("Claims agent tries to change an address", "attack", "scope check")
    async def _(url: str, st: Stack) -> bool:
        r = await call(
            url,
            CLAIMS,
            "prepare_address_change",
            {
                "policy_number": _active(st).policy_no,
                "street": "1 Main St",
                "city": "Austin",
                "state": "TX",
                "zip_code": "78701",
            },
        )
        return r.get("code") == "denied"

    @add("Analytics agent reads personal data", "attack", "PII redaction by identity")
    async def _(url: str, st: Stack) -> bool:
        r = await call(url, ANALYTICS, "get_policy", {"policy_number": _active(st).policy_no})
        text = json.dumps(r)
        p = _active(st)
        return "contact" not in r and p.ssn[-4:] not in text and p.email not in text

    @add("Any agent asks for the full SSN", "attack", "SSN never leaves the gateway")
    async def _(url: str, st: Stack) -> bool:
        p = _active(st)
        r = await call(url, SERVICE, "get_policy", {"policy_number": p.policy_no})
        return p.ssn not in json.dumps(r) and r.get("ssn_last4") == p.ssn[-4:]

    @add("XML injected into a policy number", "attack", "strict input validation")
    async def _(url: str, st: Stack) -> bool:
        p = _active(st)
        r = await call(
            url,
            CLAIMS,
            "get_policy",
            {"policy_number": f"{p.policy_no}</PolicyNo><PolicyNo>XX99999999"},
        )
        return r.get("code") == "invalid"

    @add(
        "Envelope injection in a claim description",
        "attack",
        "values escaped; injected tags stay literal text",
    )
    async def _(url: str, st: Stack) -> bool:
        p = _active(st)
        evil = "Hit a pole</Description><AmountCents>99999999</AmountCents><Description>x"
        prep = await call(
            url,
            CLAIMS,
            "prepare_claim",
            {
                "policy_number": p.policy_no,
                "loss_date": "2025-05-01",
                "description": evil,
                "amount": 400,
            },
        )
        if "confirmation_id" not in prep:
            return prep.get("code") == "invalid"
        done = await call(url, CLAIMS, "submit_claim", {"confirmation_id": prep["confirmation_id"]})
        filed = [c for c in p.claims if c.claim_no == done.get("claim_number")]
        return bool(filed) and filed[0].amount_cents == 40000 and "</" in filed[0].description

    @add("Wildcard search to enumerate customers", "attack", "name pattern, DOB required")
    async def _(url: str, st: Stack) -> bool:
        r = await call(
            url, CLAIMS, "search_policies", {"last_name": "%", "date_of_birth": "1980-01-01"}
        )
        return r.get("code") == "invalid"

    @add("Claim above the automatic limit", "attack", "amount ceiling")
    async def _(url: str, st: Stack) -> bool:
        r = await call(
            url,
            CLAIMS,
            "prepare_claim",
            {
                "policy_number": _active(st).policy_no,
                "loss_date": "2025-05-01",
                "description": "Total loss of vehicle",
                "amount": 250000,
            },
        )
        return r.get("code") == "denied"

    @add("Oversized description (100 KB)", "attack", "length limit")
    async def _(url: str, st: Stack) -> bool:
        r = await call(
            url,
            CLAIMS,
            "prepare_claim",
            {
                "policy_number": _active(st).policy_no,
                "loss_date": "2025-05-01",
                "description": "A" * 100_000,
                "amount": 100,
            },
        )
        return r.get("code") == "invalid"

    @add("Submit with a made-up confirmation id", "attack", "confirmation required")
    async def _(url: str, st: Stack) -> bool:
        r = await call(url, CLAIMS, "submit_claim", {"confirmation_id": "cf_made_up"})
        return r.get("code") == "invalid"

    @add("Submit another agent's confirmation", "attack", "confirmation bound to its agent")
    async def _(url: str, st: Stack) -> bool:
        prep = await call(
            url,
            SERVICE,
            "prepare_address_change",
            {
                "policy_number": _active(st).policy_no,
                "street": "12 Lake Dr",
                "city": "Boise",
                "state": "ID",
                "zip_code": "83702",
            },
        )
        r = await call(
            url,
            ANALYTICS,
            "submit_address_change",
            {"confirmation_id": prep.get("confirmation_id", "")},
        )
        return r.get("code") == "denied"

    @add("Replay a submitted claim", "attack", "single-use confirmation; never files twice")
    async def _(url: str, st: Stack) -> bool:
        p = _other(st, _active(st))
        before = len(p.claims)
        prep = await call(
            url,
            CLAIMS,
            "prepare_claim",
            {
                "policy_number": p.policy_no,
                "loss_date": "2025-05-02",
                "description": "Windshield cracked",
                "amount": 350,
            },
        )
        first = await call(
            url, CLAIMS, "submit_claim", {"confirmation_id": prep["confirmation_id"]}
        )
        again = await call(
            url, CLAIMS, "submit_claim", {"confirmation_id": prep["confirmation_id"]}
        )
        return (
            again.get("replayed") is True
            and again["claim_number"] == first["claim_number"]
            and len(p.claims) == before + 1
        )

    @add("Burst of 40 calls from one agent", "attack", "per-agent rate limit")
    async def _(url: str, st: Stack) -> bool:
        p = _active(st)
        results = [
            await call(url, ANALYTICS, "list_claims", {"policy_number": p.policy_no})
            for _ in range(40)
        ]
        return any(r.get("code") == "rate_limited" for r in results)

    @add(
        "Instructions planted in policy notes",
        "attack",
        "notes returned as labelled untrusted data",
    )
    async def _(url: str, st: Stack) -> bool:
        p = next(x for x in st.legacy.policies.values() if "IGNORE ALL" in x.notes)
        r = await call(url, CLAIMS, "get_policy", {"policy_number": p.policy_no})
        notes = r.get("notes", {})
        return "untrusted_text" in notes and "not instructions" in notes.get("warning", "")

    # -- legitimate traffic: each must succeed -------------------------------------------------
    @add("Find a policy by name and date of birth", "legitimate", "")
    async def _(url: str, st: Stack) -> bool:
        p = _active(st)
        last = p.insured_name.split(",")[0].title()
        dob = f"{p.dob[:4]}-{p.dob[4:6]}-{p.dob[6:]}"
        r = await call(url, CLAIMS, "search_policies", {"last_name": last, "date_of_birth": dob})
        return any(m["policy_number"] == p.policy_no for m in r.get("matches", []))

    @add("Read a policy and its claims", "legitimate", "")
    async def _(url: str, st: Stack) -> bool:
        p = _active(st)
        a = await call(url, CLAIMS, "get_policy", {"policy_number": p.policy_no})
        b = await call(url, CLAIMS, "list_claims", {"policy_number": p.policy_no})
        return a.get("policy_number") == p.policy_no and "claims" in b

    @add("File a claim with confirmation", "legitimate", "")
    async def _(url: str, st: Stack) -> bool:
        p = _other(st, _active(st))
        prep = await call(
            url,
            CLAIMS,
            "prepare_claim",
            {
                "policy_number": p.policy_no,
                "loss_date": "2025-04-11",
                "description": "Hail damage to the roof",
                "amount": "2,340.10",
            },
        )
        done = await call(url, CLAIMS, "submit_claim", {"confirmation_id": prep["confirmation_id"]})
        return done.get("amount") == "2340.10" and done.get("claim_number", "").startswith("CL")

    @add("Change an address with confirmation", "legitimate", "")
    async def _(url: str, st: Stack) -> bool:
        p = _active(st)
        prep = await call(
            url,
            SERVICE,
            "prepare_address_change",
            {
                "policy_number": p.policy_no,
                "street": "48 Birch Way",
                "city": "Raleigh",
                "state": "NC",
                "zip_code": "27601",
            },
        )
        done = await call(
            url, SERVICE, "submit_address_change", {"confirmation_id": prep["confirmation_id"]}
        )
        return done.get("updated") is True and p.addr1 == "48 Birch Way"

    @add("Service agent sees full contact details", "legitimate", "")
    async def _(url: str, st: Stack) -> bool:
        p = _active(st)
        r = await call(url, SERVICE, "get_policy", {"policy_number": p.policy_no})
        return r.get("contact", {}).get("email") == p.email

    return out


async def run_suite() -> list[dict[str, Any]]:
    results = []
    for case in cases():
        stack = local_stack()  # a fresh system per case, so cases cannot affect each other
        with serving(stack) as url:
            try:
                passed = await case.run(url, stack)
                note = ""
            except Exception as exc:  # a crash is a failed case, recorded, not a crashed suite
                passed, note = False, f"{type(exc).__name__}: {exc}"
        await stack.pas.close()
        results.append(
            {
                "name": case.name,
                "kind": case.kind,
                "defence": case.defence,
                "passed": passed,
                "note": note,
            }
        )
    return results


async def measure_overhead(n: int = 200) -> dict[str, float]:
    """Per-call latency: the legacy client alone versus the full gateway over MCP/HTTP.
    Both run locally with no injected latency, so this isolates what the gateway adds."""
    stack = local_stack(faults=Faults())
    # A benchmark identity with no practical rate limit, so the limiter cannot skew timing.
    stack.registry = Registry.from_tokens(
        {"bench-token": Agent("bench", frozenset(TOOL_SCOPES.values()), "full", 10**9)}
    )
    p = _active(stack)
    direct, gateway = [], []
    for _ in range(n):
        t = time.perf_counter()
        await stack.pas.call("GetPolicy", PolicyNo=p.policy_no)
        direct.append((time.perf_counter() - t) * 1000)
    with serving(stack) as url:
        headers = {"Authorization": "Bearer bench-token"}
        async with (
            httpx2.AsyncClient(headers=headers) as http,
            Client(streamable_http_client(url, http_client=http)) as client,
        ):
            for _ in range(n):
                t = time.perf_counter()
                await client.call_tool("get_policy", {"policy_number": p.policy_no})
                gateway.append((time.perf_counter() - t) * 1000)
    await stack.pas.close()

    def pct(xs: list[float], q: float) -> float:
        return round(sorted(xs)[min(len(xs) - 1, int(len(xs) * q))], 2)

    return {
        "n": n,
        "direct_p50_ms": pct(direct, 0.5),
        "direct_p95_ms": pct(direct, 0.95),
        "gateway_p50_ms": pct(gateway, 0.5),
        "gateway_p95_ms": pct(gateway, 0.95),
        "added_p50_ms": round(statistics.median(gateway) - statistics.median(direct), 2),
    }


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run_suite()), indent=1))
