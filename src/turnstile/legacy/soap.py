"""The policy administration system's SOAP endpoint (mock).

One POST endpoint, `/pas`, taking a SOAP 1.1 envelope whose body element names the
operation. Responses and faults follow the same shape the real service used.
"""

from __future__ import annotations

import asyncio
import random
import secrets
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, ClassVar

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from turnstile.legacy.data import Claim, Policy, generate, nightly_extract

SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
PAS_NS = "urn:pas"
TICKET_TTL_S = 15 * 60
MAX_CONCURRENT = 4
ADDR1_WIDTH = 30
DESCRIPTION_WIDTH = 200
SERVICE_USER = ("svc_gateway", "legacy-password")


class Fault(Exception):  # noqa: N818 - SOAP's own term
    def __init__(self, code: str, message: str = "", side: str = "Client") -> None:
        super().__init__(code)
        self.code, self.message, self.side = code, message or code, side


@dataclass
class Faults:
    """Injected behaviour, for testing what the gateway does when the legacy system misbehaves."""

    latency_ms: tuple[int, int] = (0, 0)
    error_rate: float = 0.0
    down: bool = False
    lose_response_after_write: bool = False  # commit FileClaim, then fail the response
    seed: int = 0
    rng: random.Random = field(init=False)

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed)


class LegacySystem:
    def __init__(self, policies: dict[str, Policy] | None = None, faults: Faults | None = None):
        self.policies = policies if policies is not None else generate()
        self.faults = faults or Faults()
        self.tickets: dict[str, float] = {}
        self.in_flight = 0
        self.calls: list[str] = []
        self.peak_in_flight = 0

    def extract(self) -> str:
        return nightly_extract(self.policies)

    # -- operations ------------------------------------------------------------------------
    def _ticket(self, body: ET.Element) -> None:
        ticket = _text(body, "Ticket")
        expires = self.tickets.get(ticket)
        if expires is None or expires < time.monotonic():
            raise Fault("InvalidTicket", "session ticket missing or expired")

    def _policy(self, body: ET.Element) -> Policy:
        policy = self.policies.get(_text(body, "PolicyNo"))
        if policy is None:
            raise Fault("PolicyNotFound")
        return policy

    def login(self, body: ET.Element) -> ET.Element:
        if (_text(body, "User"), _text(body, "Password")) != SERVICE_USER:
            raise Fault("AuthenticationFailed")
        ticket = secrets.token_hex(12)
        self.tickets[ticket] = time.monotonic() + TICKET_TTL_S
        return _el("LoginResponse", [_el("Ticket", ticket)])

    def get_policy(self, body: ET.Element) -> ET.Element:
        self._ticket(body)
        p = self._policy(body)
        fields = [
            ("PolicyNo", p.policy_no),
            ("Status", p.status),
            ("ProductCode", p.product),
            ("InsuredName", p.insured_name),
            ("DOB", p.dob),
            ("SSN", p.ssn),
            ("Addr1", p.addr1),
            ("City", p.city),
            ("State", p.state),
            ("Zip", p.zip),
            ("Phone", p.phone),
            ("Email", p.email),
            ("EffDate", p.eff_date),
            ("ExpDate", p.exp_date),
            ("PremiumCents", str(p.premium_cents)),
            ("Notes", p.notes),
        ]
        return _el("GetPolicyResponse", [_el("Policy", [_el(k, v) for k, v in fields])])

    def get_claims(self, body: ET.Element) -> ET.Element:
        self._ticket(body)
        p = self._policy(body)
        claims = [
            _el(
                "Claim",
                [
                    _el("ClaimNo", c.claim_no),
                    _el("LossDate", c.loss_date),
                    _el("Status", c.status),
                    _el("AmountCents", str(c.amount_cents)),
                    _el("Description", c.description),
                ],
            )
            for c in p.claims
        ]
        return _el("GetClaimsResponse", [_el("Claims", claims)])

    def search(self, body: ET.Element) -> ET.Element:
        self._ticket(body)
        last = _text(body, "LastName").upper()
        hits = [p for p in self.policies.values() if p.insured_name.startswith(last + ",")]
        return _el(
            "SearchPoliciesResponse",
            [
                _el("Hit", [_el("PolicyNo", p.policy_no), _el("InsuredName", p.insured_name)])
                for p in hits
            ],
        )

    def file_claim(self, body: ET.Element) -> ET.Element:
        self._ticket(body)
        p = self._policy(body)
        loss_date, description = _text(body, "LossDate"), _text(body, "Description")
        amount = _text(body, "AmountCents")
        if len(loss_date) != 8 or not loss_date.isdigit():
            raise Fault("ValidationError", "LossDate must be YYYYMMDD")
        if len(description) > DESCRIPTION_WIDTH:
            raise Fault("ValidationError", f"Description exceeds {DESCRIPTION_WIDTH} characters")
        if not amount.isdigit():
            raise Fault("ValidationError", "AmountCents must be digits")
        if p.status != "A":
            raise Fault("PolicyNotActive")
        claim = Claim(f"CL{secrets.randbelow(10**7):07d}", loss_date, "O", int(amount), description)
        p.claims.append(claim)  # no idempotency: a retried request files a second claim
        if self.faults.lose_response_after_write:
            raise Fault("Timeout", "upstream timeout", side="Server")
        return _el("FileClaimResponse", [_el("ClaimNo", claim.claim_no)])

    def update_address(self, body: ET.Element) -> ET.Element:
        self._ticket(body)
        p = self._policy(body)
        addr1 = _text(body, "Addr1")
        if len(addr1) > ADDR1_WIDTH:
            raise Fault("ValidationError", f"Addr1 exceeds {ADDR1_WIDTH} characters")
        p.addr1, p.city, p.state, p.zip = (
            addr1,
            _text(body, "City"),
            _text(body, "State"),
            _text(body, "Zip"),
        )
        return _el("UpdateAddressResponse", [_el("Result", "OK")])

    OPERATIONS: ClassVar[dict[str, str]] = {
        "Login": "login",
        "GetPolicy": "get_policy",
        "GetClaims": "get_claims",
        "SearchPolicies": "search",
        "FileClaim": "file_claim",
        "UpdateAddress": "update_address",
    }

    async def handle(self, raw: bytes) -> tuple[int, bytes]:
        f = self.faults
        if f.down:
            return 503, b"Service Unavailable"
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        try:
            lo, hi = f.latency_ms
            if hi:
                await asyncio.sleep(f.rng.uniform(lo, hi) / 1000)
            if self.in_flight > MAX_CONCURRENT:
                raise Fault("SystemBusy", "too many concurrent requests", side="Server")
            if f.error_rate and f.rng.random() < f.error_rate:
                raise Fault("InternalError", "transient failure", side="Server")
            try:
                envelope = ET.fromstring(raw)
            except ET.ParseError as exc:
                raise Fault("MalformedRequest", str(exc)) from exc
            body = envelope.find(f"{{{SOAP_NS}}}Body")
            op = body[0] if body is not None and len(body) else None
            name = op.tag.split("}")[-1] if op is not None else ""
            if op is None or name not in self.OPERATIONS:
                raise Fault("UnknownOperation", name)
            self.calls.append(name)
            result = getattr(self, self.OPERATIONS[name])(op)
            return 200, _envelope(result)
        except Fault as fault:
            return 500, _envelope(_fault(fault))
        finally:
            self.in_flight -= 1


def _text(el: ET.Element, tag: str) -> str:
    child = el.find(f"{{{PAS_NS}}}{tag}")
    return (child.text or "") if child is not None else ""


def _el(tag: str, content: Any) -> ET.Element:
    el = ET.Element(f"{{{PAS_NS}}}{tag}")
    if isinstance(content, list):
        el.extend(content)
    else:
        el.text = content
    return el


def _fault(f: Fault) -> ET.Element:
    el = ET.Element(f"{{{SOAP_NS}}}Fault")
    ET.SubElement(el, "faultcode").text = f"soap:{f.side}"
    ET.SubElement(el, "faultstring").text = f.message
    detail = ET.SubElement(el, "detail")
    ET.SubElement(detail, f"{{{PAS_NS}}}Code").text = f.code
    return el


def _envelope(payload: ET.Element) -> bytes:
    env = ET.Element(f"{{{SOAP_NS}}}Envelope")
    ET.SubElement(env, f"{{{SOAP_NS}}}Body").append(payload)
    return ET.tostring(env, encoding="utf-8", xml_declaration=True)


def create_app(system: LegacySystem) -> Starlette:
    async def pas(request: Request) -> Response:
        status, body = await system.handle(await request.body())
        return Response(body, status_code=status, media_type="text/xml")

    async def extract(_: Request) -> Response:
        return Response(system.extract(), media_type="text/csv")

    return Starlette(
        routes=[Route("/pas", pas, methods=["POST"]), Route("/extract/policies.csv", extract)]
    )


ET.register_namespace("soap", SOAP_NS)
ET.register_namespace("pas", PAS_NS)
