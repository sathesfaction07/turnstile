"""The gateway's client for the legacy SOAP service.

What it protects, and how:

* **The legacy system from the agents.** At most `max_concurrency` requests at once (below
  the service's own limit of 4), so a burst of agent traffic queues here instead of tripping
  `SystemBusy` for every other user of the system.
* **The agents from the legacy system.** A circuit breaker: after `breaker_threshold`
  consecutive failures, calls fail fast for `breaker_cooldown_s` instead of each one waiting
  on a dead service.
* **Correctness.** Reads are retried on transient faults. Writes are never retried here,
  because `FileClaim` is not idempotent; the gateway reconciles instead (see `core.py`).
* **Sessions.** Logs in on first use and again when a ticket expires, invisibly to callers.

Requests are built with ElementTree, which escapes text, so a value can never change the
structure of the envelope it travels in.
"""

from __future__ import annotations

import asyncio
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import httpx

from turnstile.legacy.soap import PAS_NS, SOAP_NS

RETRYABLE_CODES = {"SystemBusy", "InternalError", "Timeout", "HTTP503", "Transport"}
WRITE_OPS = {"FileClaim", "UpdateAddress"}


class LegacyError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code, self.message = code, message

    @property
    def retryable(self) -> bool:
        return self.code in RETRYABLE_CODES


@dataclass
class CallStats:
    calls: int = 0
    retries: int = 0
    logins: int = 0
    breaker_rejections: int = 0


class PasClient:
    def __init__(
        self,
        base_url: str = "http://pas",
        transport: httpx.AsyncBaseTransport | None = None,
        user: str = "svc_gateway",
        password: str = "legacy-password",
        timeout_s: float = 5.0,
        max_concurrency: int = 3,
        read_retries: int = 2,
        backoff_s: float = 0.05,
        breaker_threshold: int = 5,
        breaker_cooldown_s: float = 30.0,
    ) -> None:
        self._http = httpx.AsyncClient(base_url=base_url, transport=transport, timeout=timeout_s)
        self._user, self._password = user, password
        self._ticket = ""
        self._login_lock = asyncio.Lock()
        self._slots = asyncio.Semaphore(max_concurrency)
        self.read_retries, self.backoff_s = read_retries, backoff_s
        self.breaker_threshold, self.breaker_cooldown_s = breaker_threshold, breaker_cooldown_s
        self._failures = 0
        self._open_until = 0.0
        self.stats = CallStats()

    async def close(self) -> None:
        await self._http.aclose()

    @property
    def breaker_open(self) -> bool:
        return time.monotonic() < self._open_until

    async def extract(self) -> str:
        response = await self._http.get("/extract/policies.csv")
        response.raise_for_status()
        return response.text

    async def call(self, op: str, **fields: str) -> ET.Element:
        """Run one operation; return the response element, or raise LegacyError."""
        attempts = 1 if op in WRITE_OPS else 1 + self.read_retries
        for attempt in range(attempts):
            try:
                return await self._with_ticket(op, fields)
            except LegacyError as error:
                if not error.retryable or attempt == attempts - 1:
                    raise
                self.stats.retries += 1
                await asyncio.sleep(self.backoff_s * 2**attempt)
        raise AssertionError("unreachable")

    async def _with_ticket(self, op: str, fields: dict[str, str]) -> ET.Element:
        if not self._ticket:
            await self._login()
        try:
            return await self._send(op, {"Ticket": self._ticket, **fields})
        except LegacyError as error:
            if error.code != "InvalidTicket":
                raise
            await self._login(force=True)
            return await self._send(op, {"Ticket": self._ticket, **fields})

    async def _login(self, force: bool = False) -> None:
        async with self._login_lock:
            if self._ticket and not force:
                return
            response = await self._send("Login", {"User": self._user, "Password": self._password})
            self._ticket = _find(response, "Ticket")
            self.stats.logins += 1

    async def _send(self, op: str, fields: dict[str, str]) -> ET.Element:
        if self.breaker_open:
            self.stats.breaker_rejections += 1
            raise LegacyError("CircuitOpen", "the policy system is failing; not calling it")
        async with self._slots:
            self.stats.calls += 1
            try:
                response = await self._http.post(
                    "/pas", content=_envelope(op, fields), headers={"Content-Type": "text/xml"}
                )
            except httpx.TransportError as exc:
                self._record(ok=False)
                raise LegacyError("Transport", str(exc)) from exc
        if response.status_code == 503:
            self._record(ok=False)
            raise LegacyError("HTTP503", "service unavailable")
        try:
            body = ET.fromstring(response.content).find(f"{{{SOAP_NS}}}Body")
        except ET.ParseError as exc:
            self._record(ok=False)
            raise LegacyError("BadResponse", str(exc)) from exc
        payload = body[0] if body is not None and len(body) else None
        if payload is None:
            self._record(ok=False)
            raise LegacyError("BadResponse", "empty SOAP body")
        if payload.tag == f"{{{SOAP_NS}}}Fault":
            code = payload.findtext(f"detail/{{{PAS_NS}}}Code") or "Fault"
            server_side = (payload.findtext("faultcode") or "").endswith("Server")
            self._record(ok=not server_side)  # a client fault means the service is healthy
            raise LegacyError(code, payload.findtext("faultstring") or "")
        self._record(ok=True)
        return payload

    def _record(self, ok: bool) -> None:
        if ok:
            self._failures = 0
            return
        self._failures += 1
        if self._failures >= self.breaker_threshold:
            self._open_until = time.monotonic() + self.breaker_cooldown_s
            self._failures = 0


def _envelope(op: str, fields: dict[str, str]) -> bytes:
    env = ET.Element(f"{{{SOAP_NS}}}Envelope")
    body = ET.SubElement(env, f"{{{SOAP_NS}}}Body")
    request = ET.SubElement(body, f"{{{PAS_NS}}}{op}")
    for name, value in fields.items():
        ET.SubElement(request, f"{{{PAS_NS}}}{name}").text = value
    return ET.tostring(env, encoding="utf-8", xml_declaration=True)


def _find(el: ET.Element, tag: str) -> str:
    return el.findtext(f".//{{{PAS_NS}}}{tag}") or ""


def children(el: ET.Element, tag: str) -> list[ET.Element]:
    return el.findall(f".//{{{PAS_NS}}}{tag}")


def record(el: ET.Element) -> dict[str, str]:
    """Flatten one record element (e.g. Policy, Claim) into {field: text}."""
    return {child.tag.split("}")[-1]: child.text or "" for child in el}
