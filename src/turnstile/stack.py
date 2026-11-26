"""Wiring for local runs and tests: the legacy system, the gateway and its agents."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

import httpx

from turnstile.gateway.core import AuditLog, Gateway
from turnstile.gateway.identity import Agent, Registry
from turnstile.gateway.pas_client import PasClient
from turnstile.legacy.soap import Faults, LegacySystem
from turnstile.legacy.soap import create_app as legacy_app

# Development identities for the local mock only. Real tokens come from the customer's IdP.
DEV_AGENTS = {
    "dev-claims-token": Agent(
        "claims-intake-agent",
        frozenset({"policy:read", "claims:read", "claims:write"}),
        pii="masked",
        requests_per_minute=60,
        description="Takes first notice of loss from policyholders.",
    ),
    "dev-service-token": Agent(
        "service-desk-agent",
        frozenset({"policy:read", "address:write"}),
        pii="full",
        requests_per_minute=60,
        description="Answers policy questions and updates contact details.",
    ),
    "dev-analytics-token": Agent(
        "analytics-agent",
        frozenset({"policy:read", "claims:read"}),
        pii="none",
        requests_per_minute=30,
        description="Summarises portfolios; never sees personal data or writes.",
    ),
}
TODAY = date(2025, 6, 1)  # fixed so that claim-date rules are reproducible


@dataclass
class Stack:
    legacy: LegacySystem
    pas: PasClient
    gateway: Gateway
    registry: Registry


def local_stack(faults: Faults | None = None, today: date = TODAY, **pas_options: object) -> Stack:
    legacy = LegacySystem(faults=faults)
    pas = PasClient(transport=httpx.ASGITransport(app=legacy_app(legacy)), **pas_options)  # type: ignore[arg-type]
    gateway = Gateway(pas, AuditLog(), today=lambda: today)
    return Stack(legacy, pas, gateway, Registry.from_tokens(DEV_AGENTS))
