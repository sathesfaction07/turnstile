"""Gateway behaviour: redaction, validation, rate limits, confirmed writes, reconciliation."""

import asyncio

import pytest

from turnstile.gateway import core
from turnstile.legacy.soap import Faults
from turnstile.stack import DEV_AGENTS, local_stack

CLAIMS = DEV_AGENTS["dev-claims-token"]
SERVICE = DEV_AGENTS["dev-service-token"]
ANALYTICS = DEV_AGENTS["dev-analytics-token"]


def run(coro):
    return asyncio.run(coro)


def active(st):
    return next(p for p in st.legacy.policies.values() if p.status == "A")


@pytest.mark.parametrize(
    ("agent", "present", "absent"),
    [
        (ANALYTICS, [], ["contact", "ssn_last4", "date_of_birth"]),
        (CLAIMS, ["contact", "ssn_last4"], ["date_of_birth"]),
        (SERVICE, ["contact", "ssn_last4", "date_of_birth"], []),
    ],
)
def test_personal_data_follows_the_agent_identity(agent, present, absent):
    st = local_stack()
    r = run(st.gateway.get_policy(agent, active(st).policy_no))
    assert all(k in r for k in present) and not any(k in r for k in absent)
    assert active(st).ssn not in str(r)


def test_legacy_formats_are_normalised():
    st = local_stack()
    p = active(st)
    r = run(st.gateway.get_policy(SERVICE, p.policy_no))
    assert r["status"] == "active" and r["product"] == p.product.lower()
    assert r["date_of_birth"] == f"{p.dob[:4]}-{p.dob[4:6]}-{p.dob[6:]}"
    assert r["annual_premium"] == f"{p.premium_cents / 100:.2f}"
    assert "," not in r["insured_name"]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"loss_date": "2025-13-01"}, "loss_date"),
        ({"loss_date": "2026-01-01"}, "future"),
        ({"loss_date": "2022-01-01"}, "two years"),
        ({"description": "hi"}, "description"),
        ({"description": "bad\x00text here"}, "control"),
        ({"amount": "12.345"}, "two decimal"),
        ({"amount": "-5"}, "positive"),
        ({"amount": "lots"}, "number"),
    ],
)
def test_claim_validation(args, message):
    st = local_stack()
    base = {
        "policy_number": active(st).policy_no,
        "loss_date": "2025-05-01",
        "description": "Rear-ended at a light",
        "amount": 500,
    }
    r = run(st.gateway.prepare_claim(CLAIMS, **{**base, **args}))
    assert message in r["error"]


def test_prepare_writes_nothing():
    st = local_stack()
    p = active(st)
    before = len(p.claims)
    run(st.gateway.prepare_claim(CLAIMS, p.policy_no, "2025-05-01", "Kitchen fire", 900))
    assert len(p.claims) == before
    assert "FileClaim" not in st.legacy.calls


def test_inactive_policies_cannot_take_claims():
    st = local_stack()
    p = next(x for x in st.legacy.policies.values() if x.status != "A")
    r = run(st.gateway.prepare_claim(CLAIMS, p.policy_no, "2025-05-01", "Kitchen fire", 900))
    assert r["code"] == "conflict"


def test_confirmations_expire():
    st = local_stack()
    now = [1_000_000.0]
    st.gateway.clock = lambda: now[0]
    prep = run(
        st.gateway.prepare_claim(CLAIMS, active(st).policy_no, "2025-05-01", "Kitchen fire", 900)
    )
    now[0] += core.CONFIRM_TTL_S + 1
    assert "expired" in run(st.gateway.submit_claim(CLAIMS, prep["confirmation_id"]))["error"]


def test_a_lost_response_is_reconciled_not_refiled():
    st = local_stack(faults=Faults(lose_response_after_write=True))
    p = active(st)
    before = len(p.claims)
    prep = run(st.gateway.prepare_claim(CLAIMS, p.policy_no, "2025-05-01", "Kitchen fire", 900))
    done = run(st.gateway.submit_claim(CLAIMS, prep["confirmation_id"]))
    assert done["reconciled_after_error"] is True
    assert done["claim_number"] == p.claims[-1].claim_no
    assert len(p.claims) == before + 1


def test_a_failed_reconciliation_then_a_retry_still_files_once():
    st = local_stack(faults=Faults(lose_response_after_write=True), read_retries=0)
    p = active(st)
    before = len(p.claims)
    prep = run(st.gateway.prepare_claim(CLAIMS, p.policy_no, "2025-05-01", "Kitchen fire", 900))

    real_find = st.gateway._find_new_claim
    calls = {"n": 0}

    async def flaky_find(payload, seen):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # the first look-up misses, as if the read hit a stale replica
        return await real_find(payload, seen)

    st.gateway._find_new_claim = flaky_find
    first = run(st.gateway.submit_claim(CLAIMS, prep["confirmation_id"]))
    assert first["code"] == "unavailable"
    st.legacy.faults.lose_response_after_write = False
    second = run(st.gateway.submit_claim(CLAIMS, prep["confirmation_id"]))
    assert second["reconciled_after_error"] is True
    assert len(p.claims) == before + 1  # the retry found the first write instead of refiling


def test_rate_limit_refills_over_time():
    st = local_stack()
    now = [0.0]
    st.gateway.clock = lambda: now[0]
    p = active(st).policy_no
    results = [run(st.gateway.list_claims(ANALYTICS, p)) for _ in range(31)]
    assert results[-1]["code"] == "rate_limited"
    now[0] += 4  # 30 a minute: one token every 2 seconds
    assert "claims" in run(st.gateway.list_claims(ANALYTICS, p))


def test_every_call_is_audited_without_personal_data():
    st = local_stack()
    p = active(st)
    run(st.gateway.get_policy(SERVICE, p.policy_no))
    run(st.gateway.prepare_claim(ANALYTICS, p.policy_no, "2025-05-01", "Kitchen fire", 900))
    ok, refused = st.gateway.audit.entries
    assert ok["outcome"] == "ok" and ok["legacy_calls"] >= 1
    assert refused["outcome"] == "refused" and refused["code"] == "denied"
    assert refused["legacy_calls"] == 0  # refused before the legacy system was touched
    assert p.ssn not in str(st.gateway.audit.entries) and p.email not in str(
        st.gateway.audit.entries
    )


def test_search_is_from_the_extract_and_says_how_old_it_is():
    st = local_stack()
    p = active(st)
    run(st.gateway.load_extract())
    last = p.insured_name.split(",")[0]
    dob = f"{p.dob[:4]}-{p.dob[4:6]}-{p.dob[6:]}"
    r = run(st.gateway.search_policies(CLAIMS, last.lower(), dob))
    assert p.policy_no in [m["policy_number"] for m in r["matches"]]
    assert r["source"] == "nightly extract" and r["as_of"]
    assert "SearchPolicies" not in st.legacy.calls


def test_legacy_errors_become_plain_answers():
    st = local_stack()
    assert run(st.gateway.get_policy(CLAIMS, "AU00000000"))["code"] == "not_found"
    p = active(st)
    prep = run(
        st.gateway.prepare_address_change(
            SERVICE, p.policy_no, "1 Main St", "Austin", "TX", "78701"
        )
    )
    assert "confirmation_id" in prep
    long_street = run(
        st.gateway.prepare_address_change(SERVICE, p.policy_no, "x" * 31, "Austin", "TX", "78701")
    )
    assert "30" in long_street["error"]


def test_legacy_outage_is_reported_not_raised():
    st = local_stack(faults=Faults(down=True), read_retries=0, breaker_threshold=2)
    p = active(st).policy_no
    codes = [run(st.gateway.get_policy(CLAIMS, p))["code"] for _ in range(4)]
    assert set(codes) == {"unavailable"}
    assert st.pas.breaker_open


def test_the_example_registry_matches_the_dev_identities():
    from pathlib import Path

    from turnstile.gateway.identity import Registry

    path = Path(__file__).resolve().parents[1] / "config" / "agents.example.json"
    registry = Registry.from_json(path)
    for token, agent in DEV_AGENTS.items():
        assert registry.verify(token) == agent
    assert registry.verify("not-a-token") is None


def test_the_container_factory_builds_the_gateway(monkeypatch):
    from turnstile.cli import create_gateway_app

    monkeypatch.setenv("LEGACY_URL", "http://legacy.internal")
    app = create_gateway_app()
    assert any(getattr(r, "path", "") == "/mcp" for r in app.routes)
