"""The legacy client: sessions, concurrency, retries, the breaker, and safe envelopes."""

import asyncio

import pytest

from turnstile.gateway.pas_client import LegacyError, record
from turnstile.legacy.soap import MAX_CONCURRENT, Faults
from turnstile.stack import local_stack


def _policy(st):
    return next(iter(st.legacy.policies.values()))


def test_logs_in_once_and_again_when_the_ticket_expires():
    st = local_stack()
    p = _policy(st)

    async def go():
        await st.pas.call("GetPolicy", PolicyNo=p.policy_no)
        await st.pas.call("GetPolicy", PolicyNo=p.policy_no)
        assert st.pas.stats.logins == 1
        st.legacy.tickets.clear()  # every ticket expires
        r = await st.pas.call("GetPolicy", PolicyNo=p.policy_no)
        assert st.pas.stats.logins == 2
        return r

    assert record(asyncio.run(go()).find("{urn:pas}Policy"))["PolicyNo"] == p.policy_no


def test_never_exceeds_the_legacy_concurrency_limit():
    st = local_stack(faults=Faults(latency_ms=(5, 15)), max_concurrency=3)
    p = _policy(st)

    async def go():
        await asyncio.gather(*(st.pas.call("GetPolicy", PolicyNo=p.policy_no) for _ in range(30)))

    asyncio.run(go())
    assert st.legacy.peak_in_flight <= 3 < MAX_CONCURRENT + 1


def test_reads_retry_transient_faults():
    st = local_stack(faults=Faults(error_rate=0.4, seed=3), read_retries=4, backoff_s=0)
    p = _policy(st)

    async def go():
        for _ in range(10):
            await st.pas.call("GetPolicy", PolicyNo=p.policy_no)

    asyncio.run(go())
    assert st.pas.stats.retries > 0


def test_writes_are_never_retried():
    st = local_stack(faults=Faults(lose_response_after_write=True), read_retries=4, backoff_s=0)
    p = next(x for x in st.legacy.policies.values() if x.status == "A")
    before = len(p.claims)

    async def go():
        with pytest.raises(LegacyError) as err:
            await st.pas.call(
                "FileClaim",
                PolicyNo=p.policy_no,
                LossDate="20250501",
                Description="Test",
                AmountCents="100",
            )
        return err.value

    assert asyncio.run(go()).code == "Timeout"
    assert len(p.claims) == before + 1  # written once, and not again by a retry


def test_breaker_opens_and_fails_fast():
    st = local_stack(faults=Faults(down=True), read_retries=0, breaker_threshold=3)
    p = _policy(st)

    async def go():
        codes = []
        for _ in range(6):
            try:
                await st.pas.call("GetPolicy", PolicyNo=p.policy_no)
            except LegacyError as e:
                codes.append(e.code)
        return codes

    codes = asyncio.run(go())
    assert codes[:3] == ["HTTP503"] * 3 and set(codes[3:]) == {"CircuitOpen"}
    assert st.pas.stats.breaker_rejections == 3


def test_client_faults_do_not_trip_the_breaker():
    st = local_stack(read_retries=0, breaker_threshold=2)

    async def go():
        for _ in range(5):
            with pytest.raises(LegacyError):
                await st.pas.call("GetPolicy", PolicyNo="AU00000000")

    asyncio.run(go())
    assert not st.pas.breaker_open  # "not found" means the service is healthy


def test_values_cannot_change_the_envelope():
    st = local_stack()
    p = next(x for x in st.legacy.policies.values() if x.status == "A")

    async def go():
        return await st.pas.call(
            "FileClaim",
            PolicyNo=p.policy_no,
            LossDate="20250501",
            Description="x</Description><AmountCents>999</AmountCents>",
            AmountCents="100",
        )

    asyncio.run(go())
    assert p.claims[-1].amount_cents == 100
    assert p.claims[-1].description.startswith("x</Description>")
