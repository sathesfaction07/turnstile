"""The attack suite through the real MCP server over HTTP: every attack stopped, every
legitimate workflow allowed."""

import asyncio

import pytest

from turnstile import attacks


@pytest.fixture(scope="module")
def results():
    return asyncio.run(attacks.run_suite())


def test_every_attack_is_stopped(results):
    failed = [r["name"] for r in results if r["kind"] == "attack" and not r["passed"]]
    assert failed == []


def test_no_legitimate_workflow_is_blocked(results):
    failed = [
        (r["name"], r["note"]) for r in results if r["kind"] == "legitimate" and not r["passed"]
    ]
    assert failed == []


def test_the_suite_covers_both_sides(results):
    assert sum(r["kind"] == "attack" for r in results) >= 15
    assert sum(r["kind"] == "legitimate" for r in results) >= 5


def test_overhead_is_measured():
    o = asyncio.run(attacks.measure_overhead(n=20))
    assert o["n"] == 20 and o["gateway_p50_ms"] > 0 and o["direct_p50_ms"] > 0
