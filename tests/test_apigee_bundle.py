"""The Apigee proxy bundle is consistent with itself and with the gateway behind it.

apigeelint checks Apigee's own rules in CI; these tests check what it cannot know: that the
edge limits leave room for every legitimate gateway request, and that the API key never
reaches the gateway.
"""

import xml.etree.ElementTree as ET
from pathlib import Path

from turnstile.gateway import core

BUNDLE = Path(__file__).resolve().parents[1] / "apigee" / "apiproxy"


def _xml(path: Path) -> ET.Element:
    return ET.parse(path).getroot()


def _policy_files() -> dict[str, ET.Element]:
    return {p.stem: _xml(p) for p in (BUNDLE / "policies").glob("*.xml")}


def test_every_policy_is_declared_and_every_declared_policy_exists():
    declared = {p.text for p in _xml(BUNDLE / "turnstile.xml").find("Policies")}
    files = _policy_files()
    assert declared == set(files)
    for name, root in files.items():
        assert root.get("name") == name  # file name, root name and reference all agree


def test_every_step_refers_to_a_real_policy():
    files = set(_policy_files())
    for endpoint in [BUNDLE / "proxies" / "default.xml", BUNDLE / "targets" / "default.xml"]:
        steps = {n.text for n in _xml(endpoint).iter("Name")}
        assert steps <= files, steps - files


def test_api_key_is_checked_first_and_removed_before_the_target():
    order = [
        n.text
        for n in _xml(BUNDLE / "proxies" / "default.xml").find("PreFlow/Request").iter("Name")
    ]
    assert order.index("VA-VerifyAPIKey") < order.index("SA-SpikeArrest")
    assert order.index("VA-VerifyAPIKey") < order.index("Q-DailyQuota")
    assert "AM-StripAPIKey" in order
    removed = [h.get("name") for h in _policy_files()["AM-StripAPIKey"].iter("Header")]
    assert removed == ["x-api-key"]


def test_threat_protection_leaves_room_for_legitimate_requests():
    jtp = _policy_files()["JTP-JSONThreatProtection"]
    longest_legitimate = core.DESCRIPTION_RANGE[1]
    assert int(jtp.findtext("StringValueLength")) >= longest_legitimate
    assert int(jtp.findtext("StringValueLength")) <= 10_000  # but still bounds abuse
    assert int(jtp.findtext("ContainerDepth")) >= 5  # JSON-RPC envelope plus arguments


def test_rate_limits_are_per_app_and_answer_with_429():
    files = _policy_files()
    for name in ("SA-SpikeArrest", "Q-DailyQuota"):
        ident = files[name].find("Identifier").get("ref")
        assert ident == "verifyapikey.VA-VerifyAPIKey.client_id"
    assert files["AM-RateLimitedResponse"].findtext("Set/StatusCode") == "429"


def test_the_target_does_not_replace_the_agent_authorization():
    target = _xml(BUNDLE / "targets" / "default.xml")
    assert target.find(".//Authentication") is None  # the gateway verifies the agent's token
    assert target.findtext(".//Path") == "/mcp"
    assert target.findtext(".//SSLInfo/Enforce") == "true"
    assert target.find(".//LoadBalancer/Server").get("name") == "turnstile-gateway"


def test_threat_protection_only_runs_on_requests_with_a_body():
    steps = _xml(BUNDLE / "proxies" / "default.xml").find("PreFlow/Request")
    jtp = next(s for s in steps if s.findtext("Name") == "JTP-JSONThreatProtection")
    assert jtp.findtext("Condition") == "request.content != null"
