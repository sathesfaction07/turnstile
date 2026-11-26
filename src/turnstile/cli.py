"""Command line: run the legacy mock and the gateway, write the attack report."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _serve_legacy(args: argparse.Namespace) -> int:
    import uvicorn

    from turnstile.legacy.soap import Faults, LegacySystem, create_app

    faults = Faults(latency_ms=(args.min_latency_ms, args.max_latency_ms))
    print(f"Legacy policy system (mock) on http://127.0.0.1:{args.port}/pas")
    uvicorn.run(create_app(LegacySystem(faults=faults)), host="127.0.0.1", port=args.port)
    return 0


def create_gateway_app():
    """Build the gateway from the environment (used by the Dockerfile)."""
    from turnstile.gateway.core import AuditLog, Gateway
    from turnstile.gateway.identity import Registry
    from turnstile.gateway.mcp_app import create_app
    from turnstile.gateway.pas_client import PasClient
    from turnstile.stack import DEV_AGENTS

    agents_file = os.environ.get("TURNSTILE_AGENTS_FILE", "")
    registry = (
        Registry.from_json(Path(agents_file)) if agents_file else Registry.from_tokens(DEV_AGENTS)
    )
    pas = PasClient(
        base_url=os.environ.get("LEGACY_URL", "http://127.0.0.1:8090"),
        user=os.environ.get("LEGACY_USER", "svc_gateway"),
        password=os.environ.get("LEGACY_PASSWORD", "legacy-password"),
    )
    resource = os.environ.get("TURNSTILE_RESOURCE_URL", "http://127.0.0.1:8080/mcp")
    return create_app(Gateway(pas, AuditLog()), registry, resource_url=resource)


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    os.environ.setdefault("LEGACY_URL", args.legacy_url)
    os.environ.setdefault("TURNSTILE_RESOURCE_URL", f"http://127.0.0.1:{args.port}/mcp")
    if args.agents:
        os.environ["TURNSTILE_AGENTS_FILE"] = args.agents
    print(f"Turnstile MCP gateway on http://127.0.0.1:{args.port}/mcp")
    uvicorn.run(create_gateway_app(), host="127.0.0.1", port=args.port)
    return 0


def _report(args: argparse.Namespace) -> int:
    import logging

    from turnstile import attacks

    for name in ("httpx", "httpx2", "mcp", "uvicorn"):
        logging.getLogger(name).setLevel(logging.WARNING)
    results = asyncio.run(attacks.run_suite())
    overhead = asyncio.run(attacks.measure_overhead(args.calls))
    stopped = [r for r in results if r["kind"] == "attack"]
    legit = [r for r in results if r["kind"] == "legitimate"]
    lines = [
        "# Attack report",
        "",
        "Every case runs through the real MCP server over HTTP against the legacy mock, each on "
        "a fresh system. Regenerate with `turnstile report`.",
        "",
        f"- **Attacks stopped:** {sum(r['passed'] for r in stopped)} of {len(stopped)}",
        f"- **Legitimate workflows allowed:** {sum(r['passed'] for r in legit)} of {len(legit)}",
        "",
        "| Case | Kind | Defence | Result |",
        "|:--|:--|:--|:--|",
        *(
            f"| {r['name']} | {r['kind']} | {r['defence'] or '-'} | "
            f"{'as expected' if r['passed'] else 'FAILED ' + r['note']} |"
            for r in results
        ),
        "",
        "## What the gateway adds to each call",
        "",
        f"{overhead['n']} `get_policy` calls, locally, with no injected legacy latency: the legacy "
        "client alone, then the full path (MCP over HTTP, auth, scope and rate checks, "
        "validation, redaction, audit).",
        "",
        "| | p50 | p95 |",
        "|:--|--:|--:|",
        f"| Legacy client alone | {overhead['direct_p50_ms']} ms | "
        f"{overhead['direct_p95_ms']} ms |",
        f"| Through the gateway | {overhead['gateway_p50_ms']} ms | "
        f"{overhead['gateway_p95_ms']} ms |",
        "",
        f"The gateway adds about {overhead['added_p50_ms']} ms at the median on this machine. "
        "The legacy mock's default latency is 80-300 ms per call (`turnstile serve-legacy`), a "
        "stand-in for the real system, which was not measured here.",
    ]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(lines))
    return 0 if all(r["passed"] for r in results) else 1


def _hash(args: argparse.Namespace) -> int:
    from turnstile.gateway.identity import token_hash

    print(json.dumps({"token_sha256": token_hash(args.token)}))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="turnstile")
    sub = p.add_subparsers(dest="cmd", required=True)
    leg = sub.add_parser("serve-legacy", help="run the mock policy system")
    leg.add_argument("--port", type=int, default=8090)
    leg.add_argument("--min-latency-ms", type=int, default=80)
    leg.add_argument("--max-latency-ms", type=int, default=300)
    gw = sub.add_parser("serve", help="run the MCP gateway")
    gw.add_argument("--port", type=int, default=8080)
    gw.add_argument("--legacy-url", default="http://127.0.0.1:8090")
    gw.add_argument("--agents", default="", help="agent registry JSON (default: dev agents)")
    rp = sub.add_parser("report", help="run the attack suite and write the report")
    rp.add_argument("--calls", type=int, default=200)
    rp.add_argument("--out", default=str(ROOT / "reports" / "attack-report.md"))
    hs = sub.add_parser("hash-token", help="print the registry hash for a token")
    hs.add_argument("token")
    args = p.parse_args(argv)
    return {"serve-legacy": _serve_legacy, "serve": _serve, "report": _report, "hash-token": _hash}[
        args.cmd
    ](args)


if __name__ == "__main__":
    sys.exit(main())
