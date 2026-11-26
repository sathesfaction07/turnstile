# Engagement readout: Turnstile

This readout treats the project as a customer engagement: how it was scoped, what was built,
how it was proven and how it rolls out. The customer is a composite, a mid-sized insurer, not
a named company. All policy data is synthetic. Numbers marked **measured** come from this
repository and can be reproduced; everything else is labelled as a plan or an estimate.

## The customer and what they asked for

Three teams at the insurer were building agents: claims intake, a service desk, and portfolio
analytics. All three needed the policy administration system, a SOAP service from the late
2000s that no one wants to change. Security had blocked each team's plan to connect directly.

**The ask:** "Help our teams connect their agents to the policy system."

## What discovery found

| Observed | What it meant |
|:--|:--|
| Each team planned its own SOAP client with the shared service account | No way to tell which agent did what, and three copies of every mistake |
| Every agent would get every field, including full SSNs | Field-level access had to depend on who is asking. The analytics agent needs no personal data at all |
| `FileClaim` files a duplicate when retried, and responses sometimes time out after the write | Retrying writes is unsafe. A lost response has to be resolved by looking, not by asking again |
| The system refuses everyone once it has more than 4 concurrent requests | Agent bursts would take it down for the human staff too. Concurrency must be capped in front of it |
| Policy notes contain customers' pasted emails, some written to manipulate whoever reads them | Free text must reach the model labelled as untrusted data |
| Legacy search is slow and unpaged; the data team already exports a nightly CSV | Search the extract, read live records, and say how old search results are |
| The platform team already runs Apigee for partner APIs | Team-level keys and quotas belong at the edge they already operate; agent-level rules belong in the gateway |

**Deliberately not built:**
- New write operations beyond claims and addresses. Each needs its own business owner.
- Any change to the legacy system. Not possible, and not needed.
- A per-team UI. Each team keeps its own agent; the gateway is shared infrastructure.

## What was delivered

- **An MCP gateway with seven tools.** Agents authenticate with their own tokens, scopes decide
  which tools they may call, and identity decides which fields they see. A full SSN never
  leaves the gateway.
- **Two-step writes.** Prepare returns a summary and a confirmation; submit only works with
  that confirmation, once, and only for the agent that prepared it.
- **Reconciliation for the non-idempotent claim write**, so a lost response never becomes a
  duplicate claim.
- **A legacy client** with session handling, a concurrency cap below the system's limit, retries
  for reads only, and a circuit breaker.
- **An audit record of every call:** agent, tool, outcome, legacy calls made, latency, and no
  personal data.
- **An Apigee proxy, Cloud Run service, secrets and private egress**, all described as code.
- **A claims-intake agent on Google ADK** that knows only the gateway, as the reference for the
  teams.

## Proof that it works

| Claim | Evidence | Reproduce |
|:--|:--|:--|
| Attacks are stopped without blocking real work | **Measured:** 16 of 16 attacks stopped and 5 of 5 legitimate workflows allowed, through the real MCP server over HTTP | `turnstile report` |
| The legacy system is protected from agent bursts | **Measured:** at most 3 concurrent requests reach it while 30 are in flight | `pytest tests/test_pas_client.py` |
| A lost claim response never becomes a duplicate | **Measured:** one claim after a lost response, including when the first reconciliation misses and the agent submits again | `pytest tests/test_gateway.py` |
| Identity comes from the token, not the model | The ADK agent's calls are all audited as `claims-intake-agent`; with the analytics token the same agent cannot file | `pytest tests/test_adk_agent.py` |
| The gateway is cheap per call | **Measured:** about 2.4 ms added at the median on a laptop | `turnstile report` |
| The edge and the gateway agree | The Apigee limits leave room for every legitimate request, and the API key is removed before the gateway | `pytest tests/test_apigee_bundle.py`, apigeelint in CI |

## What is not yet proven

- **Behaviour against the real system.** The mock reproduces the quirks discovery found, but
  real latency, fault rates and concurrency behaviour come from the shadow phase below.
- **Model behaviour with real customers.** The ADK agent is tested with a scripted model. How
  often Gemini gets a first notice of loss right, and how it handles the poisoned notes, is the
  same kind of measurement as in the Handoff project. It is the next step for the claims team,
  not for the gateway.

## Rollout plan

| Phase | What changes | Gate to move on |
|:--|:--|:--|
| 1. Read-only shadow | The gateway goes live against the real system for the analytics agent only, with no writes | A week with no `SystemBusy` caused by agent traffic; real latency measured; every audit record complete |
| 2. Claims intake, human submit | The claims agent prepares claims; a human adjuster presses submit | Adjusters accept most prepared claims unchanged; every rejected one is reviewed |
| 3. Claims intake, customer confirms | The agent submits after the customer's explicit confirmation | Weekly sample of filed claims matches the customer's account of the loss; no duplicate claims |
| 4. Service desk | Address changes, with confirmation | Same gates, owned by the service desk lead |

## Risks and open items

- **One instance.** The legacy concurrency cap is per process, so the gateway runs as one
  instance. More capacity needs a shared limiter, such as a Redis semaphore.
- **Static tokens.** These are for development only. Production uses the identity provider's
  tokens, with JWT verification in the `TokenVerifier`.
- **The tool list is not filtered by identity.** Calls outside an agent's scope are refused, but
  the agent can still see that those tools exist.

## Feedback for the product team

- **Per-identity tool lists:** MCP servers commonly need to show each client only the tools it
  may call. A first-class hook in the SDK's tool listing, keyed by the verified token, would
  make least privilege the default.
- **Confirmed writes as a pattern:** ADK has tool confirmation for a human in the loop. A
  matching server-side primitive (a confirmation id bound to a principal, single use) would let
  gateways enforce what the agent framework asks for.
- **Non-idempotent backends:** most legacy systems have writes like `FileClaim`. A documented
  reconcile-don't-retry pattern for MCP tools would save every team from learning it from a
  duplicate claim.
