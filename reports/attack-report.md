# Attack report

Every case runs through the real MCP server over HTTP against the legacy mock, each on a fresh system. Regenerate with `turnstile report`.

- **Attacks stopped:** 16 of 16
- **Legitimate workflows allowed:** 5 of 5

| Case | Kind | Defence | Result |
|:--|:--|:--|:--|
| No token | attack | 401 before any tool runs | as expected |
| Forged token | attack | 401 before any tool runs | as expected |
| Read-only agent tries to file a claim | attack | scope check | as expected |
| Claims agent tries to change an address | attack | scope check | as expected |
| Analytics agent reads personal data | attack | PII redaction by identity | as expected |
| Any agent asks for the full SSN | attack | SSN never leaves the gateway | as expected |
| XML injected into a policy number | attack | strict input validation | as expected |
| Envelope injection in a claim description | attack | values escaped; injected tags stay literal text | as expected |
| Wildcard search to enumerate customers | attack | name pattern, DOB required | as expected |
| Claim above the automatic limit | attack | amount ceiling | as expected |
| Oversized description (100 KB) | attack | length limit | as expected |
| Submit with a made-up confirmation id | attack | confirmation required | as expected |
| Submit another agent's confirmation | attack | confirmation bound to its agent | as expected |
| Replay a submitted claim | attack | single-use confirmation; never files twice | as expected |
| Burst of 40 calls from one agent | attack | per-agent rate limit | as expected |
| Instructions planted in policy notes | attack | notes returned as labelled untrusted data | as expected |
| Find a policy by name and date of birth | legitimate | - | as expected |
| Read a policy and its claims | legitimate | - | as expected |
| File a claim with confirmation | legitimate | - | as expected |
| Change an address with confirmation | legitimate | - | as expected |
| Service agent sees full contact details | legitimate | - | as expected |

## What the gateway adds to each call

200 `get_policy` calls, locally, with no injected legacy latency: the legacy client alone, then the full path (MCP over HTTP, auth, scope and rate checks, validation, redaction, audit).

| | p50 | p95 |
|:--|--:|--:|
| Legacy client alone | 0.35 ms | 0.38 ms |
| Through the gateway | 2.74 ms | 3.26 ms |

The gateway adds about 2.39 ms at the median on this machine. The legacy mock's default latency is 80-300 ms per call (`turnstile serve-legacy`), a stand-in for the real system, which was not measured here.
