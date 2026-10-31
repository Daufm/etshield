# EthioShield

EthioShield is an application security SDK and cloud platform foundation for
request protection, rate limiting, security telemetry, webhook verification,
and developer operations.

## Status

This repository is **experimental and not production-ready**. The initial
foundation contains versioned TypeScript contracts, a minimal Node.js SDK, and
an Express 5 playground. Security policies, cloud ingestion, account
management, and production operational guarantees are not implemented yet.

## Requirements

- Node.js 22 or newer
- npm 10 or newer

## Development

```bash
npm ci
npm run validate
```

The repository is an npm workspace monorepo. The initial package exports ESM
only; CommonJS compatibility is intentionally not claimed until it is built
and tested.

## Contract compatibility

Contracts use `major.minor` schema versions. A new major version may remove,
rename, or change the meaning of fields and must be rejected by consumers that
do not support it. A new minor version may add optional fields or enum values
only when consumers have a safe fallback; the current runtime validators reject
unsupported versions and unknown fields at trust boundaries. Policy documents
must validate completely before activation, and activation is atomic.

Telemetry contracts deliberately exclude API secrets, passwords, authorization
headers, cookies, payment secrets, and raw request bodies. Client timestamps,
forwarded headers, and fingerprints are untrusted metadata and must not be used
as authoritative identity or event time.

## Packages

- `@ethioshield/security-contracts`: shared event, decision, and policy types
- `@ethioshield/sdk-node`: experimental Node.js SDK
- `@ethioshield/playground`: minimal Express 5 application

The SDK includes an experimental local detection engine with separate
SQL-injection, NoSQL-injection, XSS, and path-traversal indicator detectors.
It inspects only the normalized route, query values, route parameters, and
body values supplied by the host application. Detection is heuristic and is
not a complete prevention mechanism for SQL injection, XSS, or other attacks.
The versioned detection contract is `1.0`. Existing detectors are exposed
through compatibility adapters, and custom synchronous plugins receive a
bounded, typed context containing the original request view, normalized
values, and a detection budget. Plugins return findings and evidence; they do
not apply enforcement policy. The engine never changes request values, and
callers must handle an error result conservatively according to their policy.

Normalization is bounded and non-mutating: scalar values are length-limited,
percent-decoded once, Unicode-normalized with NFKC, and lower-cased before
matching. Malformed encodings and safety-limit exhaustion produce an error
status rather than a clean result. Nested objects are traversed iteratively
with fixed depth, node, value, byte, cycle, and finding limits. Query, JSON,
route-parameter, and header parser adapters are exported for integrations that
need explicit parser boundaries. JSON text is parsed only through the explicit
bounded adapter; the SDK does not implicitly parse request body strings.
Header parsing exposes only bounded `user-agent`, `accept-language`, and
`content-type` values to plugins and excludes credentials and forwarding
headers.

The detectors use bounded structured parsing as their primary signal:
SQL indicators are tokenized with bounded comment handling, NoSQL indicators
inspect operator-shaped values, XSS indicators scan HTML-like tags and
dangerous schemes, and path traversal inspects normalized path segments.
Regexes remain supplementary heuristics where used. Findings are deduplicated
by stable evidence identifiers and include a qualitative confidence band;
confidence is not a calibrated probability. These request indicators cannot
prove exploitability without application or runtime sink context.

### Detection Engine v2 — Milestone 1

Milestone 1 establishes the contract and evidence baseline. Inspection results
now distinguish `complete`, `error`, and `inconclusive`; invalid plugin
findings are rejected; and the declared duration budget is cooperative rather
than a hard timeout. A synchronous detector cannot be interrupted by this
budget. These changes preserve existing detector rule IDs, ordering, finding
deduplication, and monitor/block behavior.

The current SQLi, NoSQLi, XSS, and path-traversal detectors remain heuristic
request indicators. They do not establish sink-level exploitability or provide
complete prevention. Detector limitations and known false-positive/false-
negative cases remain documented in this repository. Milestone 2 must address
Express body-state enforcement, parser ordering, exclusions, and fail-open/
fail-closed behavior before broader canonicalization work.

Milestone 1 verification:

- `npm run lint`: passed
- `npm run typecheck`: passed
- `npm test`: 66 tests passed
- `npm run test:integration`: 2 tests passed
- `npm run test:coverage`: configured thresholds passed
- `npm run build`: passed
- `npm run test:exports`: 2 tests passed
- `npm run check:artifacts`: passed

The repository-wide `npm run format:check` remains blocked by the two
pre-existing untracked audit Markdown files; the Milestone 1 source and package
documentation are formatted. No code change in this milestone changes Express
body parsing, route exclusions, or sink instrumentation.

### Detection Engine v2 — Milestone 3

Milestone 3 adds a bounded canonicalization/provenance record to each
normalized value. It preserves a bounded raw value, records the canonical
value's parser identity/version, one percent-decoding depth, transformation
provenance, duplicate-input status, truncation, and ambiguity. A valid
second-stage percent-encoding candidate produces an explicit
`ambiguous_representation` inspection error; the SDK does not decode until
stable or apply HTML, SQL, or filesystem-specific decoding globally.

This provenance is available to detection plugins and findings, while raw
values remain excluded from telemetry events. Parser and sink consistency
across a host application's proxy/parser stack remains a host integration
requirement.

### Detection Engine v2 — Milestone 4

The structured detector adapter milestone is complete. SQL, NoSQL, XSS, and
path-traversal detectors now consume bounded intermediate token/tag/operator/
segment representations. Existing rule IDs, detector ordering, deduplication,
confidence bands, and plugin compatibility are preserved. The adapters retain
explicit limitations and report request indicators only; they do not establish
sink-level exploitability or provide standalone vulnerability prevention.

### Detection Engine v2 — Sink observation and correlation

The SDK now exposes an explicit `correlateSinkObservation()` adapter. It
separates request indicators from sink observations and correlated
exploitability results. Correlation requires matching request and sink
correlation IDs plus a successfully delivered observer result. This remains a
host-invoked integration: the SDK does not monkey-patch runtime APIs, infer
sink calls, or treat an observer failure as a clean result.

### Detection Engine v2 — Stateful behavioral correlation hardening

Rate-limit and correlation keys now use bounded length-prefixed components,
preventing delimiter-based identity collisions. Local stores evict expired
entries before applying cardinality limits, while store errors retain the
configured deterministic monitor/block failure mode. Distributed deployments
must provide an atomic shared store with equivalent TTL and cardinality
semantics; IP remains one signal and is not treated as authenticated identity.

Detection output is evaluated separately from enforcement by the versioned
policy evaluator. Enabled rule settings select the action and optional
confidence threshold; disabled or below-threshold findings are ignored.
`monitor` enforcement downgrades block, throttle, and challenge actions to
monitor. Inspection errors produce a fail-safe block under enforcing policy
and monitor under monitor policy. The Express SDK remains monitor-by-default;
passing `mode: 'block'` explicitly enables enforcing behavior for middleware.
Challenge decisions still require a host-provided challenge adapter.

## Express integration

The SDK supports Express 5.x. Mount `express.json()` or another bounded,
application-owned parser before `protect()` when parsed JSON or URL-encoded
values should be inspected:

```ts
app.use(express.json({ limit: '1mb' }));
app.use(shield.protect());
```

`protect()` never reads a request stream, buffers a body, or parses a body a
second time. It records the body boundary as `absent`, `parsed`, `malformed`,
`unavailable`, or `streaming`. If it is mounted before a parser and a relevant
body is unavailable, monitor mode continues with a non-clean inspection
decision; block mode returns `503` and does not pass the request to the
application. Multipart, streaming, and already-consumed bodies require an
explicit safe parser integration and are not parsed by this SDK. Configure
parser limits independently.

The default mode is `monitor`; detected requests continue to the application
with a structured decision hook and an `x-ethioshield-action` response header.
`block` mode returns a generic `403` for findings and `503` when inspection
fails. Response bodies do not include request payloads or internal errors.
Telemetry failures and decision-hook failures are reported through `onError`
when supplied, but never change the request decision.

Route exclusions are exact routes or bounded prefix patterns ending in `/*`.
They may be scoped to specific HTTP methods. Excluded requests skip detector
execution but produce an explicit `policy.route_exclusion` decision and
telemetry event. Exclude only narrowly controlled health or infrastructure
endpoints. Exclusions are validated at construction; a method-scoped exclusion
does not bypass protection for other methods.

Client IP metadata is omitted by default. Forwarded headers are ignored unless
the immediate socket peer matches an explicitly configured IP allowlist in
`trustedProxy`; even then only a valid first `X-Forwarded-For` address is
accepted. Header values are never used as authentication.

Roll out safely by starting in `monitor`, reviewing sanitized findings and
false positives, then enabling `block` for narrowly scoped routes and rules.

## Rate limiting and network risk

The SDK supports layered rate-limit keys for explicitly supplied authenticated
user IDs, verified API-key IDs, session IDs, target account IDs, route, trusted
client IP, and optional network labels. Identity values must come from the
`trustedIdentity` host callback; arbitrary request headers are not accepted.
Client IP values are available only when an explicitly trusted proxy is
configured.

The MVP uses bounded fixed-window counters. An injected `AtomicCounterStore`
is required for atomic multi-instance enforcement; the built-in
`InMemoryAtomicCounterStore` is intended only for single-process development
and tests. Counter keys have bounded cardinality, windows have TTLs, and
store outages follow each policy's configured `failureMode`.

Stateful correlation is separately configurable through policy correlation
rules. It supports trusted authenticated-user and target-account dimensions,
route, and IP as an additional dimension. Rules can be scoped to a route and
network-risk threshold. The bounded `InMemoryCorrelationStore` is intended
only for single-process development and tests; multi-instance deployments
must provide a shared atomic `CorrelationStore`. Missing trusted identity
values do not fall back to IP alone for identity correlation, and correlation
store cardinality failures follow the configured deterministic failure mode.

`NetworkIntelligenceResolver` is optional and returns expiring,
provenance-bearing risk signals. VPN, proxy, Tor, hosting, and residential
classification is only a risk signal: VPN usage alone never blocks a request,
and network intelligence is not authentication. Local detection and rate
limits continue when the resolver is unavailable or stale.

Rate-limit rules may return `monitor`, `throttle`, or `block`. `challenge`
requires an explicit host `ChallengeAdapter`; no challenge provider is bundled.
The MVP does not include a paid intelligence provider, ASN database, cloud
counter service, dashboard, billing, or persistent device fingerprinting.
Future work may add those behind explicit approvals and privacy review.

## Operational hardening and release guidance

Coverage is measured with the pinned Vitest V8 provider:

```bash
npm run test:coverage
```

The configured minimums are 70% for statements, lines, and functions, and 60%
for branches. Coverage is a signal for test completeness, not a security
guarantee; adversarial and integration tests remain required.

Before a release, run:

```bash
npm run validate
npm run test:coverage
npm run test:exports
npm run check:artifacts
npm run audit:production
```

Production audit policy fails on high or critical vulnerabilities in runtime
dependencies. Full development-dependency audit results are tracked
separately with `npm run audit:full`; development-tool findings must be
reviewed before promoting a release candidate. Dependabot is configured for
weekly npm update proposals.

The package export and artifact checks verify ESM entry points, declaration
files, and npm dry-run contents. Source and test files must not be included in
published artifacts. Performance and memory regression tests assert bounded
normalization output and local processing budgets, but they are not production
capacity benchmarks.

Operational qualification also exercises sustained bounded inspections and a
staged monitor-to-enforce policy transition. These tests verify stable
decision semantics and resource bounds; they do not establish throughput,
latency SLOs, detector recall, or production capacity. A release candidate
must pass the full validation commands above plus the adversarial and
integration suites. The repository's full development audit may still report
tooling vulnerabilities and must be reviewed separately from the production
dependency audit.

Roll out in stages: run monitor mode in a representative environment, review
sanitized decisions and false positives, configure bounded parser limits and
shared atomic stores, then enable narrowly scoped throttle or block rules.
Keep an application-level emergency disable path, monitor inspection errors,
store outages, callback timeouts, memory pressure, and event volume. Do not
represent this experimental SDK as a complete WAF or as proof that an input
indicator is exploitable.

## Runtime instrumentation

Instrumentation is opt-in and host-invoked through `InstrumentationHub`; the
SDK never monkey-patches global database, network, filesystem, process, or
authorization APIs. The hub exposes typed observers for SQL, outbound HTTP,
filesystem, command execution, and authorization decisions. Observations use
sanitized classifications and a per-request correlation ID rather than raw
queries, credentials, paths, command arguments, cookies, or request bodies.
Observer calls are bounded by a configurable timeout of at most one second
(100 ms by default), and observer errors return isolated failure results
without changing application behavior.

The Express middleware generates one correlation ID per request. It is
available in `DecisionContext.correlationId`, in the detection plugin context,
and through `shield.getCorrelationId(request)` for host instrumentation code.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting guidance.
