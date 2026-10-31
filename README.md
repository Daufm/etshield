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

## Express integration

The SDK supports Express 5.x. Mount `express.json()` or another bounded,
application-owned parser before `protect()` when parsed JSON or URL-encoded
values should be inspected:

```ts
app.use(express.json({ limit: '1mb' }));
app.use(shield.protect());
```

`protect()` never reads a request stream, buffers a body, or parses a body a
second time. If it is mounted before a parser, the body is intentionally not
inspected. Multipart, streaming, and already-consumed bodies require an
explicit safe parser integration and are not parsed by this SDK. Configure
parser limits independently.

The default mode is `monitor`; detected requests continue to the application
with a structured decision hook and an `x-ethioshield-action` response header.
`block` mode returns a generic `403` for findings and `503` when inspection
fails. Response bodies do not include request payloads or internal errors.
Telemetry failures and decision-hook failures are reported through `onError`
when supplied, but never change the request decision.

Route exclusions are exact routes or bounded prefix patterns ending in `/*`.
They may be scoped to specific HTTP methods. They bypass detection and
telemetry, so exclude only narrowly controlled health or infrastructure
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

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting guidance.
