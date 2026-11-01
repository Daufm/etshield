# @ethioshield/sdk-node

Experimental Node.js and Express 5 SDK for local application security
indicators, policy evaluation, rate limiting, correlation, and opt-in
instrumentation.

This package is not production-ready. Review the repository
[README](../../README.md) for middleware ordering, trust boundaries, rollout
guidance, and known limitations before using it.

Operational qualification tests cover sustained bounded requests and a
monitor-to-enforce rollout transition. They are regression gates, not
production capacity benchmarks or security effectiveness measurements.

## Detection contract baseline

The detection engine returns `complete`, `error`, or `inconclusive` inspection
states. Detector exceptions, invalid plugin findings, malformed input, and
normalization limits are non-clean outcomes. `maxDurationMs` is a cooperative
budget checked between detector executions; it is not a hard timeout and cannot
interrupt synchronous JavaScript. Hard interruption would require a separately
approved worker or process isolation design.

Each result also has an additive `outcome`: `clean` means no indicator or
inspection problem was observed, `indicator` means at least one finding was
produced, `degraded` means inspection continued with a bounded limitation
(`normalization_limit`, `ambiguous_representation`, or `body_unavailable`), and
`failed` means inspection encountered an error. Findings are evaluated before
these fallback states, so an indicator is not discarded merely because the
same request was truncated or ambiguous.

For Express, `inspection.degradedAction` can be set to `monitor` (the default)
or `block`. Blocking degraded requests returns `503 Security inspection
incomplete` when no finding applies. This is a deliberate latency and
availability trade-off: padding a request beyond the normalization cap can
otherwise evade blocking of content that was not inspected. Body-unavailable
requests retain the existing fail-closed behavior in block mode.

Findings are request indicators, not proof that an exploit reached a database,
HTML output, filesystem, command, or outbound HTTP sink. Sink-level
exploitability requires explicit host integration and is not implemented by
this package.

The Express middleware records body availability at its inspection boundary.
Relevant bodies that are absent from the parser boundary are non-clean:
monitor mode continues with an `inspection_failed` decision, while block mode
returns a controlled `503`. The middleware does not read or replay streams.
Route exclusions skip detector execution but emit an explicit exclusion
decision and telemetry event.

Milestone 3 adds bounded provenance to normalized values: raw bounded input,
canonical value, one explicit percent-decoding depth, transformation names,
parser identity/version, duplicate-input status, truncation, and ambiguity.
Values that still contain a valid percent-encoded representation after the
allowed decode pass are reported as ambiguous rather than treated as clean.
The SDK does not globally decode HTML entities, SQL literals, or filesystem
paths. Raw values remain in the in-process detection context only and are not
included in security events.

The structured detector adapters use bounded intermediate parsing rather than
one broad regular expression per detector. SQL input is tokenized with bounded
comment and quote handling; NoSQL input recognizes an allowlisted operator
grammar; HTML input is scanned into bounded tags and executable attributes;
and path input is split into bounded platform-neutral segments. These are
request indicators only, not proof of sink-level exploitability or prevention.

Host applications can use `correlateSinkObservation()` with an explicit
instrumentation result to distinguish request-only indicators from correlated
sink observations. Correlation requires the same request correlation ID and a
successfully delivered observer result. Observer errors, timeouts, mismatched
IDs, or absent sink observations never upgrade a request indicator. The
correlator consumes sanitized sink classifications and does not accept query
text, request bodies, command arguments, or other raw secrets.

Rate-limit and behavioral-correlation keys use bounded length-prefixed
components, so delimiter-bearing identities cannot collide with another
dimension combination. The in-memory stores lazily evict expired entries before
enforcing their cardinality limit. Shared deployments still require an atomic
store with equivalent TTL, cardinality, and failure semantics.
