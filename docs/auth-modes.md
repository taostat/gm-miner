# gm-miner auth modes

Each upstream provider on a gm miner can be authenticated one of two ways.
The wire shape is the operator's choice — the registry sees only the
provider's normal API responses.

| Mode | Source of credentials | Selected by | Phase |
|------|-----------------------|-------------|-------|
| API key (default) | Provider's developer console | `gm-miner set-api-keys` | GA |
| OAuth subscription | Personal `ChatGPT` Plus / Claude Pro/Max account | `gm-miner deploy --paste-{codex,claude}-auth` | A — manual paste |

The default — and the only mode covered by the registry's published price
guidance — is API key. The OAuth subscription mode is experimental: it
lets an operator point the miner at a personal subscription's quota
instead of paying per-token, but it comes with caveats spelled out below.

## Manual-paste UX (Phase A)

The Phase A implementation does not run the OAuth flow inside the gm-miner CLI.
Instead, the operator runs an OAuth-capable CLI on their own laptop, completes
the flow there, and pastes the resulting `auth.json` (or `~/.claude/.credentials.json`)
file into the deploy command:

```bash
# Claude Pro / Claude Max
gm-miner deploy \
  --paste-claude-auth ~/.claude/.credentials.json \
  ...other flags...

# ChatGPT Plus / Codex
gm-miner deploy \
  --paste-codex-auth ~/.codex/auth.json \
  ...other flags...
```

Either flag triggers a one-time terms-of-service confirmation banner before the
deploy proceeds; the operator must type `I understand` verbatim. The parsed
refresh token, initial access token, and expiry timestamp are written into the
encrypted `phala deploy` env file as three sealed variables per provider:

```text
GM_ANTHROPIC_OAUTH_REFRESH_TOKEN=...
GM_ANTHROPIC_OAUTH_INITIAL_ACCESS_TOKEN=...
GM_ANTHROPIC_OAUTH_EXPIRES_AT=<RFC 3339>
```

The variable names mirror Phase B (native OAuth inside the CVM) so the
in-CVM consumer surface does not change when the manual-paste step is later
retired.

### Accepted file shapes

`--paste-*-auth` accepts three layouts defensively:

| Layout | Field shape | Source CLI |
|--------|-------------|------------|
| Flat snake_case | `access_token`, `refresh_token`, `expires_at` (seconds) | Codex CLI |
| Flat camelCase | `accessToken`, `refreshToken`, `expiresAt` (ms) | Claude Code |
| Nested | `{ "openai-codex": {...}, "anthropic": {...} }` | Hermes `auth.json` |

`expires_at` may be RFC 3339, seconds-since-epoch, or milliseconds-since-epoch.
The parser normalises to RFC 3339 before emitting the env var.

See `docs/research/oauth-subscription-prior-art.md` for the source wire shapes
and OAuth endpoint details.

## Terms-of-service caveat

Using a personal `ChatGPT` Plus or Claude Pro/Max subscription to serve
third-party gm traffic may violate the provider's terms of service. The exact
provisions vary between providers and may change at any time without notice.
gm provides the technical rails; ToS compliance is the operator's
responsibility. The CLI's confirmation banner exists to make that boundary
explicit before any deploy that wires a paste flag.

A revoked subscription token, a rate-limited 429, or a provider-side policy
change is the operator's responsibility to detect and recover from.

## In-CVM refresh worker (Phase A)

Phase A ships the manual paste UX above plus an in-CVM sidecar process
(`gm-miner-auth-sidecar`) that refreshes the access token before it
expires. The operator pastes once at deploy; the sidecar keeps the
token live without intervention as long as the refresh token remains
valid (typically months — providers rotate the refresh token on every
refresh and the sidecar honours the rotation in memory).

The sidecar runs as a third process alongside `envoy` and
`gm-miner-attestd` inside the same TEE container. It is only launched
when at least one provider is in `oauth_subscription` mode; api-key-
only deployments skip it.

### Wire shape

| Surface | Bound | Purpose |
|---------|-------|---------|
| `GET 127.0.0.1:7100/token/{provider}` | loopback | Envoy fetches the current bearer token on every data-plane request via a per-route Lua filter |
| `GET 127.0.0.1:7101/metrics` | loopback | Prometheus text exposition of `gm_miner_oauth_*` series, federated by the data-plane `metrics` listener at `/sidecar/metrics` |
| `GET 127.0.0.1:7100/healthz` | loopback | Always 200 |

### Refresh schedule

* Refresh skew: 120 seconds before `expires_at` (matches Hermes per
  `docs/research/oauth-subscription-prior-art.md`).
* Retry budget on failure: 3 retries with exponential backoff
  (2s → 4s → 8s, capped at 60s) and ±25% jitter.
* Once the budget is exhausted the provider is marked unhealthy and
  Envoy's OAuth route returns 503 for that provider's traffic until a
  later probe succeeds. The gateway's capacity router and the registry
  probe both treat 503 from a miner as "provider unavailable", so the
  routing layer drops the dead provider until the sidecar recovers.
* While the provider is unhealthy the sidecar continues to probe on a
  slow 5-minute cadence — a transient upstream blip recovers without
  operator intervention.

### Observability

The metrics surface lives under the same `x-gm-node-key`-gated metrics
URL operators already scrape. Two paths are reachable:

| Path | Source | Notes |
|------|--------|-------|
| `/stats/prometheus` | Envoy admin | Existing envoy counters, unchanged |
| `/sidecar/metrics` | auth sidecar | `gm_miner_oauth_*` series — only meaningful in OAuth-subscription mode |

Series exposed by the sidecar:

| Series | Type | Labels |
|--------|------|--------|
| `gm_miner_oauth_token_expires_in_seconds` | gauge | `provider` |
| `gm_miner_oauth_refresh_success_total` | counter | `provider` |
| `gm_miner_oauth_refresh_failure_total` | counter | `provider`, `reason` (`network`, `unauthorized`, `rate_limited`, `malformed`) |
| `gm_miner_provider_down` | gauge | `provider` — `1` when the sidecar has marked the provider unhealthy |
| `gm_miner_auth_sidecar_build_info` | gauge | always `1` |

A `gm_miner_subscription_quota_remaining` gauge was considered but is
deliberately omitted: the sidecar only sees the refresh exchange, not
the inference call, so the `anthropic-ratelimit-*` response headers
documented in the research file are out of reach from this layer.
Surfacing per-request quota will require an Envoy response-header
tap, which is Phase B work.

### Capacity feedback to the gateway

The miner already drops to zero capacity for a provider when Envoy
returns 503 on that provider's route — the gateway's capacity-aware
router treats 503 as "provider unavailable" and routes around. The
sidecar's `provider_down` gauge is the in-band reason: when it flips
to `1` the OAuth Lua filter starts returning 503 for that provider,
and the gateway already takes the right action without any new
gateway code in this PR.

## Phase B (not yet implemented)

Phase B will run the OAuth flow inside the gm-miner CLI itself — no
laptop-side CLI roundtrip — so a fresh refresh token can be minted
without re-running the laptop CLI. The env-var surface
(`GM_<PROVIDER>_OAUTH_*`) is reserved so a Phase B upgrade is a
drop-in for any operator already running Phase A.

Until Phase B lands, the refresh-token lifetime is the operational
ceiling: if a refresh token is revoked (the operator signs out of
ChatGPT / Claude on their laptop, or the provider rotates it
server-side), the sidecar will mark that provider down until the
operator re-runs `gm-miner deploy --paste-{codex,claude}-auth` with a
fresh file.
