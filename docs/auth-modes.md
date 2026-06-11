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

## Phase B (not yet implemented)

Phase B will run the OAuth flow inside the gm-miner CLI itself — no laptop-side
CLI roundtrip — and refresh access tokens automatically inside the CVM. The
env-var surface (`GM_<PROVIDER>_OAUTH_*`) is reserved so a Phase B upgrade is a
drop-in for any operator already running Phase A.

The in-CVM refresh worker and per-provider upstream adapter for the
`oauth_subscription` mode are not yet implemented. Until Phase B lands, a
Phase A deploy will:

  1. Carry a valid initial access token only for as long as the provider's
     access-token lifetime permits (typically 1 hour for Anthropic, 1 hour for
     `OpenAI`).
  2. Stop serving traffic for that provider when the access token expires.

Operators running Phase A today should expect to re-paste the auth file at
least once per access-token lifetime, or pair the manual-paste with an
external cron that re-runs `gm-miner deploy` on a schedule.
