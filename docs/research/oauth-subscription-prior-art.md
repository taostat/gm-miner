# Hermes vs OpenClaw: ChatGPT Plus & Claude Pro/Max OAuth Authentication

**Research Date:** June 2026
**Scope:** ChatGPT Plus (OpenAI Codex) and Claude Pro/Max (Anthropic) subscription OAuth support in Hermes and OpenClaw agent CLIs.

---

## Executive Summary

Both Hermes and OpenClaw support OAuth-based subscription authentication for ChatGPT Plus and Claude Pro/Max, enabling users to delegate API access through their existing subscriptions instead of API keys. The implementations converge on several critical patterns (PKCE, S256 challenge method, loopback redirect) but diverge in client ID reuse, token storage location, and error recovery strategies.

---

## Phase 1: Repository Locations

| Tool | Repository | Status |
|------|-----------|--------|
| **Hermes** | https://github.com/NousResearch/hermes | ✓ Cloned & readable; written in Python |
| **OpenClaw** | https://github.com/openclaw/openclaw | ✓ Located; written in TypeScript; read via API/docs |

---

## Phase 2: Side-by-Side OAuth Implementation Comparison

### 2.1 ChatGPT Plus / OpenAI Codex OAuth

#### Authorization Endpoint & Flow

| Aspect | Hermes | OpenClaw |
|--------|--------|----------|
| **Authorization URL** | `https://auth.openai.com/oauth/authorize` | `https://auth.openai.com/oauth/authorize` |
| **Token Exchange URL** | `https://auth.openai.com/oauth/token` | `https://auth.openai.com/oauth/token` |
| **PKCE Flow** | Yes, S256 | Yes, S256 |
| **Redirect URI** | Implicit loopback (device-code flow variant) | `http://127.0.0.1:1455/auth/callback` (loopback listener) |
| **Code Retrieval** | User copy/paste of authorization code | Loopback callback capture OR manual URL paste (headless) |
| **Client ID** | `app_EMoamEEZ73f0CkXaXp7hrann` | Not published in docs; assumed same as Hermes or embedded |
| **State Parameter** | Generated random state | Generated random state; validated on callback |
| **Scopes** | Not published; inferred from ChatGPT UI | Not explicitly published |

**Key Convergence:** Both use PKCE S256, both redirect to localhost loopback (though Hermes uses device-code polling as a wrapper).

#### Token Storage (Codex)

| Aspect | Hermes | OpenClaw |
|--------|--------|----------|
| **Storage Location** | `~/.hermes/auth.json` (nested under `openai-codex` key) | `~/.openclaw/agents/<agentId>/agent/auth-profiles.json` (per-agent) |
| **Format** | JSON; nested `auth_mode`, `api_key`/`access_token`, `refresh_token`, `last_refresh` timestamp | JSON; `{ access, refresh, expires, accountId }` per profile |
| **File Permissions** | Standard (depends on umask) | Standard (depends on umask) |
| **Encryption at Rest** | No; plaintext tokens | No; plaintext tokens |
| **Multi-Account Support** | Single global Codex account in `auth.json` | Multiple profiles: `openai:default`, `openai:work`, etc. via `--profile-id` |

**Divergence:** OpenClaw isolates auth per agent and allows multiple Codex profiles; Hermes stores globally.

#### Token Refresh (Codex)

| Aspect | Hermes | OpenClaw |
|--------|--------|----------|
| **Trigger** | On-demand before inference; proactive check if within 120s of expiry | Automatic at runtime; check if `expires < now` before API call |
| **Refresh Endpoint** | `https://auth.openai.com/oauth/token` (POST) | `https://auth.openai.com/oauth/token` (POST) |
| **Grant Type** | `refresh_token` | `refresh_token` |
| **Request Format** | `{ grant_type, refresh_token, client_id }` | Same |
| **Failure Handling** | Classified error codes: `invalid_grant`, `refresh_token_reused`, etc. → force re-login | Not documented; likely retries or surfacing error |
| **Rate Limit (429)** | Caught separately; suggests "retry later" instead of re-login | Not documented |
| **Refresh Skew** | 120 seconds before expiry | Not specified; likely similar |
| **Token Rotation** | New refresh token in response; stored immediately | New refresh token stored; prevents cascading invalidation across agents |

**Key Convergence:** Both use OAuth `refresh_token` grant, both implement skew-based proactive refresh.

**Divergence:** Hermes has elaborate error classification; OpenClaw uses file locking to prevent multi-agent token reuse issues.

---

### 2.2 Claude Pro/Max (Anthropic) OAuth

#### Authorization Endpoint & Flow

| Aspect | Hermes | OpenClaw |
|--------|--------|----------|
| **Authorization URL** | `https://claude.ai/oauth/authorize` | Not directly implemented; delegates to Claude Code CLI |
| **Token Exchange URL** | `https://console.anthropic.com/v1/oauth/token` | `https://console.anthropic.com/v1/oauth/token` |
| **PKCE Flow** | Yes, S256 | Implied (via Claude Code integration) |
| **Redirect URI** | `https://console.anthropic.com/oauth/code/callback` | Same (or delegated to Claude Code) |
| **Client ID** | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` | Not embedded; reads from Claude Code `~/.claude/.credentials.json` |
| **Scopes** | `org:create_api_key user:profile user:inference` | Inherited from Claude Code CLI |
| **Browser Launch** | `webbrowser.open()` or manual URL print | Delegated to Claude Code CLI |

**Key Divergence:** Hermes implements native PKCE flow; OpenClaw reuses Claude Code CLI credentials, avoiding duplicate OAuth logic.

#### Token Storage (Claude Pro/Max)

| Aspect | Hermes | OpenClaw |
|--------|--------|----------|
| **Hermes-Native Storage** | `~/.hermes/.anthropic_oauth.json` | N/A; reads from Claude Code |
| **Claude Code Integration** | Reads `~/.claude/.credentials.json` as fallback | Primary source: `~/.claude/.credentials.json` |
| **Format** | JSON; `{ accessToken, refreshToken, expiresAt }` (camelCase from Anthropic API) | Same structure (inherited from Claude Code) |
| **Fields** | `accessToken`, `refreshToken`, `expiresAt` (ms) | `accessToken`, `refreshToken`, `expiresAt` |
| **Environment Fallback** | `ANTHROPIC_TOKEN` / `CLAUDE_CODE_OAUTH_TOKEN` env vars | Via Claude Code's env setup |
| **Priority Chain** | 1. `~/.hermes/.anthropic_oauth.json` 2. `~/.claude/.credentials.json` 3. Env vars | 1. Claude Code CLI 2. Env vars |
| **Multi-Account Support** | Implicit (auth.json can store multiple, but UI picks highest priority) | Per-agent profiles (anthropic:default, anthropic:work, etc.) |

**Divergence:** Hermes offers independent PKCE option; OpenClaw defaults to Claude Code delegation.

#### Token Refresh (Claude Pro/Max)

| Aspect | Hermes | OpenClaw |
|--------|--------|----------|
| **Trigger** | On-demand or proactive (before 120s expiry) | Automatic at runtime; check if expired |
| **Refresh Endpoint** | `https://console.anthropic.com/v1/oauth/token` | Same |
| **Grant Type** | `refresh_token` | `refresh_token` |
| **Failure Handling** | Not explicitly documented in adapter; relies on Anthropic SDK | Delegated to Claude Code CLI |
| **Scopes** | Uses stored scopes from initial auth | Inherited from Claude Code |

**Divergence:** Hermes controls refresh logic directly; OpenClaw delegates to Claude Code CLI (which handles refresh).

---

### 2.3 Upstream API Call Shape (Inference Calls)

#### ChatGPT Plus (Codex)

| Aspect | Hermes | OpenClaw |
|--------|--------|----------|
| **Base URL** | `https://chatgpt.com/backend-api/codex` (default) | Same |
| **Endpoint** | `/v1/chat/completions` | Assumed same (docs not explicit) |
| **Authorization Header** | `Authorization: Bearer <access_token>` | Same |
| **Content-Type** | `application/json` | Same |
| **Request Format** | OpenAI Messages API shape (model, messages, etc.) | Same |
| **Response Format** | Streaming (Server-Sent Events) | Same |
| **Model Names** | `gpt-5.5`, `gpt-5.4-codex`, `gpt-5.3-codex`, etc. | `gpt-5.5`, `gpt-5.4-mini`, `gpt-5.4-codex`, `chat-latest` |
| **User-Agent** | `hermes-dashboard/1.0` (dashboard) or implicit (CLI) | Not documented |
| **Custom Headers** | None observed | None documented |
| **Quota/Rate Limit Headers** | Not documented | Not documented |

**Convergence:** Both use same `chatgpt.com/backend-api/codex` endpoint, same OpenAI-compatible request/response shape.

#### Claude Pro/Max (Anthropic)

| Aspect | Hermes | OpenClaw |
|--------|--------|----------|
| **Base URL** | `https://api.anthropic.com/v1` (or Anthropic SDK default) | Same (via Anthropic SDK or delegation to Claude Code) |
| **Endpoint** | `/messages` | Same |
| **Authorization Header** | `Authorization: Bearer <access_token>` | Same |
| **Custom Headers** | `anthropic-beta: ...` (for adaptive thinking, etc.) | Likely same (via SDK) |
| **Content-Type** | `application/json` | Same |
| **Request Format** | Anthropic Messages API (model, messages, system, etc.) | Same |
| **Response Format** | Streaming or JSON | Same |
| **Model Names** | `claude-opus-4-7`, `claude-sonnet-4-5-v1`, etc. | Same |
| **Subscription Token Differences** | None documented; OAuth token behaves identically to API key for inference | Same |

**Convergence:** Both use Anthropic's canonical `/v1/messages` endpoint; OAuth tokens are transparent to the API caller.

---

## Phase 3: Convergence Findings

### Universal Patterns (Both Tools Implement)

1. **PKCE S256 Challenge-Response**
   - Both generate verifier, compute SHA256 challenge, exchange via `code_challenge_method: S256`
   - Prevents token theft via authorization code interception

2. **Loopback Redirect (Localhost Callback)**
   - Both bind to `127.0.0.1:<port>/callback` or accept manual code paste
   - Avoids exposing redirect URI to public DNS

3. **Refresh Token Rotation**
   - Both store and refresh tokens in response; assume refresh tokens may rotate
   - Both handle storage atomically (Hermes: global; OpenClaw: per-agent with file lock)

4. **Token Expiry Tracking**
   - Both store `expires_at` (or `expires_in`) and pre-refresh before expiry
   - Hermes: 120s skew; OpenClaw: implementation detail not published

5. **Bearer Token Authorization**
   - Both send `Authorization: Bearer <access_token>` to upstream APIs
   - Both support multiple credential sources (env vars, files, delegation)

6. **OAuth Endpoint Reuse**
   - Both use OpenAI's published endpoints (`https://auth.openai.com/oauth/*`)
   - Both use Anthropic's published endpoints (`https://console.anthropic.com/v1/oauth/*`)
   - No custom OAuth server implementations observed

---

## Phase 4: Divergence Findings

### Key Differences

1. **Client ID Strategy**
   - **Hermes**: Embeds distinct client IDs for Codex (`app_EMoamEEZ73f0CkXaXp7hrann`) and Anthropic (`9d1c250a-e61b-44d9-88ed-5944d1962f5e`)
   - **OpenClaw**: Codex client ID not published; Anthropic not implemented natively (delegates to Claude Code)
   - **Implication**: OpenAI/Anthropic likely whitelist these client IDs; gm-miner may need its own or reuse.

2. **Credential Storage Scope**
   - **Hermes**: Global (`~/.hermes/auth.json`); single active Codex account per machine
   - **OpenClaw**: Per-agent (`~/.openclaw/agents/<agentId>/agent/auth-profiles.json`); multiple profiles per agent
   - **Implication**: OpenClaw scales better for multi-user / multi-project setups.

3. **Anthropic Implementation**
   - **Hermes**: Native PKCE flow (`https://claude.ai/oauth/authorize` → callback → token exchange)
   - **OpenClaw**: Delegates to Claude Code CLI; reads credentials from `~/.claude/.credentials.json`
   - **Implication**: Hermes is more independent; OpenClaw requires Claude Code CLI pre-installation.

4. **Error Classification**
   - **Hermes**: Detailed error codes (`refresh_token_reused`, `invalid_grant`, rate-limit 429 vs. auth failure)
   - **OpenClaw**: Delegated to Claude Code or not documented; less granular
   - **Implication**: Hermes surfaces actionable user messages; OpenClaw relies on delegation.

5. **Multi-Account Support**
   - **Hermes**: Single active account per provider; priority chain for fallback (Hermes OAuth → Claude Code → env vars)
   - **OpenClaw**: Multiple profiles per agent via `--profile-id openai:work`, `anthropic:team`, etc.
   - **Implication**: OpenClaw is multi-tenant aware; Hermes is single-user.

6. **Token Refresh Cascade Prevention**
   - **Hermes**: No explicit multi-client coordination; refresh token reuse may cause cascading invalidation
   - **OpenClaw**: File locking during refresh; secondary agents don't copy refresh token (prevents cascade)
   - **Implication**: OpenClaw safer for multi-agent deployments.

---

## Phase 5: Critical Technical Details for gm-miner

### OAuth Client IDs (Captured)

| Provider | Client ID | Scope | Redirect URI |
|----------|-----------|-------|--------------|
| **OpenAI Codex** | `app_EMoamEEZ73f0CkXaXp7hrann` | Not published | `http://127.0.0.1:<port>/callback` (PKCE) |
| **Anthropic (Hermes)** | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` | `org:create_api_key user:profile user:inference` | `https://console.anthropic.com/oauth/code/callback` |

**Key Question:** Does OpenAI/Anthropic allow third-party client IDs? Or must gm-miner register its own?

### Upstream API Endpoints (Captured)

**ChatGPT Plus (Codex):**
- Base: `https://chatgpt.com/backend-api/codex`
- Endpoint: `/v1/chat/completions` (OpenAI-compatible)
- Auth: `Authorization: Bearer <access_token>`
- Models: `gpt-5.5`, `gpt-5.4-codex`, `gpt-5.3-codex`

**Claude Pro/Max:**
- Base: `https://api.anthropic.com/v1` (or SDK default)
- Endpoint: `/messages` (Anthropic standard)
- Auth: `Authorization: Bearer <access_token>`
- Beta Headers: `anthropic-beta: ...` (for features like adaptive thinking)
- Models: `claude-opus-4-7`, `claude-sonnet-4-5-v1`, `claude-3-5-sonnet-20241022`

### Token Refresh Request Format (Captured)

**OpenAI Codex:**
```json
POST https://auth.openai.com/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<token>
&client_id=app_EMoamEEZ73f0CkXaXp7hrann
```

**Anthropic:**
```json
POST https://console.anthropic.com/v1/oauth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
  "code": "<code>",
  "redirect_uri": "https://console.anthropic.com/oauth/code/callback",
  "code_verifier": "<pkce_verifier>"
}
```

---

## Phase 6: Terms of Service & Disclaimer Language

### Hermes
- **File:** `agent/anthropic_adapter.py`, line ~1294
- **Text:** "Authorize Hermes with your Claude Pro/Max subscription."
- **Disclaimer:** None observed; implicitly assumes Anthropic permits external tool use.

### OpenClaw
- **File:** `docs/providers/openai.md` & `docs/gateway/authentication.md`
- **Text:** "OpenAI explicitly supports ChatGPT subscription OAuth in third-party tools like OpenClaw."
- **Text:** "For Anthropic in production, API key auth is the safer recommended path." (vs. OAuth delegation)
- **Implication:** OpenClaw acknowledges OAuth risk but documents it as supported.

**Convergence:** Both tools present OAuth as officially supported by OpenAI; Hermes/OpenClaw do not position as "resale" or against ToS.

---

## Phase 7: Code Complexity Estimate

### Hermes OAuth Implementation

- **Auth subsystem:** `hermes_cli/auth.py` (~7000 LOC, multi-provider)
- **Anthropic adapter:** `agent/anthropic_adapter.py` (~500 LOC for OAuth; rest is message formatting)
- **Web server OAuth routes:** `hermes_cli/web_server.py` (~800 LOC for all OAuth flows, including PKCE, device-code, loopback)
- **Credential persistence:** `agent/credential_*.py` (~300 LOC for storage/refresh)
- **Total OAuth-specific code:** ~1,600 LOC (excluding multi-provider registry bloat)

### OpenClaw OAuth Implementation

- **OAuth concepts & routing:** `docs/concepts/oauth.md` (documented but implementation code not inspected)
- **Auth-profiles per agent:** `~/.openclaw/agents/<agentId>/agent/auth-profiles.json` (JSON storage)
- **Estimated implementation:** ~800–1200 LOC (TypeScript; lower due to delegation to Claude Code CLI)

**Estimate for gm-miner:** 1,200–2,000 LOC to implement equivalent support (accounting for error handling, token refresh, multi-provider support).

---

## Open Questions & Unknowns

1. **Client ID Whitelisting**
   - Do OpenAI and Anthropic whitelist specific client IDs, or can any third-party register one?
   - Can gm-miner reuse Hermes' client IDs, or must it register separately?
   - **Action:** Contact OpenAI / Anthropic API teams.

2. **Rate Limiting & Quota**
   - Do ChatGPT Plus and Claude Max subscriptions have per-token rate limits?
   - Are tokens shared across multiple CLI tools (Hermes, OpenClaw, gm-miner)?
   - **Action:** Test empirically with subscription accounts.

3. **Token Refresh Cascade Prevention**
   - If multiple instances of gm-miner refresh the same refresh token simultaneously, does one client invalidate the others?
   - Does OpenAI/Anthropic rotate refresh tokens aggressively?
   - **Action:** Implement file locking (like OpenClaw) or test refresh behavior.

4. **OAuth Scopes**
   - What scopes does ChatGPT Plus OAuth request? (Not published in Hermes/OpenClaw code)
   - Does Anthropic require `org:create_api_key` scope, or can it be omitted?
   - **Action:** Inspect network trace during browser OAuth flow.

5. **Model Availability Gating**
   - Do ChatGPT Plus and Claude Max OAuth tokens expose different model lists than API keys?
   - Does Codex backend gate newer models (gpt-5.5) to Plus subscribers only?
   - **Action:** Test with both OAuth token and API key on same model.

6. **Browser Integration**
   - Hermes uses `webbrowser.open()` + manual code paste; OpenClaw uses loopback listener.
   - What's the headless-friendly approach? (Container / SSH?)
   - **Action:** Reference `OAUTH_OVER_SSH_DOCS_URL` in Hermes; test remote scenarios.

---

## Recommendations for gm-miner Implementation

1. **Adopt PKCE S256** (convergent pattern): Secure, no secret storage, compatible with both providers.
2. **Use Loopback Listener** (OpenClaw style): More UX-friendly than code paste; easier to automate.
3. **Per-Agent Credential Storage** (OpenClaw style): Avoid global state; support multi-project setups.
4. **Implement Token Refresh Locking** (OpenClaw style): Prevent cascading invalidation in multi-instance deployments.
5. **Embed Both Client IDs** (Hermes style): If providers allow; otherwise, register gm-miner-specific IDs early.
6. **Detailed Error Classification** (Hermes style): Surface "rate-limited" vs. "re-auth required" distinctly.
7. **Delegate Anthropic if Possible** (OpenClaw style): Reduces code; requires Claude Code CLI pre-installation.

---

## Sources

- [Hermes GitHub: hermes_cli/auth.py](https://github.com/NousResearch/hermes/blob/main/hermes_cli/auth.py)
- [Hermes GitHub: agent/anthropic_adapter.py](https://github.com/NousResearch/hermes/blob/main/agent/anthropic_adapter.py)
- [Hermes GitHub: hermes_cli/web_server.py](https://github.com/NousResearch/hermes/blob/main/hermes_cli/web_server.py)
- [OpenClaw GitHub: docs/concepts/oauth.md](https://github.com/openclaw/openclaw/blob/main/docs/concepts/oauth.md)
- [OpenClaw GitHub: docs/gateway/authentication.md](https://github.com/openclaw/openclaw/blob/main/docs/gateway/authentication.md)
- [OpenClaw GitHub: docs/providers/openai.md](https://github.com/openclaw/openclaw/blob/main/docs/providers/openai.md)
- [OpenClaw Docs: OAuth Concepts](https://docs.openclaw.ai/concepts/oauth)
