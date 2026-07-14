# Azure OpenAI Owner-Capture Verification

## One implementation, two callers

The checks live in the `gm-azure-verify` workspace crate (`azure-verify/`), and both callers run *that* code:

- `attestd` runs it inside the CVM as a fail-closed boot gate, and then periodically.
- `gmcli doctor` runs it on the operator's machine as a preflight, before a CVM is paid for.

The two cannot drift, which is the reason for the crate. A doctor `[ok]` is a promise the boot gate keeps; a doctor `[!!]` names the same violation the enclave would refuse to boot on, with the same `az` command to clear it. The only difference is where the sweep stops: `AzureVerifier::audit_target` collects *every* finding so doctor can print them all at once, and `verify_target` — what `attestd` calls — collapses that same audit into the gate's pass/fail, where any one finding is fatal. Doctor audits the credentials verbatim, exactly as `render_env_file` ships them into the CVM, and issues read-only ARM requests just as the enclave does.

With no Azure-backed upstream selected, doctor prints no Azure line at all: the check is skipped, not failed.

### A finding always outranks a transport error

The sweep keeps reading ARM after it records a violation, because doctor wants every finding and not just the first. That makes the ordering of the two failure kinds a safety property, not a detail:

- **A policy violation is definitive.** It fails the gate, and the periodic loop shuts the miner down.
- **A transport error (timeout, 408/429/5xx, decode failure) is transient.** The periodic loop tolerates a few in a row, because a genuine Azure hiccup on a clean account must not kill an honest miner.

So a later transport error must never be allowed to replace a finding already recorded. Otherwise an operator could attach a capture sink and then induce throttling on the *next* ARM read: the gate would see a 429, rate it transient, tolerate it, and envoy would keep streaming prompts into the sink for the whole tolerance window.

Two rules, and both are needed — the first is useless without the second:

1. **A recorded finding outranks a transport error.** `AzureAudit::findings_outrank` is the single place this is decided: once `findings` is non-empty a transport failure cannot win, and the audit comes back with `swept_completely: false` to say the list is a floor rather than the whole story.
2. **Record a violation the moment it is observable, before making another fallible call.** A gate can only prefer a finding that exists. `fetch_paged` therefore returns the pages it *did* read alongside the failure that stopped it (`PagedRead`), and the caller asserts over those items and records before letting the failure through — otherwise an App Insights connection on page 1 would be discarded by a 429 on page 2, nothing would be recorded, and rule 1 would have nothing to prefer. The same applies to the RAI path: a deployment with no `raiPolicyName` is a violation on sight and is recorded even if a later policy read throttles.

The converse of rule 2 matters just as much: a deployment whose RAI policy we never managed to read is **dropped**, not judged (`retain_observable_deployments`). Assessing it against an absent mode would manufacture a definitive finding out of a transient failure — the mirror image of the bug — and would kill honest miners on an Azure hiccup. Transport errors are never converted into findings; the asymmetry is the point.

## Startup gate and continuous verification

When `OPENAI_UPSTREAM=azure` or `ANTHROPIC_UPSTREAM=foundry`, `image/start.sh` first runs `gm-miner-attestd --verify-azure-once` as a blocking gate. Both accounts are verified when both are configured; either failing is fatal. Envoy is not rendered, RA-TLS is not provisioned, and no serving process is started until that one-shot verification exits successfully. A verification failure exits the container non-zero so the runtime restarts it.

The gate fails closed if:

- `AZURE_OPENAI_ENDPOINT` is not `https`, contains userinfo, or is outside the allowed Azure suffixes: `.openai.azure.com`, `.services.ai.azure.com`, `.cognitiveservices.azure.com`.
- ARM cannot read the bound `Microsoft.CognitiveServices/accounts/{name}` resource, where `{name}` is the leftmost endpoint host label.
- The ARM account `kind` is not `OpenAI` or `AIServices`.
- `properties.customSubDomainName` is missing or does not match the configured endpoint account label.
- `properties.endpoint` does not use the same host as the configured Azure endpoint, including the configured allowed suffix.
- `properties.raiMonitorConfig` is non-null.
- `properties.userOwnedStorage` is non-null and non-empty.
- Any deployment on the account references a Responsible AI policy whose `properties.mode` is not `Asynchronous_filter` or legacy `Deferred`. `Blocking`, `Default`, an absent mode, or a deployment with no `properties.raiPolicyName` is treated as synchronous buffering and always fails verification.

The streaming check uses the same scoped Entra credentials and ARM API version as the account binding check:

- List deployments: `GET https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.CognitiveServices/accounts/{name}/deployments?api-version=2024-10-01`
- Read each distinct referenced RAI policy: `GET https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.CognitiveServices/accounts/{name}/raiPolicies/{raiPolicyName}?api-version=2024-10-01`

The verifier reads `value[].properties.raiPolicyName` from the deployment list, then reads `properties.mode` from each referenced RAI policy. Streaming is considered enabled only when the mode is `Asynchronous_filter` or `Deferred`. The verifier checks all deployments on the account so the attestation covers whatever the gateway may route to. If the account has zero deployments, the streaming check passes and logs that there are no deployments to check; model availability is gated elsewhere.

Asynchronous content filtering (streaming-safe, no completion buffering) is required and enforced as gm policy. Any synchronous or buffering deployment fails the startup gate and continuous verification; there is no operator override.

The account's diagnostic-settings list must be empty. Presence of any setting fails the gate — enabled or not, whatever its categories, whatever its destination. There is no allowlist of "safe" categories: a disabled setting can be enabled between two polls, and a sink using a destination field this verifier does not model would otherwise pass. See the Security boundary section for the operator migration note.

After the startup gate passes and the listener binds, `attestd` re-runs the same Azure owner-capture verification periodically, including the deployment streaming-mode check. The default re-verification interval is 900 seconds; values below 60 seconds are clamped to 60 seconds. Transient verification errors such as Azure management/login network errors, timeouts, HTTP 408/429/5xx responses, or response decode failures are tolerated for 3 consecutive checks by default. A definitive verification failure, such as `raiMonitorConfig` becoming non-null, endpoint binding changing, account kind changing, async filtering being disabled, or other policy mismatch, stops `attestd` immediately with a non-zero exit so the container restarts and the boot-time gate blocks serving.

Envoy validates the Azure upstream against the system CA bundle with an exact DNS SAN pin for the configured host. Root pinning was dropped because it is out of scope for the operator threat model — a miner operator cannot obtain a valid cert for a Microsoft-owned hostname regardless of the trusted-root set — and a pinned bundle would fail closed if Microsoft rotates its Azure PKI. Direct `api.openai.com` uses the same system CA bundle and SAN pin approach.

## Required miner configuration

Azure miners must provide:

- `OPENAI_UPSTREAM=azure`
- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_API_KEY`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `AZURE_RESOURCE_GROUP`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`

The Entra app/service principal should have `Reader` scoped to the Azure OpenAI resource so `attestd` can read the account and diagnostic settings without broader permissions.

Azure deployments must use a content-filter RAI policy configured for asynchronous filtering. In ARM, this is the RAI policy `mode`, not a deployment-level `contentFilters` field. The deployment's `properties.raiPolicyName` must point to a policy whose `properties.mode` is `Asynchronous_filter` or `Deferred`; the default synchronous modes buffer completions under `stream:true` and are not allowed for gm Azure miners.

## Security boundary

The owner-capture checks enforce that the Azure OpenAI account is bound to the configured endpoint by ARM identity, has no secondary storage or monitoring sinks attached (`userOwnedStorage`, `raiMonitorConfig`), and that every deployment uses asynchronous content filtering so completions are never buffered server-side before delivery. These checks run at container startup and repeat every 15 minutes; a policy violation detected after startup terminates `attestd` and restarts the container.

Network operators on the path between the miner CVM and Azure observe only TLS-encrypted ciphertext. Prompt content stays confidential end-to-end through Envoy: the RA-TLS data plane is terminated inside the TEE, and the Azure upstream connection is validated against the system CA bundle with an exact DNS SAN pin for the configured Azure host. The ARM account binding checks verify that the endpoint belongs to the miner's own resource, not a third-party account.

The account must export nothing. The diagnostic-settings list must be **empty** — presence of any setting is the failure, enabled or not, whatever its categories, whatever its destination. This is a property of the account, not of the upstream it serves, so it applies to Azure `OpenAI` and Foundry alike. `AIServices` accounts additionally must have no connections and no capability hosts, on the account and on every project.

Earlier releases only *warned* on unexpected Azure `OpenAI` log categories. That was weaker than this document claimed, and it is now enforced.

**Operator migration.** The gate lives in the miner image, so an already-running miner is unaffected until it deploys a newer image version. A miner that redeploys — including for an unrelated reason, such as adding a provider key — picks up the newest approved image and will fail the boot gate if its Azure account has a diagnostic setting attached. The failure names the setting and prints the `az monitor diagnostic-settings delete` command to remove it. Operators should clear their account before upgrading.

## Microsoft Foundry (`ANTHROPIC_UPSTREAM=foundry`)

Claude on Foundry is served over Anthropic's own Messages API
(`https://<resource>.services.ai.azure.com/anthropic/v1/messages`), so the data
plane is a host/path/header rewrite with no body translation. What differs is
verification.

Azure's Responsible-AI content filter is **not** in Claude's inference path on
Foundry ("Foundry doesn't provide built-in content filtering for Claude models at
deployment time"), so the async-filter check that proves non-buffered streaming
for Azure `OpenAI` has no equivalent here and the verifier does not consult
`raiPolicyName` at all. Microsoft's own Claude reference templates *do* set
`raiPolicyName: Microsoft.DefaultV2` on Claude deployments, and it is inert —
reading it would prove nothing in either direction. Streaming for Foundry offers
is therefore established empirically by the registry's inference probe, not
attested from ARM. This is stated plainly rather than dressed up as an
attestation.

The account must be **inference-only**, and the checks are strict rather than
allowlist-based (the same sweep runs for Azure `OpenAI`; the project/connection
checks apply to `AIServices` accounts, which are the only kind that has them):

- account `kind` must be exactly `AIServices`
- `properties.customSubDomainName` binds the ARM account to the configured host
- `properties.raiMonitorConfig` must be null, `properties.userOwnedStorage` empty
- the diagnostic-settings list must be **empty** — on the account and on every
  project. Presence is the failure, not the fields: a disabled setting can be
  enabled between two polls, and a sink using a destination field this verifier
  does not model would otherwise pass. Microsoft publishes no field-level schema
  for the `RequestResponse` category either, so whether it can carry request
  bodies for this resource kind is unsettled. Requiring zero settings moots all
  three questions.
- the account's and every project's `connections` must be empty. An `AppInsights`
  connection alone is enough for Foundry to trace **prompt content** server-side
  with no code change by the caller ("Foundry enables it for you automatically
  once you connect an Application Insights resource to your project"). Rejecting
  every connection category — not just `AppInsights` — also fails closed on sink
  categories Azure adds later.
- the account's and every project's `capabilityHosts` must be empty (they
  redirect Agent-Service storage to operator-owned stores).

Foundry's "online evaluation / continuous monitoring" of sampled live traffic is
**not** an independent capture surface: it is downstream of captured data, and
every Microsoft how-to lists a connected Application Insights resource as a
prerequisite. With no connection and an uninstrumented caller, it has nothing to
read. The connection gate above is what neutralizes it.

### What Foundry verification does NOT cover

- **Anthropic-side retention.** Anthropic is an independent data processor on
  Foundry and retains prompts and outputs for 30 days, with exceptions-only Trust
  & Safety review; Foundry ZDR is a separate contractual arrangement. No ARM
  property represents any of this. It is not a gap in the verifier — Azure does
  not expose it at all — and it is the same posture the `direct` Anthropic
  backend already carries.
- **The polling window.** Boot-time plus periodic ARM verification is detection,
  not prevention: the operator owns the subscription and can enable a capture
  surface after a poll and remove it before the next. The re-verification
  interval bounds the exposure window; it does not eliminate it. Closing this
  properly needs a control outside the operator's authority (e.g. a gm-owned
  management-group deny assignment). This applies equally to the Azure `OpenAI`
  backend and is not specific to Foundry.

### Required miner configuration

`ANTHROPIC_UPSTREAM=foundry`, `AZURE_FOUNDRY_ENDPOINT`, `AZURE_FOUNDRY_API_KEY`,
plus a read-only Entra service principal for ARM: `AZURE_FOUNDRY_TENANT_ID`,
`AZURE_FOUNDRY_SUBSCRIPTION_ID`, `AZURE_FOUNDRY_RESOURCE_GROUP`,
`AZURE_FOUNDRY_CLIENT_ID`, `AZURE_FOUNDRY_CLIENT_SECRET`. These are separate from
the `AZURE_*` Azure `OpenAI` variables on purpose: a worker may hold the two
accounts in different tenants, subscriptions, or resource groups.

Offers are declared with `--upstream-model <deployment-name>`: Foundry routes on
the *deployment* name, which defaults to the model id but does not have to match
it.

The operator procedure for satisfying these checks — which resource kind to
create, the `az` calls that list and clear the connections, capability hosts and
diagnostic settings on the account and its projects, and the read-only service
principal — is in [`docs/foundry-setup.md`](docs/foundry-setup.md). The step
operators most often miss is the Application Insights connection Azure attaches
to any Foundry resource created through the portal: it is the connection this
gate rejects, and it is present by default.

### Provenance of the ARM shapes

The ARM request/response shapes here were built from
`Azure/azure-rest-api-specs` (stable `2026-05-01`) and Microsoft's own
`Azure-Samples/claude` templates. The design deliberately depends on no fact
those sources leave unsettled: every check is either a spec-confirmed field read
or an emptiness assertion.

Since then the connection sweep has been exercised against a live Foundry
account. A portal-created resource carried an `AppInsights` connection nobody
asked for; the account failed verification while it existed and passed once it
was deleted. The Anthropic-native passthrough
(`/anthropic/v1/messages`, `x-api-key` + `anthropic-version: 2023-06-01`) was
confirmed on the same resource, streaming included, and routing was confirmed to
be on the deployment name rather than the canonical model id.
