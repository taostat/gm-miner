# Serving Claude through Microsoft Foundry

This guide sets up an Azure AI Foundry resource for the miner. It does **not** by itself make Foundry a routable or registry-admissible
source: an HTTP-successful Foundry probe is transport capability, not
authoritative model admission. Cloud registration, recovery, and declaration
also require a registry that advertises `upstream-model-echo`; the deployed
image must advertise `upstream-model-hop`. Azure OpenAI chat completions uses
the same gates, while Azure Responses and Bedrock remain unqualified.

The rest of this guide prepares the Azure resource, endpoint, credentials, and
canonical deployment names. It covers the Azure side — the resource, the connections and
settings that must not exist on it, the read-only service principal, and the
deployment name — then the `gmcli` command that consumes the result.

Foundry serves Claude over Anthropic's own Messages API at
`https://<resource>.services.ai.azure.com/anthropic/v1/messages`, authenticated
with `x-api-key` and `anthropic-version: 2023-06-01`. The miner's Envoy only
rewrites host, path and headers; there is no body translation, and streaming
comes back as native Anthropic SSE events.

Before serving, `attestd` verifies from ARM that the Foundry account carries no
owner-capture controls, and it repeats that check while the miner runs. If a
check fails, the container does not serve — no Envoy, no RA-TLS, no traffic.
What those checks are, and what they deliberately do not cover, is in
[`AZURE_VERIFY_NOTES.md`](../AZURE_VERIFY_NOTES.md). This guide is the operator
procedure for satisfying them.

## Read this first: the Application Insights connection

Azure attaches an Application Insights connection to any AI Foundry resource
created through the portal. It is created for you, it is not mentioned in the
creation flow, and it is the single most common reason a first Foundry deploy
fails to boot. On a resource created with portal defaults it looks like this:

```
name=hello0323resourceappiafzvcx  category=AppInsights
target=/subscriptions/.../providers/microsoft.insights/components/...
```

An `AppInsights` connection alone lets Foundry trace **prompt content**
server-side, with no code change by the caller. `attestd` therefore treats any
connection on the account or on one of its projects as a capture sink and fails
closed. The miner will refuse to boot while it exists — after you have already
paid for a CVM.

Delete it before you deploy (step 3 below). Deleting it makes verification pass;
nothing else about the resource has to change.

## 1. Create the resource — it must be `kind=AIServices`

Foundry is the `Microsoft.CognitiveServices/accounts` resource with
`kind=AIServices`. The older `kind=OpenAI` resource is classic Azure OpenAI: it
serves the `openai` route (`OPENAI_UPSTREAM=azure`, a different set of `AZURE_*`
variables) and it cannot serve Claude. `attestd` requires the Foundry account's
kind to be exactly `AIServices` and fails verification otherwise, so confirm
what you have before going further:

```sh
az resource list --resource-type Microsoft.CognitiveServices/accounts \
  --query "[?kind=='AIServices'].{name:name, rg:resourceGroup, id:id}" -o table
```

Keep the `id` — it is the full ARM resource id of the account
(`/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.CognitiveServices/accounts/<name>`),
referred to below as `<ACCOUNT_ID>`. Deploy at least one Claude model on the
resource, and note the tenant and subscription you are working in:

```sh
az account show --query '{tenant:tenantId, subscription:id}' -o json
```

## 2. Use the `services.ai.azure.com` endpoint, not the one ARM reports

The account's `properties.endpoint` in ARM reads
`https://<name>.cognitiveservices.azure.com/`. That is **not** the Foundry
Anthropic passthrough host, and it is not what you pass to `gmcli`. The endpoint
the miner needs is:

```
https://<resource>.services.ai.azure.com
```

`gmcli set-api-keys` and `attestd` both accept only the `.services.ai.azure.com`
suffix for the Foundry endpoint, so an ARM-copied hostname is rejected up front
rather than at boot.

## 3. Delete the Application Insights connection

List the account's connections, then delete the `AppInsights` one by name:

```sh
az rest --method get \
  --url "https://management.azure.com<ACCOUNT_ID>/connections?api-version=2026-05-01" \
  --query "value[].{name:name, category:properties.category}" -o table

az rest --method delete \
  --url "https://management.azure.com<ACCOUNT_ID>/connections/<NAME>?api-version=2026-05-01"
```

Re-run the `get` and confirm the list is empty. `attestd` requires **zero**
connections, not merely zero `AppInsights` ones: rejecting every category also
fails closed on sink categories Azure adds later. If you have added a storage or
search connection for other work on this resource, either remove it or use a
separate account for the miner.

## 4. Clear the other capture surfaces — on the account *and* every project

The same emptiness requirement applies to two further collections, and it applies
at project scope as well as account scope. A Foundry project is a child of the
account, and it can carry its own connections, its own capability hosts, and its
own diagnostic settings; `attestd` walks every project, so one instrumented
project blocks the whole account.

Enumerate the projects first, then check each collection at both scopes:

ARM qualifies a project's `name` with the account that owns it: a project `p1` on
account `acct` comes back as `acct/p1`, not `p1`. The URL wants the last segment
alone — pasting the name back verbatim addresses a resource that does not exist,
and every project-scope check below would silently target the wrong URL.

```sh
# projects on the account — strip ARM's "<account>/" qualifier
az rest --method get \
  --url "https://management.azure.com<ACCOUNT_ID>/projects?api-version=2026-05-01" \
  --query "value[].name" -o tsv | cut -d/ -f2

# connections and capability hosts — expect [] for the account and each project
az rest --method get \
  --url "https://management.azure.com<ACCOUNT_ID>/connections?api-version=2026-05-01"
az rest --method get \
  --url "https://management.azure.com<ACCOUNT_ID>/capabilityHosts?api-version=2026-05-01"
az rest --method get \
  --url "https://management.azure.com<ACCOUNT_ID>/projects/<PROJECT>/connections?api-version=2026-05-01"
az rest --method get \
  --url "https://management.azure.com<ACCOUNT_ID>/projects/<PROJECT>/capabilityHosts?api-version=2026-05-01"

# diagnostic settings — expect [] for the account and each project
az monitor diagnostic-settings list --resource "<ACCOUNT_ID>"
az monitor diagnostic-settings list --resource "<ACCOUNT_ID>/projects/<PROJECT>"
```

Capability hosts redirect Agent-Service storage to stores you own, which is why
they must be absent. Diagnostic settings must be absent as a list, not merely
disabled or scoped to harmless categories: a disabled setting can be enabled
between two of `attestd`'s polls, so presence is the failure. Delete any you
find:

```sh
az monitor diagnostic-settings delete --name '<NAME>' --resource "<ACCOUNT_ID>"
```

The boot-gate failure message names the offending setting and prints this command
for you, but clearing the account first saves a wasted deploy.

## 5. Create a read-only service principal for `attestd`

`attestd` reads the account from ARM using Entra credentials you supply. It only
ever reads, so give it `Reader` and scope it to the one account — not the
resource group, not the subscription:

```sh
az ad sp create-for-rbac --name gm-miner-attestd --role Reader --scopes "<ACCOUNT_ID>"
```

Keep the `appId`, `password` and `tenant` from the output: they become
`--azure-foundry-client-id`, `--azure-foundry-client-secret` and
`--azure-foundry-tenant-id`. The secret is shown once.

These credentials are separate from the `AZURE_*` variables used by the Azure
OpenAI upstream on purpose — a worker may hold the two accounts in different
tenants, subscriptions or resource groups.

## 6. Create a deployment with the canonical gm model name

**Name the deployment exactly the canonical gm model id**, for example
`claude-opus-4-6`. Foundry routes by deployment name, so the gateway's `model`
value reaches Azure unchanged. The image enumerates deployments through ARM and
requires every name in its Foundry catalog to have `properties.model.format:
Anthropic` and `properties.model.name` equal to that deployment name, exact ASCII.
A catalog-named mismatch refuses boot or takes the worker offline when the
60-second poll observes it. Non-catalog names are ignored by the binding check.
A missing deployment is handled by the registry's per-offer probe and the gateway;
it does not take attestd offline.

As of September 2026, Anthropic deployments require `modelProviderData` containing
`organizationName`, `countryCode`, and lowercase `industry`. Only
`api-version=2025-10-01-preview` accepts this creation property; the verifier's ARM
read API remains separate. Microsoft's [Claude starter kit](https://github.com/Azure-Samples/claude)
uses these fields. Supply your actual organization details:

```sh
az rest --method put \
  --url "https://management.azure.com<ACCOUNT_ID>/deployments/claude-opus-4-6?api-version=2025-10-01-preview" \
  --body '{
    "sku": {"name": "GlobalStandard", "capacity": 25},
    "properties": {
      "model": {"format": "Anthropic", "name": "claude-opus-4-6", "version": "1"},
      "modelProviderData": {
        "organizationName": "<your organization>",
        "countryCode": "GB",
        "industry": "technology"
      }
    }
  }'
```

Azure cannot re-point a deployment to another model in place. Delete and recreate
it with the correct model and name. Read back the resulting identities:

```sh
az cognitiveservices account deployment list -n <ACCOUNT> -g <RG> \
  --query "[].{name:name, format:properties.model.format, model:properties.model.name, version:properties.model.version}" -o table
```

## 7. Configure gmcli

Point the `anthropic` route at Foundry and hand `gmcli` the data-plane endpoint,
the resource's API key, and the service principal from step 5:

```sh
gmcli set-api-keys \
  --anthropic-upstream foundry \
  --azure-foundry-endpoint https://<resource>.services.ai.azure.com \
  --azure-foundry-api-key <foundry-api-key> \
  --azure-foundry-tenant-id <tenant> \
  --azure-foundry-subscription-id <subscription> \
  --azure-foundry-resource-group <rg> \
  --azure-foundry-client-id <appId> \
  --azure-foundry-client-secret <password>
```

All seven endpoint/key/ARM fields are required together. The values are supplied
inside the encrypted CVM environment. The Foundry API key is single-slot;
semicolon-separated multi-key lists are rejected. Envoy forwards the request body
unchanged and uses the existing TLS host, SNI and SAN policy.

Run `gmcli doctor` before spending a deploy on it. Doctor does not merely check
that the group is complete: it runs the *same* owner-capture sweep `attestd` runs
at boot — the `gm-azure-verify` crate, one implementation, so the two cannot
disagree — against your account and every project on it. If a connection,
capability host or diagnostic setting is still attached, doctor names it and
prints the `az` command that clears it, here rather than after you have paid for
a CVM that crashloops. It also lists every ARM deployment with name, format, model
and version, flags each catalog-named mismatch, and sends one 1-token request per
honestly named catalog deployment, printing the echoed `model` against its name.

## 8. Deploy and validate transport

```sh
gmcli deploy
```

The CLI refuses Foundry registration or declaration when the registry does not
advertise `upstream-model-echo` or the selected image lacks
`upstream-model-hop`. Do not use `--upstream-model`: declare a Foundry offer
exactly like the direct product, for example:

```sh
gmcli declare-product --provider anthropic \
  --model claude-sonnet-4-6 --discount-pct 5
```

The deployment name, request `model` and offer model id are the same canonical id.
The in-TEE ARM binding and the gateway's per-response echo check provide the model
identity checks; the registry/gateway contract is unchanged.

If the account still has a connection, a capability host or a diagnostic setting
on it, the CVM starts, the boot gate fails, the container exits non-zero, and the
runtime restarts it into the same failure. The container logs name the offending
resource. Fix it in Azure — no redeploy is needed for the next verification pass
to see the change, but the container must restart to clear the gate.

## Checking the upstream by hand

The passthrough is a plain Anthropic Messages call, so you can confirm the
resource works before involving the miner at all:

```sh
curl https://<resource>.services.ai.azure.com/anthropic/v1/messages \
  -H "x-api-key: <foundry-api-key>" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-opus-4-6","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}'
```

Adding `"stream": true` returns native Anthropic SSE events. A 404 here almost
often means that no deployment with that canonical name exists on the account.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Miner boots, exits non-zero, restarts in a loop right after deploy | A connection, capability host or diagnostic setting on the account or a project. The container log names it; clear it (steps 3–4) and restart. `gmcli doctor` finds the same thing without a deploy |
| `gmcli set-api-keys` rejects the endpoint | The endpoint must end in `.services.ai.azure.com`. The `cognitiveservices.azure.com` host ARM reports is not the Foundry passthrough (step 2) |
| Verification fails on account kind | The resource is `kind=OpenAI` (classic Azure OpenAI), not `kind=AIServices`. Create a Foundry resource (step 1) |
| ARM read fails at boot | The service principal cannot see the account. Confirm the `Reader` assignment is scoped to `<ACCOUNT_ID>` and the tenant/subscription/resource-group fields match it (step 5) |
| Upstream 404s on a model gm lists | Create a deployment named exactly the canonical gm model id serving that same model, then run `gmcli doctor` (steps 6 and 8) |
