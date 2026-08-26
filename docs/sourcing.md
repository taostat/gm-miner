# Sourcing routes: the upstreams that can serve a buyer product

A **buyer product** is what a buyer asks for — `zai/glm-5.2`, `anthropic/claude-sonnet-4-6`.
A **route** is how your worker fulfils it: which host it calls, with which key.

One buyer product can have several routes, and none of them is the canonical one.
`zai/glm-5.2` is the open GLM weights; Z.ai runs an API for them, and so do
DeepInfra, Engy, KubeTEE, Moonmath and NEAR. The product id names the model, not the
company you buy it from. Buyers see the product they asked for either way.

Routes differ on more than price — latency, availability, region, context window,
and data handling all vary between hosts serving identical weights. Price is
usually why you pick one, but it is not the only reason.

Run `gmcli sources` to see the routes available to you now, whether any of your
workers can serve them, and the exact command to declare each. This document
explains the table and how to set each upstream up.

## The routes

| Buyer product | Route | Upstream host | Key flag |
|---|---|---|---|
| `nvidia/nemotron-3-nano-omni-30b-tee` | `chutes/Nemotron-3-Nano-Omni-30B-TEE` | `llm.chutes.ai` | `--chutes` |
| `qwen/qwen3-235b-a22b-thinking-2507-tee` | `chutes/Qwen/Qwen3-235B-A22B-Thinking-2507-TEE` | `llm.chutes.ai` | `--chutes` |
| `qwen/qwen3-32b-tee` | `chutes/Qwen/Qwen3-32B-TEE` | `llm.chutes.ai` | `--chutes` |
| `qwen/qwen3.5-397b-a17b-tee` | `chutes/Qwen/Qwen3.5-397B-A17B-TEE` | `llm.chutes.ai` | `--chutes` |
| `qwen/qwen3.6-27b-tee` | `chutes/Qwen/Qwen3.6-27B-TEE` | `llm.chutes.ai` | `--chutes` |
| `deepseek/deepseek-v3.2-tee` | `chutes/deepseek-ai/DeepSeek-V3.2-TEE` | `llm.chutes.ai` | `--chutes` |
| `deepseek/deepseek-v4-flash-0731-tee` | `chutes/deepseek-ai/DeepSeek-V4-Flash-0731-TEE` | `llm.chutes.ai` | `--chutes` |
| `google/gemma-4-31b-turbo-tee` | `chutes/google/gemma-4-31B-turbo-TEE` | `llm.chutes.ai` | `--chutes` |
| `moonshot/kimi-k2.6-tee` | `chutes/moonshotai/Kimi-K2.6-TEE` | `llm.chutes.ai` | `--chutes` |
| `moonshot/kimi-k3-tee` | `chutes/moonshotai/Kimi-K3-TEE` | `llm.chutes.ai` | `--chutes` |
| `mistral/mistral-nemo-instruct-2407-tee` | `chutes/unsloth/Mistral-Nemo-Instruct-2407-TEE` | `llm.chutes.ai` | `--chutes` |
| `zai/glm-5.1-tee` | `chutes/zai-org/GLM-5.1-TEE` | `llm.chutes.ai` | `--chutes` |
| `zai/glm-5.2-tee` | `chutes/zai-org/GLM-5.2-TEE` | `llm.chutes.ai` | `--chutes` |
| `zai/glm-5.2` | `deepinfra/zai-org/GLM-5.2` | `api.deepinfra.com` | `--deepinfra` |
| `moonshot/kimi-k3` | `deepinfra/moonshotai/Kimi-K3` | `api.deepinfra.com` | `--deepinfra` |
| `deepseek/deepseek-v4-flash-0731` | `deepinfra/deepseek-ai/DeepSeek-V4-Flash-0731` | `api.deepinfra.com` | `--deepinfra` |
| `qwen/qwen3.6-35b-a3b` | `deepinfra/Qwen/Qwen3.6-35B-A3B` | `api.deepinfra.com` | `--deepinfra` |
| `qwen/qwen3.8-27b` | `deepinfra/Qwen/Qwen3.8-27B` | `api.deepinfra.com` | `--deepinfra` |
| `zai/glm-5.2` | `engy/glm-5.2` | `api.engy.ai` | `--engy` |
| `deepseek/deepseek-v4-flash-0731` | `engy/deepseek-v4-flash-0731` | `api.engy.ai` | `--engy` |
| `qwen/qwen3.6-35b-a3b` | `engy/qwen3.6-35b-a3b` | `api.engy.ai` | `--engy` |
| `qwen/qwen3.8-27b` | `engy/qwen3.8-27b` | `api.engy.ai` | `--engy` |
| `ornith/ornith-1.5-397b` | `engy/ornith-1.5-397b` | `api.engy.ai` | `--engy` |
| `zai/glm-5.2` | `kubetee/z-ai/glm-5.2` | `llm.kubetee.ai` | `--kubetee` |
| `zai/glm-5.3-flash` | `kubetee/z-ai/glm-5.3-flash` | `llm.kubetee.ai` | `--kubetee` |
| `qwen/qwen3.8-flash-next` | `kubetee/qwen/qwen3.8-flash-next` | `llm.kubetee.ai` | `--kubetee` |
| `moonshot/kimi-k3` | `kubetee/moonshotai/kimi-k3` | `llm.kubetee.ai` | `--kubetee` |
| `deepseek/deepseek-v4-flash-0731` | `kubetee/deepseek/deepseek-v4-flash-0731` | `llm.kubetee.ai` | `--kubetee` |
| `ornith/ornith-1.5-397b` | `kubetee/ornith/ornith-1.5-397b` | `llm.kubetee.ai` | `--kubetee` |
| `moonshot/kimi-k3` | `engy/kimi-k3` | `api.engy.ai` | `--engy` |
| `zai/glm-5.2` | `moonmath/glm-5.2` | `zro.moonmath.ai` | `--moonmath` |
| `moonshot/kimi-k3` | `moonmath/kimi-k3` | `zro.moonmath.ai` | `--moonmath` |
| `zai/glm-5.1-tee` | `near/zai-org/GLM-5.1-FP8` | `glm-5-1.completions.near.ai` | `--near` |
| `qwen/qwen3.6-27b-tee` | `near/Qwen/Qwen3.6-27B-FP8` | `qwen3-6-27b.completions.near.ai` | `--near` |
| `zai/glm-5.2-tee` | `near/z-ai/glm-5.2` | `glm-5-2-long.completions.near.ai` | `--near` |
| `deepseek/deepseek-v4-flash-0731-tee` | `near/deepseek-ai/DeepSeek-V4-Flash` | `dsv4-flash.completions.near.ai` | `--near` |
| `google/gemma-4-31b-turbo-tee` | `near/google/gemma-4-31B-it` | `gemma-4-31b.completions.near.ai` | `--near` |
| `qwen/qwen3.8-27b-tee` | `near/Qwen/Qwen3.8-27B` | `qwen3-8-27b.completions.near.ai` | `--near` |

Source pairs that differ from their buyer are absent from the public catalog:
they are dispatch targets, not products a buyer can request by name. The
`gmcli sources` uses `GET /miners/products/routes` and lists every explicit
route, including self routes. It falls back to the older cross-product-only
endpoint while reporting a registry that predates the complete route catalog.

### Cloud transport variants

Three backend transports are selected per worker rather than declared as separate products,
because the product id is unchanged:

| Buyer product | Route | Selector |
|---|---|---|
| `anthropic/*` | AWS Bedrock | `--anthropic-upstream bedrock` |
| `anthropic/*` | Claude on Microsoft Foundry | `--anthropic-upstream foundry` (see [foundry-setup.md](foundry-setup.md)) |
| `openai/*` | Azure OpenAI | `--openai-upstream azure` |

Same idea, different mechanism — these are set once per worker and apply to every
model from that provider.

## One lottery entry per worker

A worker may offer several routes into one buyer product. For each request, the
gateway first removes routes that cannot serve its capability envelope or fail
another admission gate, then keeps that worker's cheapest surviving route.
Source pair and route id only break equal-cost ties. The worker receives one
lottery entry regardless of how many routes it offers.

## How you are paid

Settlement is on the **buyer** product's retail, whichever route served it:

```
your rate per Mtok = buyer_retail[dimension] x (10000 - discount_bp) / 10000
```

The discount applies to every dimension the buyer product prices — input and
output always, plus prompt-cache, audio and long-context rates where the model
has them. So for `zai/glm-5.2` at a buyer retail of $1.40 in / $4.40 out,
declaring any of its routes at `--discount-pct 5` pays you:

```
in:  $1.40 x 9500 / 10000 = $1.330 per Mtok
out: $4.40 x 9500 / 10000 = $4.180 per Mtok
```

`gmcli declare-product` prints the resolved figure for every priced dimension
and asks you to confirm before it sends anything. What it sends is the
percentage; the registry resolves the figures against its own retail when it
records the offer.

Your spread is that figure minus whatever the upstream charges you for the same
tokens, and it is what differs between routes. `gmcli sources` shows the buyer
retail in the `BUYER RETAIL / MTOK` column so you can compute the left-hand
side; the right-hand side is between you and the upstream. A trailing `+N` in
that column counts the dimensions the buyer product prices beyond input and
output.

> **A route's own catalog price is not your cost.** The registry carries a price
> row for each route, but it mirrors the buyer product — it exists so the dispatch
> machinery has a well-formed row, not to describe what the upstream bills you.
> Get your real cost from the upstream's own pricing page. This is why the
> endpoint does not surface it and why `gmcli sources` does not show it.

If an upstream sells capacity by subscription or prepaid pack rather than purely
per token, your cost per token depends on how much of the allowance you use and
whether it expires. Work that out before you set a discount; gm cannot compute it
for you.

DeepInfra's cached-input price for DeepSeek V4 Flash 0731 was $0.016/Mtok on
2026-08-26, above the buyer product's $0.014/Mtok cache retail. Because one
discount applies to every dimension, that route cannot be profitable on cached
tokens in isolation. Price it only against a measured blended traffic mix with
enough margin for the mix and upstream price to move.

## Setting up a route

Three steps, in order.

**1. Set the upstream key.** Keys are baked into your TEE at deploy time and are
never seen by gm:

```sh
gmcli set-api-keys --deepinfra <key>
gmcli set-api-keys --engy <key>
gmcli set-api-keys --kubetee <key>
gmcli set-api-keys --moonmath <key>
gmcli set-api-keys --near <key>
```

Like the other upstream flags, each accepts up to 8 semicolon-separated keys and
the miner advertises opaque slot ids for them — see
[multi-key-slots.md](multi-key-slots.md).

**2. Deploy, so the key reaches a worker.**

```sh
gmcli deploy
```

**3. Declare the route.** Use the route's **source pair**, including when the
source pair happens to equal the buyer pair:

```sh
gmcli declare-product --provider engy --model glm-5.2 --discount-pct 5
gmcli declare-product --provider engy --model kimi-k3 --discount-pct 5
gmcli declare-product --provider engy --model deepseek-v4-flash-0731 --discount-pct 5
gmcli declare-product --provider engy --model qwen3.6-35b-a3b --discount-pct 5
gmcli declare-product --provider engy --model qwen3.8-27b --discount-pct 5
gmcli declare-product --provider deepinfra --model zai-org/GLM-5.2 --discount-pct 5
gmcli declare-product --provider deepinfra --model moonshotai/Kimi-K3 --discount-pct 5
gmcli declare-product --provider deepinfra --model deepseek-ai/DeepSeek-V4-Flash-0731 --discount-pct 5
gmcli declare-product --provider deepinfra --model Qwen/Qwen3.6-35B-A3B --discount-pct 5
gmcli declare-product --provider deepinfra --model Qwen/Qwen3.8-27B --discount-pct 5
gmcli declare-product --provider kubetee --model z-ai/glm-5.2 --discount-pct 5
gmcli declare-product --provider kubetee --model moonshotai/kimi-k3 --discount-pct 5
gmcli declare-product --provider moonmath --model glm-5.2 --discount-pct 5
gmcli declare-product --provider moonmath --model kimi-k3 --discount-pct 5
gmcli declare-product --provider near --model zai-org/GLM-5.1-FP8 --discount-pct 5
gmcli declare-product --provider near --model Qwen/Qwen3.6-27B-FP8 --discount-pct 5
gmcli declare-product --provider near --model z-ai/glm-5.2 --discount-pct 5
gmcli declare-product --provider near --model deepseek-ai/DeepSeek-V4-Flash --discount-pct 5
gmcli declare-product --provider near --model google/gemma-4-31B-it --discount-pct 5
```

### NEAR attestation enforcement

NEAR is not a normal TLS proxy route. When a NEAR key is present, the image
first verifies every closed-list NEAR endpoint before starting Envoy. For each
inference request, the co-located verifier then opens a fresh TLS connection,
requests nonce-bound evidence on that connection, validates the Intel TDX quote,
the exact model id, the live TLS public-key fingerprint, the compose measurement
binding, and NVIDIA's GPU verdict, and only then forwards inference on that same
connection. A missing, stale, substituted, malformed, or failed verdict returns
an error; there is no direct-origin or unattested fallback route.

The registry's `GET /v1/models` capability check is answered locally from that
same compiled allowlist. It does not contact an unattested catalog endpoint;
the registry's follow-up one-token balance check still takes the fully attested
inference path for the exact offered source model.

The verifier's endpoint and model allowlist is compiled into the measured miner
image. Adding a NEAR model therefore requires a new image build and the normal
registry image-approval process; changing a CLI catalog row alone cannot make an
arbitrary NEAR host reachable.

`gmcli sources` prints this line for you, pre-filled, for every undeclared route
where declaring it would actually get you somewhere — one a worker already
serves, or any route under a provider you have no live offer under. It stays
quiet for a route whose provider is already declared and whose count is still
zero, because a second offer there changes nothing about why no worker qualifies.

**For a provider you have no offer under, declare before waiting for
`YOU SERVE: yes`.** The registry builds its probe set from the providers you
have offers for, so while a provider has no offer it is not probed and every one
of its routes reads `YOU SERVE: no` however your workers are configured.
Declaring one of them puts the provider into the probe set, which is what lets
the count move for **all** of that provider's routes — the probe is per provider,
not per route. It still has to reach the upstream before any count rises; a key
the upstream rejects leaves them all at zero.

Once the provider is probed, a `YOU SERVE: no` on one of its other routes is
telling you about that route rather than about the probe set: no worker of yours
currently qualifies for it. That is worth diagnosing (the causes are listed
below, and several are transient) rather than answering with another declare.
`gmcli sources` uses the same distinction to decide when to print the declare
line, from the offers it can see — it knows whether a provider is offered now,
not whether a probe has finished, so give a fresh declaration a cycle before
reading anything into its count.

Note that `declare-products` (the fan-out) is catalog-only on purpose and will not
declare a route. A route offer commits you to an upstream you hold a key for, so
each one is declared individually.

To withdraw a route later, `gmcli undeclare-product --provider engy --model
glm-5.2`. The registry keeps the row for audit and re-declaring re-offers it.

## Why a route shows `YOU SERVE: no`

The count is how many of your workers are active, are on an approved image, and
carry that route in the capability the registry last probed for them. It is
evaluated when you ask, so revoking an image drops the count
immediately. It is a capability count, not final admission: if one
worker can serve two routes for the same buyer product, it is counted under both,
and only one of them will be routed. In rough order of frequency:

- **You have no live offer under that provider.** Not a fault: the registry
  only probes providers you have offers for, so a provider with no offer reads
  zero across all its routes no matter how the worker is configured. Declare any
  one of them to put the provider in the probe set; the causes below then decide
  whether the counts actually rise. This does **not** apply once the provider has
  an offer — from then on work through the causes below instead.
- The key is not set, or was set after your last deploy — run `gmcli set-api-keys`
  then `gmcli deploy`.
- The worker has not been probed since it came up. Wait a cycle and re-check.
- The worker is on an image version the registry no longer approves — `gmcli
  worker list` shows each worker's status and last attestation. A route added in a
  newer image cannot be served by a worker still running an older one.
- The worker was just restored from suspension; its supported-model list is
  cleared and repopulates on the next probe.

A zero is not by itself proof the key is missing, which is why `gmcli sources`
words it as "no worker of yours is currently serving" rather than blaming the key.

## Why a route might not appear at all

`gmcli sources` lists a route only when both the buyer product row and the route's
own row are active in the catalog and the buyer's retail block parses. If a route
you expect is missing, it has been withdrawn from the catalog rather than hidden
from you specifically — the table is self-scoped, but the *set* of routes is the
same for every miner.

If the command reports that the registry "does not publish sourcing routes yet",
your registry predates the endpoint; nothing on your side to fix.

If `gmcli sources` is not recognised at all, your CLI is older than v0.3.12.
Run `gmcli update`, or re-run the installer from the
[README](../README.md#quick-start).
