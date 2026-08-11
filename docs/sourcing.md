# Sourcing routes: the upstreams that can serve a buyer product

A **buyer product** is what a buyer asks for — `zai/glm-5.2`, `anthropic/claude-sonnet-4-6`.
A **route** is how your worker fulfils it: which host it calls, with which key.

One buyer product can have several routes, and none of them is the canonical one.
`zai/glm-5.2` is the open GLM weights; Z.ai runs an API for them, and so do
DeepInfra and Engy. The product id names the model, not the company you buy it
from. Buyers see the product they asked for either way.

Routes differ on more than price — latency, availability, region, context window,
and data handling all vary between hosts serving identical weights. Price is
usually why you pick one, but it is not the only reason.

Run `gmcli sources` to see the routes available to you now, whether any of your
workers can serve them, and the exact command to declare each. This document
explains the table and how to set each upstream up.

## The routes

| Buyer product | Route | Upstream host | Key flag |
|---|---|---|---|
| `zai/glm-5.2` | `deepinfra/zai-org/GLM-5.2` | `api.deepinfra.com` | `--deepinfra` |
| `zai/glm-5.2` | `engy/glm-5.2` | `api.engy.ai` | `--engy` |
| `moonshot/kimi-k3` | `kubetee/moonshotai/kimi-k3` | `llm.kubetee.ai` | `--kubetee` |
| `moonshot/kimi-k3` | `engy/kimi-k3` | `api.engy.ai` | `--engy` |

Both buyer products can also be served **direct** — with a Z.ai key (`--zai`) or a
Moonshot key (`--moonshot`). Direct is not the canonical route, but it does carry one
concrete advantage: where a worker could serve a product both directly and through a
route, the router keeps the direct one (see below).

Routes are absent from the public catalog (`gmcli pricing`, and the registry's
buyer-facing `GET /products`): they are dispatch targets, not products a buyer can
ask for by name. `gmcli sources` is where they appear.

### Cloud upstreams for a direct product

Three routes are selected per worker rather than declared as a separate product,
because the product id is unchanged:

| Buyer product | Route | Selector |
|---|---|---|
| `anthropic/*` | AWS Bedrock | `--anthropic-upstream bedrock` |
| `anthropic/*` | Claude on Microsoft Foundry | `--anthropic-upstream foundry` (see [foundry-setup.md](foundry-setup.md)) |
| `openai/*` | Azure OpenAI | `--openai-upstream azure` |

Same idea, different mechanism — these are set once per worker and apply to every
model from that provider.

## One route per buyer product per worker

A worker may hold keys for several upstreams, but it can only serve **one route
per buyer product**. If a single worker declares both `deepinfra/zai-org/GLM-5.2`
and `engy/glm-5.2`, the router keeps one of them and ignores the other: it draws
from a pool keyed by worker, so two routes from one worker would be the same
worker twice. A direct offer always wins over a route; between two routes the
outcome is not one you should rely on.

To run two upstreams for the same buyer product, put them on **separate workers**,
each holding only that upstream's key.

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

## Setting up a route

Three steps, in order.

**1. Set the upstream key.** Keys are baked into your TEE at deploy time and are
never seen by gm:

```sh
gmcli set-api-keys --deepinfra <key>
gmcli set-api-keys --engy <key>
gmcli set-api-keys --kubetee <key>
```

Like the other upstream flags, each accepts up to 8 semicolon-separated keys and
the miner advertises opaque slot ids for them — see
[multi-key-slots.md](multi-key-slots.md).

**2. Deploy, so the key reaches a worker.**

```sh
gmcli deploy
```

The registry probes each worker for the models it can actually reach. Until that
probe succeeds, the route shows `YOU SERVE: no` and declaring it would only
produce an ineligible offer.

**3. Declare the route.** Use the **route** pair, not the buyer pair:

```sh
gmcli declare-product --provider engy --model glm-5.2 --discount-pct 5
```

`gmcli sources` prints this line for you, pre-filled, for every route you can
serve and have not declared yet.

Note that `declare-products` (the fan-out) is catalog-only on purpose and will not
declare a route. A route offer commits you to an upstream you hold a key for, so
each one is declared individually.

To withdraw a route later, `gmcli undeclare-product --provider engy --model
glm-5.2`. The registry keeps the row for audit and re-declaring re-offers it.

## Why a route shows `YOU SERVE: no`

The count is how many of your workers hold a usable key for that upstream and are
on an approved image today. Zero means declaring it buys you nothing yet. It is a
capability count, not final admission: if one worker can serve two routes for the
same buyer product, it is counted under both, and only one of them will be routed.
In rough order of frequency:

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
