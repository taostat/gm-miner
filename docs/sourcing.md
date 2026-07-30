# Sourcing routes: serving a buyer product from a cheaper upstream

Most gm products are served direct: a buyer asks for `anthropic/claude-sonnet-4-6`,
you hold an Anthropic key, and your worker calls `api.anthropic.com`. A **sourcing
route** is the other case — a buyer product you serve from a *different, cheaper*
upstream. Buyers see the product they asked for; you buy the capacity wherever it
is cheapest and keep the difference.

Run `gmcli sources` to see which routes are available to you right now, whether
any of your workers can serve them, and the exact command to declare each one.
This document explains what the table means and how to set each upstream up.

## The routes

| Buyer product | Served from | Upstream host | Key flag |
|---|---|---|---|
| `zai/glm-5.2` | `deepinfra/zai-org/GLM-5.2` | `api.deepinfra.com` | `--deepinfra` |
| `moonshot/kimi-k3` | `kubetee/moonshotai/kimi-k3` | `llm.kubetee.ai` | `--kubetee` |

Both buyer products can also be served **direct** — with a Z.ai key (`--zai`) or a
Moonshot key (`--moonshot`) — if that is cheaper for you. A sourcing route is an
additional option, never a replacement.

Sourcing routes are deliberately absent from the public catalog (`gmcli pricing`,
and the registry's buyer-facing `GET /products`): they are internal dispatch
targets, not products a buyer can ask for by name. `gmcli sources` is the only
place they appear.

### Related: alternate upstreams for a direct product

Two direct products can be served through a cloud reseller instead of the
provider's own API. These are *not* sourcing routes — the product id is unchanged
and you declare them normally — but they are the same idea:

| Buyer product | Alternate upstream | Selector |
|---|---|---|
| `anthropic/*` | AWS Bedrock | `--anthropic-upstream bedrock` |
| `anthropic/*` | Claude on Microsoft Foundry | `--anthropic-upstream foundry` (see [foundry-setup.md](foundry-setup.md)) |
| `openai/*` | Azure OpenAI | `--openai-upstream azure` |

## How you are paid

Settlement is always on the **buyer** product's retail, never the source's:

```
your rate per Mtok = buyer_retail x (10000 - discount_bp) / 10000
```

So for `zai/glm-5.2` at a buyer retail of $1.40 in / $4.40 out, declaring the
DeepInfra route at `--discount-pct 5` pays you:

```
in:  $1.40 x 9500 / 10000 = $1.330 per Mtok
out: $4.40 x 9500 / 10000 = $4.180 per Mtok
```

Your spread is that figure minus whatever DeepInfra charges you for the same
tokens. `gmcli sources` shows the buyer retail in the `BUYER RETAIL / MTOK`
column so you can compute the left-hand side; the right-hand side is between you
and the upstream.

> **The source product's own catalog price is not your cost.** The registry
> carries a price row for `deepinfra/zai-org/GLM-5.2`, but it is set to mirror the
> buyer product — it exists so the dispatch machinery has a well-formed row, not
> to describe what DeepInfra bills you. Get your real cost from the upstream's own
> pricing page. This is why the endpoint does not surface it and why `gmcli
> sources` does not show it.

## Setting up a route

Three steps, in order.

**1. Set the upstream key.** Keys are baked into your TEE at deploy time and are
never seen by gm:

```sh
gmcli set-api-keys --deepinfra <key>
gmcli set-api-keys --kubetee <key>
```

Like the other direct-upstream flags, each accepts up to 8 semicolon-separated
keys and the miner advertises opaque slot ids for them — see
[multi-key-slots.md](multi-key-slots.md).

**2. Deploy, so the key reaches a worker.**

```sh
gmcli deploy
```

The registry probes each worker for the models it can actually reach. Until that
probe succeeds, the route shows `YOU SERVE: no` and declaring it would only
produce an ineligible offer.

**3. Declare the route.** Use the **source** pair, not the buyer pair:

```sh
gmcli declare-product --provider deepinfra --model zai-org/GLM-5.2 --discount-pct 5
```

`gmcli sources` prints this line for you, pre-filled, for every route you can
serve and have not declared yet.

Note that `declare-products` (the fan-out) is catalog-only on purpose and will
not declare a sourcing route. A source offer commits you to an upstream you hold
a key for, so each one is declared individually.

To withdraw a route later, `gmcli undeclare-product --provider deepinfra --model
zai-org/GLM-5.2`. The registry keeps the row for audit and re-declaring re-offers
it.

## Why a route shows `YOU SERVE: no`

The count is how many of your workers the router would admit for that upstream
today. Zero means declaring it buys you nothing yet. In rough order of frequency:

- The key is not set, or was set after your last deploy — run `gmcli set-api-keys`
  then `gmcli deploy`.
- The worker has not been probed since it came up. Wait a cycle and re-check.
- The worker is on an image version the registry no longer approves — `gmcli
  worker list` shows each worker's status and last attestation.
- The worker was just restored from suspension; its supported-model list is
  cleared and repopulates on the next probe.

A zero is not by itself proof the key is missing, which is why `gmcli sources`
words it as "no worker of yours is currently serving" rather than blaming the key.

## Why a route might not appear at all

`gmcli sources` lists a route only when both the buyer product row and the source
product row are active in the catalog and the buyer's retail block parses. If a
route you expect is missing, it has been withdrawn from the catalog rather than
hidden from you specifically — the table is self-scoped, but the *set* of routes
is the same for every miner.

If the command reports that the registry "does not publish sourcing routes yet",
your registry predates the endpoint; nothing on your side to fix.

If `gmcli sources` is not recognised at all, your CLI is older than v0.3.12.
Re-run the installer from the [README](../README.md#quick-start) to upgrade.
