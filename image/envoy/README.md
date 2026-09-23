# Miner Envoy config

The miner's data plane is one Envoy process. Its config is assembled at
container start from this directory:

- `base.yaml`: the parts every miner shares. That is the listeners, the
  node-key and slot-selection Lua filter, the rate limit, the attestation
  route, the 501 catch-all and the loopback clusters.
- `upstreams/*.yaml`: one file per upstream, holding its routes, its cluster
  and its key-slot settings.

`start.sh` validates the environment, then runs the hidden
`gmcli render-envoy` (`cli/src/envoy_render.rs`), which writes
`/tmp/envoy.rendered.yaml` for Envoy to load. The directory is copied into the
image, so every file here is covered by the image digest and so by the
attested `compose_hash`.

CI loads every rendered variant into the pinned Envoy image with
`envoy --mode validate` (`scripts/validate-envoy.sh`). Run it locally with
Docker after changing anything here.

## Rendering

1. **Tokens.** Every `__GM_<NAME>__` in a file's text is replaced by the
   `GM_<NAME>` environment variable in one pass. Inserted values are never
   rescanned, so a node secret that looks like a token stays literal. An unset
   variable fails the render.
2. **Splicing.** Each selected upstream's routes replace the
   `- gm:upstream-routes` item in `base.yaml`, and its clusters replace
   `- gm:upstream-clusters`. Files load in file-name order. That order does
   not matter because every upstream route matches a different
   `x-gm-provider` value.
3. **Header strip.** Every upstream route gets the gm-internal headers
   (`x-gm-request-id`, `x-gm-gateway-sig`, `x-gm-product`, `x-gm-node-key`,
   `x-gm-provider`, `x-gm-upstream-slot`) appended to its
   `request_headers_to_remove`. Upstream files list only the extra headers a
   route removes.
4. **Slot config.** The Lua filter's `slot_config` table is generated from
   each upstream's `slots` block plus the `GM_<PROVIDER>_SLOT_IDS` variable
   that `gmcli slot-env` exported.

## Upstream files

A file is named for the `x-gm-provider` value it serves. A provider with more
than one way to reach its model ships variant files, `<provider>.<variant>.yaml`,
and `start.sh` picks exactly one with `--select <provider>=<variant>`
(`anthropic.direct` / `.foundry` / `.bedrock`, `openai.direct` / `.azure`).

```yaml
slots:                        # omit for an upstream without keys (benchmark)
  direct_env: CHUTES_API_KEY  # used when the key is not split into slots
  auth_header: authorization  # header Lua sets from the selected key
  auth_prefix: "Bearer "      # prepended to the key; default ""
  cloud: false                # true: a route adds the key, Lua only checks the slot
  disabled: false             # true: every request is refused (Bedrock)
routes: [ ... ]               # Envoy route objects, in match order
clusters: [ ... ]             # Envoy cluster objects
```

A direct upstream (not `cloud`, not `disabled`) must name an `auth_header`.

### Adding a supplier

Add `upstreams/<provider>.yaml`, then complete the rest of the checklist in
`CLAUDE.md` (the `Provider` enum, the key flag, `start.sh`'s key guard and
`fan_out_slots` call, the compose env passthrough, and so on).

## Route conventions

These apply to every provider route unless its file says otherwise.

- **`timeout: 1800s`**, the same as the HCM's `stream_idle_timeout`. The route
  timeout caps a request that streams continuously, such as a 10–20 minute
  reasoning stream. The idle timeout caps a silent one: a `stream: false`
  request, or an upstream that buffers the whole completion and sends it in
  one burst. Envoy cannot tell a silently reasoning upstream from a hung one,
  so a hung connection is held for up to 30 minutes.
- **One retry, before response headers only:**
  `retry_on: reset,connect-failure,refused-stream,5xx`. Envoy retries only
  before headers reach the caller, so a retry never duplicates a stream the
  gateway has started billing.
  - 429 is not retried. The gateway's cooldown logic reads the 429, and
    retrying would hide quota exhaustion while hammering the upstream.
  - There is no `per_try_timeout`, because it would cut long generations.
  - A body larger than the connection buffer cannot be replayed, so Envoy
    skips that retry.
- **No retry** on non-idempotent paths (DeepInfra `/v1/inference/`, KubeTEE
  image generation), on the loopback NEAR, Chutes-verifier and attestation routes (a retry
  would mask a local failure), or on benchmark (it would distort the
  measurement). The Lua filter also strips caller-supplied `x-envoy-retry-*`
  headers on the two non-idempotent paths.
- **Keyless probes see a 401.** A direct route stays in place when its key is
  unset. Lua then sends an empty key, the upstream answers 401, and the
  registry reads "no key" the same way it reads "key revoked".

## Data plane design

- **RA-TLS.** The `:8080` listener terminates TLS with a certificate that
  `gm-miner-ratls` mints from the dstack guest agent (`GetTlsKey` with
  `usage_ra_tls`). The certificate carries a TDX quote whose `report_data`
  commits to the key. Callers use the dstack gateway's TLS-passthrough URL
  (`<app-id>-8080s`), so the certificate they receive is this one, not the
  gateway's. The certificate is self-signed: trust comes from the quote, and
  a plain `curl` needs `-k`.
- **Node key.** The Lua filter rejects any request without the right
  `x-gm-node-key`, before routing, except `/attestation/info`, which is
  public by contract. With `GM_NODE_SECRET` unset the check is skipped, which
  is the legacy open data plane.
- **Load shedding.** A process-wide token bucket (500 requests per second)
  returns a JSON 429, the saturation signal the gateway and registry act on.
  `/attestation/info` is exempt. The overload manager's 8192-connection cap
  guards against file-descriptor exhaustion and is sized to fire only in a
  flood. Past it, connections are refused at accept time with no status
  code.
- **Error bodies.** Local replies are JSON: 401 for the node key, 421 for an
  unavailable key slot, 429 when rate limited, 501 for an unknown provider,
  and 502 for an upstream that failed before responding. Provider error
  responses pass through byte for byte. The 502 body must never contain a
  provider-drain phrase (quota, credit, billing, account, api key), because
  the gateway matches those substrings on any status.
- **Metrics.** `:9902` exposes only `/stats/prometheus`, gated on the node
  key. The full admin interface stays on loopback `:9901`.
