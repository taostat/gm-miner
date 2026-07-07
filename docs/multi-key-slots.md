# Multi-Key Upstream Slots

Direct upstream provider keys can be configured as semicolon-separated values
in the existing key variables:

```sh
gmcli set-api-keys --anthropic "sk-ant-a;sk-ant-b;sk-ant-c"
gmcli set-api-keys --openai "sk-a;sk-b"
gmcli set-api-keys --google "AIza-a;AIza-b"
gmcli set-api-keys --chutes "cpk-a;cpk-b"
```

At deploy time `gmcli` derives opaque 12-character slot ids from each trimmed
key and the worker's `GM_NODE_SECRET`, then advertises those ids to the
registry. The key values stay inside the TEE; rendered Envoy config contains
only slot ids and per-slot environment variable names.

The gateway chooses a slot per request with `x-gm-upstream-slot`. If the header
is absent, the first key in the configured list is used. Empty segments and
more than 8 entries for a provider fail fast. Repeated keys are de-duplicated
while preserving the first occurrence order.

Cloud backends are single-slot in this release: do not use semicolons in
`BEDROCK_API_KEY` or `AZURE_OPENAI_API_KEY`.

Protocol authority lives in the gm repo:
<https://github.com/taostat/gm/blob/main/docs/contracts/upstream-key-slots.md>.
