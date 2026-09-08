# Gemini image canary

The image canary is an explicit, paid testnet check for the two native Gemini
image products:

```text
gemini/gemini-3.1-flash-lite-image
gemini/gemini-3.1-flash-image
```

It is not part of `gmcli doctor` or `gmcli check-streaming`. Routine worker
health checks stay text-only so they cannot unexpectedly generate an image.
The SKU definitions, publication, discovery, and declaration are supported on
both networks. The funded canary remains deliberately testnet-only so routine
or mainnet operator commands cannot unexpectedly spend buyer credit.

## Run it

Use a funded GM buyer API key, not the Google provider key stored in a worker:

```sh
GM_API_KEY=<funded-testnet-buyer-key> \
  gmcli --network testnet image-canary
```

`--buyer-api-key` is also accepted. The command uses
`https://test-api.saygm.com` by default. `GM_GATEWAY_URL` or `--gateway-url`
can override that host for local/mock verification, but the command still
refuses every network except explicit testnet.

Before spending, it requests:

```text
GET /v1/models?api_shape=generateContent
```

Both exact image SKU ids must be present with `available: true`. If either
live eligible offer is missing, the command exits before reading credits or
sending either paid generation request.

If both offers are present, it sends exactly one non-streaming native request
per SKU:

```text
POST /v1beta/models/{model}:generateContent
```

The fixed private probe asks for one `IMAGE` candidate at `imageSize: "1K"`
(`candidateCount: 1`). It includes no `tools` field, so grounding/search is
not requested. The generated image and the probe prompt are never printed or
written to disk.

A `200` response is accepted only when it contains at least one non-empty
image `inlineData` part under `candidates[].content.parts[]` and reports
positive image-output usage. A text-only response, safety/refusal response,
empty image part, or response with zero image-output usage fails the SKU and
the canary exits non-zero.

## JSONL output

Once paid probes are dispatched, stdout contains one `record: "probe"` JSON
object per SKU in request order, followed by exactly one
`record: "summary"` object. The summary is emitted even when both probes fail.
The pre-spend missing-offer gate emits no JSONL because no probe or balance
run occurred.

A probe record always contains:

```text
record              "probe"
model               exact image SKU
outcome             "succeeded" or "failed"
billing_status      "settled", "unbilled", or "unknown"
reconciliation      run-level balance state
```

`request_id` is present when the gateway header or native response supplied
one. `http_status` is present when an HTTP response was received. Successful
probes also contain `usage` and `settled_ndollars` (nUSD). Failed probes retain
`settled_ndollars` when the gateway authoritatively reports a settled charge;
their optional `failure` is a bounded category or HTTP status, never the
provider error body. `billing_status: "unbilled"` is authoritative evidence of
no charge, while `"unknown"` means the canary cannot determine whether the
attempt was charged.

Both probe records include `balance_before_ndollars`,
`balance_after_ndollars`, and `balance_delta_ndollars` when the corresponding
`/v1/credits` reads are available. These are run-level values repeated for
convenience and must not be attributed to an individual SKU.

The final summary record contains:

```text
record                     "summary"
successful_probes          number of accepted image responses
failed_probes              number of failed probes
known_settled_ndollars     sum of authoritative successful and failed charges
unknown_billing_probes     number of attempts with unknown billing
balance_before_ndollars    optional run-level starting balance
balance_after_ndollars     optional run-level ending balance
balance_delta_ndollars     optional observed run-level debit
reconciliation             "ok", "unknown", "unavailable", or "mismatch"
```

`known_settled_ndollars` is omitted only if the checked sum overflows. That is
a reconciliation mismatch and the command exits non-zero.

Gemini's `candidatesTokenCount` is visible candidate output and excludes
`thoughtsTokenCount`. The report keeps visible text output and
`reasoning_tokens` separate, retains `toolUsePromptTokenCount` separately,
and treats `totalTokenCount` as prompt + candidates + tool-use prompt +
thoughts (with that sum as the fallback when total is omitted). This keeps
usage evidence from counting thoughts twice or treating them as visible
output.

If either native request fails, both safe probe records and the run summary are
still emitted and the command exits non-zero with an explicit partial-failure
error. A balance mismatch likewise emits the safe records before failing. A
successful native response is streamed into a bounded buffer capped at 16
MiB; declared and chunked responses over that limit fail without unbounded
allocation. A non-2xx gateway error envelope is separately capped at 64 KiB,
and only its allowlisted billing fields are retained.

If both balances are available, `"ok"` means their decrease equals all known
settled charges, including charges attached to failed requests. `"unknown"`
means the known charges do not contradict the balance but at least one probe's
billing is uncertain. `"mismatch"` means the observed balance contradicts the
known charges. When either balance is unavailable, reconciliation is
`"unavailable"` rather than inventing a balance result. The canary captures
only response and balance evidence. Downstream validator
admission/settlement, finalizer artifacts, and dashboard evidence are separate
checks in the GM runbook.
