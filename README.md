# gm-miner

Miner image and CLI for the gm Bittensor subnet.

| Path | Owner | Description |
|---|---|---|
| `image/` | W4 | Envoy-only miner image with three provider routes (Anthropic / OpenAI / Gemini). Pinned to digest. The runtime is `envoy` plus its native `/stats/prometheus` exposure — no sidecar service. |
| `cli/` | W4 | `gm-miner` CLI (Rust + clap). Login via Taostats device-code OAuth; register image; declare products + prices; check status. Runs operator-side from a laptop, not inside the TEE. |
| `dstack/` | W4 | dstack-cloud compose template + `app.json` skeleton for operators. |
| `docs/` | W4 | Operator-facing docs including reproducibility caveats. |

This repository is **scaffolded by Phase 0** (`agent-foundation`) and
**implemented by Phase 1's `agent-miner` workstream W4**. Contracts the
miner publishes (capability response shapes, dstack attestation
conventions) live in the gm repo's `docs/contracts/`.

## Getting started for Phase 1 / W4

```bash
git clone git@github-taostat:taostat/gm-miner.git
cd gm-miner
wt switch phase1/miner   # see workstreams.md
```

Workstream scope and Definition of Done in
`taostat/gm` → `workstreams.md` → W4.

## License

Apache-2.0.
