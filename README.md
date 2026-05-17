# gm-miner

Miner image and CLI for the gm Bittensor subnet.

| Path | Owner | Description |
|---|---|---|
| `image/` | W4 | Envoy-based miner image with three provider routes (Anthropic / OpenAI / Gemini). Pinned to digest. |
| `capability/` | W4 | Rust binary inside the image: per-provider capability check endpoints (free, registry-only) plus a Prometheus exporter. |
| `cli/` | W4 | `gm-miner` CLI (Rust + clap). Login via Taostats device-code OAuth; register image; declare products + prices; check status. |
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
