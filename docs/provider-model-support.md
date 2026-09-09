# Miner model sourcing matrix

Use this table to answer one question: **I want to provide a model — where can
I source it from?**

Snapshot date: **2026-09-09**. This is a miner setup matrix, not a buyer product
catalog. It distinguishes transport capability from registry admission:

* A direct/API-key source is declarable when the registry publishes the route
  and the worker passes its normal capability checks.
* Direct Anthropic/OpenAI supply additionally requires verified key slots enforced
  inside the miner runtime.
* Azure OpenAI chat completions and Microsoft Foundry Messages forward request
  bodies unchanged through Envoy. Cloud registration, recovery and declaration
  require registry capability `upstream-model-echo`; `gmcli deploy` also checks
  the approved image for `upstream-model-hop`. Declarations leave per-worker
  eligibility to the registry. Azure Responses is unqualified because its echo
  is the deployment name; Bedrock inference is disabled inside the image until
  its transport has an authoritative model echo. A known model id or a
  successful HTTP probe is not sufficient.

Name each Azure OpenAI or Foundry deployment **exactly the canonical gm model id**.
The image enumerates the bound account's deployments through ARM. Each deployment
named X in that adapter's catalog must serve model X with format `OpenAI` (Azure
OpenAI) or `Anthropic` (Foundry), using exact ASCII comparison. A mismatch blocks
boot or takes the worker offline on the 60-second deployment poll. Non-catalog
names are ignored by this binding check; absent deployments are the registry's
per-offer probe and gateway's concern. The gateway's per-response echo check and
registry contract remain unchanged.

`gmcli doctor` lists ARM name, format, model and version, flags every catalog-named
violation and sends one 1-token probe per honestly named catalog deployment,
printing the echoed `model` against its name. Offers use canonical `provider/model`.

See [Foundry setup](foundry-setup.md) for deployment creation prerequisites,
the creation API version, and the replacement procedure. The verifier reads
deployment identities; it does not create or replace deployments.

The backticked `provider/model` is the pair to pass to
`gmcli declare-product` for a direct route. See
[sourcing.md](sourcing.md) for complete commands and route selection rules. Run
`gmcli sources` against your chosen network before deploying: it is the live
authority for which explicit routes that registry has published.

| Model you want to provide | Supported sources |
|---|---|
| `claude-fable-5` | Anthropic API: `anthropic/claude-fable-5` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-fable-5-1` | Anthropic API: `anthropic/claude-fable-5-1` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-haiku-4-5` | Anthropic API: `anthropic/claude-haiku-4-5` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-opus-4-6` | Anthropic API: `anthropic/claude-opus-4-6` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-opus-4-7` | Anthropic API: `anthropic/claude-opus-4-7` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-opus-4-8` | Anthropic API: `anthropic/claude-opus-4-8` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-opus-5` | Anthropic API: `anthropic/claude-opus-5` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-sonnet-4-6` | Anthropic API: `anthropic/claude-sonnet-4-6` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-sonnet-5` | Anthropic API: `anthropic/claude-sonnet-5` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `DeepSeek V3.2 TEE` | Chutes: `chutes/deepseek-ai/DeepSeek-V3.2-TEE` (`--chutes`) |
| `DeepSeek V4 Flash 0731` | KubeTEE: `kubetee/deepseek/deepseek-v4-flash-0731` (`--kubetee`); Engy: `engy/deepseek-v4-flash-0731` (`--engy`); DeepInfra: `deepinfra/deepseek-ai/DeepSeek-V4-Flash-0731` (`--deepinfra`) |
| `DeepSeek V4 Flash 0731 TEE` | Chutes: `chutes/deepseek-ai/DeepSeek-V4-Flash-0731-TEE` (`--chutes`); NEAR confidential inference: `near/deepseek-ai/DeepSeek-V4-Flash` (`--near`) |
| `Gemma 4 31B Turbo TEE` | Chutes: `chutes/google/gemma-4-31B-turbo-TEE` (`--chutes`); NEAR confidential inference: `near/google/gemma-4-31B-it` (`--near`) |
| `Gemini 3.1 Flash Lite Image` | Google native `generateContent`: `gemini/gemini-3.1-flash-lite-image` (`--google`) |
| `Gemini 3.1 Flash Image` | Google native `generateContent`: `gemini/gemini-3.1-flash-image` (`--google`) |
| `Gemini 3.1 Pro Preview` | Google: `gemini/gemini-3.1-pro-preview` (`--google`) |
| `Gemini 3.5 Flash` | Google: `gemini/gemini-3.5-flash` (`--google`) |
| `GLM-5.1 TEE` | Chutes: `chutes/zai-org/GLM-5.1-TEE` (`--chutes`); NEAR confidential inference: `near/zai-org/GLM-5.1-FP8` (`--near`) |
| `GLM-5.2` | Z.ai API: `zai/glm-5.2` (`--zai`); DeepInfra: `deepinfra/zai-org/GLM-5.2` (`--deepinfra`); Engy: `engy/glm-5.2` (`--engy`); KubeTEE: `kubetee/z-ai/glm-5.2` (`--kubetee`); Moonmath ZRO: `moonmath/glm-5.2` (`--moonmath`) |
| `GLM-5.2 TEE` | Chutes: `chutes/zai-org/GLM-5.2-TEE` (`--chutes`); NEAR confidential inference: `near/z-ai/glm-5.2` (`--near`) |
| `GLM-5.3` | Z.ai API: `zai/glm-5.3` (`--zai`); KubeTEE: `kubetee/z-ai/glm-5.3` (`--kubetee`); Engy: `engy/glm-5.3` (`--engy`) |
| `GLM-5.3-Flash` | Z.ai API: `zai/glm-5.3-flash` (`--zai`); KubeTEE: `kubetee/z-ai/glm-5.3-flash` (`--kubetee`); Engy: `engy/glm-5.3-flash` (`--engy`) |
| `GPT-5.4` | OpenAI API: `openai/gpt-5.4` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.4 mini` | OpenAI API: `openai/gpt-5.4-mini` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.4 nano` | OpenAI API: `openai/gpt-5.4-nano` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.5` | OpenAI API: `openai/gpt-5.5` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.5 Pro` | OpenAI API: `openai/gpt-5.5-pro` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.6` | OpenAI API: `openai/gpt-5.6` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.6 Luna` | OpenAI API: `openai/gpt-5.6-luna` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.6 Sol` | OpenAI API: `openai/gpt-5.6-sol` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.6 Terra` | OpenAI API: `openai/gpt-5.6-terra` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `Kimi K2.6 TEE` | Chutes: `chutes/moonshotai/Kimi-K2.6-TEE` (`--chutes`) |
| `Kimi K3` | Moonshot API: `moonshot/kimi-k3` (`--moonshot`); DeepInfra: `deepinfra/moonshotai/Kimi-K3` (`--deepinfra`); KubeTEE: `kubetee/moonshotai/kimi-k3` (`--kubetee`); Engy: `engy/kimi-k3` (`--engy`); Moonmath ZRO: `moonmath/kimi-k3` (`--moonmath`) |
| `Kimi K3 TEE` | Chutes: `chutes/moonshotai/Kimi-K3-TEE` (`--chutes`) |
| `Mistral Nemo Instruct 2407 TEE` | Chutes: `chutes/unsloth/Mistral-Nemo-Instruct-2407-TEE` (`--chutes`) |
| `Nemotron 3 Nano Omni 30B TEE` | Chutes: `chutes/Nemotron-3-Nano-Omni-30B-TEE` (`--chutes`) |
| `o3` | OpenAI API: `openai/o3` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `o4-mini` | OpenAI API: `openai/o4-mini` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `Ornith 1.5 397B` | KubeTEE: `kubetee/ornith/ornith-1.5-397b` (`--kubetee`); Engy: `engy/ornith-1.5-397b` (`--engy`) |
| `Qwen3 235B A22B Thinking 2507 TEE` | Chutes: `chutes/Qwen/Qwen3-235B-A22B-Thinking-2507-TEE` (`--chutes`) |
| `Qwen3 32B TEE` | Chutes: `chutes/Qwen/Qwen3-32B-TEE` (`--chutes`) |
| `Qwen3.5 397B A17B TEE` | Chutes: `chutes/Qwen/Qwen3.5-397B-A17B-TEE` (`--chutes`) |
| `Qwen3.6 35B A3B` | Engy: `engy/qwen3.6-35b-a3b` (`--engy`); DeepInfra: `deepinfra/Qwen/Qwen3.6-35B-A3B` (`--deepinfra`) |
| `Qwen3.6 27B TEE` | Chutes: `chutes/Qwen/Qwen3.6-27B-TEE` (`--chutes`); NEAR confidential inference: `near/Qwen/Qwen3.6-27B-FP8` (`--near`) |
| `Qwen3.8 27B` | Engy: `engy/qwen3.8-27b` (`--engy`); DeepInfra: `deepinfra/Qwen/Qwen3.8-27B` (`--deepinfra`) |
| `Qwen3.8 27B TEE` | NEAR confidential inference: `near/Qwen/Qwen3.8-27B` (`--near`) |
| `Qwen3.8-Flash-Next` | KubeTEE: `kubetee/qwen/qwen3.8-flash-next` (`--kubetee`) |

The two Gemini image SKUs use the native
`POST /v1beta/models/{model}:generateContent` request shape. Envoy forwards
that path and body unchanged to Google's Gemini API; there is no Interactions
route in the MVP. Routine capability/health probes stay text-only and must not
request image output, so a probe does not create a paid image.

These definitions, publication, discovery, and declaration are supported on
both networks. Pass `--network` explicitly when changing an image offer so the
intended registry is unambiguous. A funded comparison is available only as the
deliberate
`gmcli --network testnet image-canary` command; it checks
`/v1/models?api_shape=generateContent` for both live eligible SKUs, sends one
non-streaming native request per SKU with `candidateCount=1`, `imageSize=1K`,
`responseModalities=["IMAGE"]`, and no `tools`/grounding, then prints model,
request id, usage dimensions, settled nUSD, and optional before/after balance.
The canary captures only response and balance reconciliation evidence;
validator, finalizer, and dashboard evidence belongs to a separate GM
runbook check. It never prints its prompt, generated image, or either key.
See [`image-canary.md`](image-canary.md).

`gmcli check-streaming` also skips these native image SKUs because its
streaming check targets the OpenAI-compatible SSE surface; it never sends an
image-generation probe.
