# Miner model sourcing matrix

Use this table to answer one question: **I want to provide a model — where can
I source it from?**

Snapshot date: **2026-10-29**. This is a miner setup matrix, not a buyer product
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
  is the deployment name. Bedrock Mantle accepts models listed in the fixed
  network-selected registry binding snapshot in `us-east-1`; it requires the
  `bedrock-mantle-model-bindings-v1` approved image feature and the selected
  binding's row revision. The measured adapter validates the raw provider
  response identity, then canonicalizes the response model before content release.
  Older images and unadmitted models remain unavailable. A known model id
  or successful HTTP probe is not sufficient.

Bedrock bindings refresh every 60 seconds and expire 120 seconds after the last
successful refresh. Failed refreshes do not extend validity. The adapter rechecks
the current binding after reading the request body and immediately before dispatch.
Requests already dispatched finish against the binding captured for that request;
a later mapping change does not replay or retarget them.

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

Sources marked **disabled in catalog** have miner transport support, but their
routes are disabled in the curated catalog. They are listed for completeness;
their presence here does not establish registry admission.

| Model you want to provide | Sources and admission status |
|---|---|
| `claude-fable-5` | Anthropic API: `anthropic/claude-fable-5` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-fable-5-1` | Anthropic API: `anthropic/claude-fable-5-1` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-haiku-4-5` | Anthropic API: `anthropic/claude-haiku-4-5` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-haiku-5-5` | Anthropic API: `anthropic/claude-haiku-5-5` (`--anthropic`) |
| `claude-opus-4-7` | Anthropic API: `anthropic/claude-opus-4-7` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-opus-4-8` | Anthropic API: `anthropic/claude-opus-4-8` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-opus-5` | Anthropic API: `anthropic/claude-opus-5` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-opus-5-5` | Anthropic API: `anthropic/claude-opus-5-5` (`--anthropic`) |
| `claude-sonnet-4-6` | Anthropic API: `anthropic/claude-sonnet-4-6` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-sonnet-5` | Anthropic API: `anthropic/claude-sonnet-5` (`--anthropic`); Microsoft Foundry: ARM-verified transport, feature-gated admission |
| `claude-sonnet-5-5` | Anthropic API: `anthropic/claude-sonnet-5-5` (`--anthropic`) |
| `DeepSeek V3.2 TEE` | Chutes: `chutes/deepseek-ai/DeepSeek-V3.2-TEE` (`--chutes`) |
| `DeepSeek V4 Flash 0731` | Engy: `engy/deepseek-v4-flash-0731` (`--engy`); DeepInfra: `deepinfra/deepseek-ai/DeepSeek-V4-Flash-0731` (`--deepinfra`); Chutes (TEE sibling): `chutes/deepseek-ai/DeepSeek-V4-Flash-0731-TEE` (`--chutes`) |
| `DeepSeek V4 Flash 0731 TEE` | Chutes: `chutes/deepseek-ai/DeepSeek-V4-Flash-0731-TEE` (`--chutes`) |
| `DeepSeek V4.1 Flash` | DeepInfra: `deepinfra/deepseek-ai/DeepSeek-V4.1-Flash` (`--deepinfra`); Engy: `engy/deepseek-v4.1-flash` (`--engy`); KubeTEE (TEE sibling): `kubetee/deepseek/deepseek-v4.1-flash` (`--kubetee`) |
| `DeepSeek V4.1 Flash TEE` | KubeTEE: `kubetee/deepseek/deepseek-v4.1-flash` (`--kubetee`) |
| `DeepSeek V4.1 Flash 1017` | KubeTEE (TEE sibling): `kubetee/deepseek/deepseek-v4.1-flash-1017` (`--kubetee`) |
| `DeepSeek V4.1 Flash 1017 TEE` | KubeTEE: `kubetee/deepseek/deepseek-v4.1-flash-1017` (`--kubetee`) |
| `FLUX.2 klein 4B` | DeepInfra: `deepinfra/black-forest-labs/FLUX-2-klein-4b` (`--deepinfra`); NEAR confidential inference (**disabled in catalog**): `near/black-forest-labs/FLUX.2-klein-4B` (`--near`); KubeTEE (**disabled in catalog**): `kubetee/black-forest-labs/flux.2-klein-4b` (`--kubetee`) |
| `Gemini 3.1 Flash Image` | Google native `generateContent`: `gemini/gemini-3.1-flash-image` (`--google`) |
| `Gemini 3.1 Flash Lite` | Google: `gemini/gemini-3.1-flash-lite` (`--google`) |
| `Gemini 3.1 Flash Lite Image` | Google native `generateContent`: `gemini/gemini-3.1-flash-lite-image` (`--google`) |
| `Gemini 3.1 Pro Preview` | Google: `gemini/gemini-3.1-pro-preview` (`--google`) |
| `Gemini 3.5 Flash Lite` | Google: `gemini/gemini-3.5-flash-lite` (`--google`) |
| `Gemini 3.6 Flash` | Google: `gemini/gemini-3.6-flash` (`--google`) |
| `Gemini 3.8 Flash` | Google: `gemini/gemini-3.8-flash` (`--google`) |
| `Gemini 4 Argon` | Google: `gemini/gemini-4-argon` (`--google`) |
| `Gemma 4 31B Turbo TEE` | Chutes: `chutes/google/gemma-4-31B-turbo-TEE` (`--chutes`) |
| `GLM-5.1 TEE` | Chutes: `chutes/zai-org/GLM-5.1-TEE` (`--chutes`) |
| `GLM-5.2` | Z.ai API: `zai/glm-5.2` (`--zai`); DeepInfra: `deepinfra/zai-org/GLM-5.2` (`--deepinfra`); Engy: `engy/glm-5.2` (`--engy`); Moonmath ZRO: `moonmath/glm-5.2` (`--moonmath`); Chutes (TEE sibling): `chutes/zai-org/GLM-5.2-TEE` (`--chutes`); KubeTEE (TEE sibling): `kubetee/z-ai/glm-5.2` (`--kubetee`) |
| `GLM-5.2 TEE` | Chutes: `chutes/zai-org/GLM-5.2-TEE` (`--chutes`); KubeTEE: `kubetee/z-ai/glm-5.2` (`--kubetee`) |
| `GLM-5.3` | Z.ai API: `zai/glm-5.3` (`--zai`); Engy: `engy/glm-5.3` (`--engy`); DeepInfra: `deepinfra/zai-org/GLM-5.3` (`--deepinfra`); KubeTEE (TEE sibling): `kubetee/z-ai/glm-5.3` (`--kubetee`) |
| `GLM-5.3 TEE` | KubeTEE: `kubetee/z-ai/glm-5.3` (`--kubetee`) |
| `GLM-5.3-Flash` | Z.ai API: `zai/glm-5.3-flash` (`--zai`); Engy: `engy/glm-5.3-flash` (`--engy`); DeepInfra: `deepinfra/zai-org/GLM-5.3-Flash` (`--deepinfra`); KubeTEE (TEE sibling): `kubetee/z-ai/glm-5.3-flash` (`--kubetee`) |
| `GLM-5.3-Flash TEE` | KubeTEE: `kubetee/z-ai/glm-5.3-flash` (`--kubetee`); NEAR confidential inference: `near/z-ai/glm-5.3-flash` (`--near`) |
| `GPT-5.4` | OpenAI API: `openai/gpt-5.4` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.4 mini` | OpenAI API: `openai/gpt-5.4-mini` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.4 nano` | OpenAI API: `openai/gpt-5.4-nano` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.5` | OpenAI API: `openai/gpt-5.5` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.5 Pro` | OpenAI API: `openai/gpt-5.5-pro` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.6 Luna` | OpenAI API: `openai/gpt-5.6-luna` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.6 Sol` | OpenAI API: `openai/gpt-5.6-sol` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-5.6 Terra` | OpenAI API: `openai/gpt-5.6-terra` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-6 Astra` | OpenAI API: `openai/gpt-6-astra` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-6 Luna` | OpenAI API: `openai/gpt-6-luna` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-6 Sol` | OpenAI API: `openai/gpt-6-sol` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-6.1 Sol` | OpenAI API: `openai/gpt-6.1-sol` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `GPT-6.1 Terra` | OpenAI API: `openai/gpt-6.1-terra` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `gpt-oss-20b` | DeepInfra: `deepinfra/openai/gpt-oss-20b` (`--deepinfra`); chat completions only |
| `Kimi K2.6 TEE` | Chutes: `chutes/moonshotai/Kimi-K2.6-TEE` (`--chutes`) |
| `Kimi K3` | Moonshot API: `moonshot/kimi-k3` (`--moonshot`); DeepInfra: `deepinfra/moonshotai/Kimi-K3` (`--deepinfra`); Engy: `engy/kimi-k3` (`--engy`); Moonmath ZRO: `moonmath/kimi-k3` (`--moonmath`); Chutes (TEE sibling): `chutes/moonshotai/Kimi-K3-TEE` (`--chutes`) |
| `Kimi K3 TEE` | Chutes: `chutes/moonshotai/Kimi-K3-TEE` (`--chutes`) |
| `Kimi K3.1 Pro` | Moonshot API: `moonshot/kimi-k3.1-pro` (`--moonshot`) |
| `MiMo V2.6 Pro Ultraspeed` | KubeTEE (TEE sibling): `kubetee/xiaomi/mimo-v2.6-pro` (`--kubetee`) |
| `MiMo V2.6 Pro Ultraspeed TEE` | KubeTEE: `kubetee/xiaomi/mimo-v2.6-pro` (`--kubetee`) |
| `MiniMax H3` | Engy: `engy/MiniMax-H3` (`--engy`, native async video API); KubeTEE (**disabled in catalog**): `kubetee/minimax/h3` (`--kubetee`) |
| `Mistral Nemo Instruct 2407 TEE` | Chutes: `chutes/unsloth/Mistral-Nemo-Instruct-2407-TEE` (`--chutes`) |
| `Nano Banana 2.1` | Google native `generateContent`: `gemini/gemini-nano-banana-2.1` (`--google`) |
| `Nano Banana Pro` | Google native `generateContent`: `gemini/gemini-3-pro-image` (`--google`) |
| `Nemotron 3 Nano Omni 30B TEE` | Chutes: `chutes/Nemotron-3-Nano-Omni-30B-TEE` (`--chutes`) |
| `o3` | OpenAI API: `openai/o3` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `o4-mini` | OpenAI API: `openai/o4-mini` (`--openai`); Azure OpenAI: ARM-verified transport, feature-gated admission |
| `Ornith 1.5 397B` | KubeTEE (TEE sibling): `kubetee/ornith/ornith-1.5-397b` (`--kubetee`) |
| `Ornith 1.5 397B TEE` | KubeTEE: `kubetee/ornith/ornith-1.5-397b` (`--kubetee`) |
| `Qwen3 235B A22B Thinking 2507 TEE` | Chutes: `chutes/Qwen/Qwen3-235B-A22B-Thinking-2507-TEE` (`--chutes`) |
| `Qwen3 32B TEE` | Chutes: `chutes/Qwen/Qwen3-32B-TEE` (`--chutes`) |
| `Qwen3.5 397B A17B TEE` | Chutes: `chutes/Qwen/Qwen3.5-397B-A17B-TEE` (`--chutes`) |
| `Qwen3.6 27B TEE` | Chutes: `chutes/Qwen/Qwen3.6-27B-TEE` (`--chutes`) |
| `Qwen3.6 35B A3B` | Engy: `engy/qwen3.6-35b-a3b` (`--engy`); DeepInfra: `deepinfra/Qwen/Qwen3.6-35B-A3B` (`--deepinfra`) |
| `Qwen3.8 27B` | Engy: `engy/qwen3.8-27b` (`--engy`); DeepInfra: `deepinfra/Qwen/Qwen3.8-27B` (`--deepinfra`) |
| `Veo 3.1 Fast` | DeepInfra (**disabled in catalog**): `deepinfra/google/veo-3.1-fast` (`--deepinfra`) |
| `Wan 2.6 T2V` | DeepInfra (**disabled in catalog**): `deepinfra/Wan-AI/Wan2.6-T2V` (`--deepinfra`) |

Routes marked `TEE sibling` are shared through the catalog's explicit link from a TEE buyer product to its ordinary sibling.

The buyer API for `FLUX.2 klein 4B` uses the OpenAI images shape,
`POST /v1/images/generations` with `response_format: "b64_json"`. DeepInfra supply
uses the native `POST /v1/inference/black-forest-labs/FLUX-2-klein-4b` route after
gateway adaptation. It requires an approved image carrying
`deepinfra-native-images`; the miner forwards that native request unchanged
without retries. NEAR and KubeTEE image routes remain disabled in the catalog.

Gemini image-generation SKUs use the native
`POST /v1beta/models/{model}:generateContent` request shape. Envoy forwards
that path and body unchanged to Google's Gemini API; there is no Interactions
route in the MVP. Routine capability/health probes stay text-only and must not
request image output, so a probe does not create a paid image.

These definitions, publication, discovery, and declaration are supported on
both networks. Pass `--network` explicitly when changing an image offer so the
intended registry is unambiguous.

`gmcli check-streaming` skips every offered product whose registry catalog
entry publishes image generation because its streaming check targets the
OpenAI-compatible SSE surface; it never sends an image-generation probe.
