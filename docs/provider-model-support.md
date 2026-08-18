# Miner model sourcing matrix

Use this table to answer one question: **I want to provide a model — where can
I source it from?**

Snapshot date: **2026-08-12**. This is a miner setup matrix, not a buyer product
catalog. A direct or named source route is listed only when the GM miner image
supports its API and GM has reviewed the exact upstream model id. Its
backticked `provider/model` is the exact pair to pass to
`gmcli declare-product`; configure its key, redeploy the worker, then declare
that pair. Bedrock, Foundry and Azure entries mean the miner supports that
cloud transport; you must also make the model available in your own cloud
account. See [sourcing.md](sourcing.md) for complete commands and route
selection rules. Run `gmcli sources` against your chosen network before
deploying: it is the live authority for which source routes that registry has
published.

| Model you want to provide | Supported sources |
|---|---|
| `claude-fable-5` | Anthropic direct: `anthropic/claude-fable-5` (`--anthropic`); AWS Bedrock (`--anthropic-upstream bedrock`); Microsoft Foundry (`--anthropic-upstream foundry`, with `--upstream-model`) |
| `claude-haiku-4-5` | Anthropic direct: `anthropic/claude-haiku-4-5` (`--anthropic`); AWS Bedrock; Microsoft Foundry |
| `claude-opus-4-7` | Anthropic direct: `anthropic/claude-opus-4-7` (`--anthropic`); AWS Bedrock; Microsoft Foundry |
| `claude-opus-4-8` | Anthropic direct: `anthropic/claude-opus-4-8` (`--anthropic`); AWS Bedrock; Microsoft Foundry |
| `claude-opus-5` | Anthropic direct: `anthropic/claude-opus-5` (`--anthropic`); AWS Bedrock; Microsoft Foundry |
| `claude-sonnet-4-6` | Anthropic direct: `anthropic/claude-sonnet-4-6` (`--anthropic`); AWS Bedrock; Microsoft Foundry |
| `claude-sonnet-5` | Anthropic direct: `anthropic/claude-sonnet-5` (`--anthropic`); AWS Bedrock; Microsoft Foundry |
| `DeepSeek V3.2 TEE` | Chutes: `chutes/deepseek-ai/DeepSeek-V3.2-TEE` (`--chutes`) |
| `DeepSeek V4 Flash 0731 TEE` | Chutes: `chutes/deepseek-ai/DeepSeek-V4-Flash-0731-TEE` (`--chutes`) |
| `Gemma 4 31B Turbo TEE` | Chutes: `chutes/google/gemma-4-31B-turbo-TEE` (`--chutes`) |
| `Gemini 3.1 Pro Preview` | Google: `gemini/gemini-3.1-pro-preview` (`--google`) |
| `Gemini 3.5 Flash` | Google: `gemini/gemini-3.5-flash` (`--google`) |
| `GLM-5.1 TEE` | Chutes: `chutes/zai-org/GLM-5.1-TEE` (`--chutes`); NEAR confidential inference: `near/zai-org/GLM-5.1-FP8` (`--near`) |
| `GLM-5.2` | Z.ai direct: `zai/glm-5.2` (`--zai`); DeepInfra: `deepinfra/zai-org/GLM-5.2` (`--deepinfra`); Engy: `engy/glm-5.2` (`--engy`); KubeTEE: `kubetee/z-ai/glm-5.2` (`--kubetee`); Moonmath ZRO: `moonmath/glm-5.2` (`--moonmath`) |
| `GLM-5.2 TEE` | Chutes: `chutes/zai-org/GLM-5.2-TEE` (`--chutes`) |
| `GPT-5.4` | OpenAI direct: `openai/gpt-5.4` (`--openai`); Azure OpenAI (`--openai-upstream azure`) |
| `GPT-5.4 mini` | OpenAI direct: `openai/gpt-5.4-mini` (`--openai`); Azure OpenAI |
| `GPT-5.4 nano` | OpenAI direct: `openai/gpt-5.4-nano` (`--openai`); Azure OpenAI |
| `GPT-5.5` | OpenAI direct: `openai/gpt-5.5` (`--openai`); Azure OpenAI |
| `GPT-5.5 Pro` | OpenAI direct: `openai/gpt-5.5-pro` (`--openai`); Azure OpenAI |
| `GPT-5.6` | OpenAI direct: `openai/gpt-5.6` (`--openai`); Azure OpenAI |
| `GPT-5.6 Luna` | OpenAI direct: `openai/gpt-5.6-luna` (`--openai`); Azure OpenAI |
| `GPT-5.6 Sol` | OpenAI direct: `openai/gpt-5.6-sol` (`--openai`); Azure OpenAI |
| `GPT-5.6 Terra` | OpenAI direct: `openai/gpt-5.6-terra` (`--openai`); Azure OpenAI |
| `Kimi K2.6 TEE` | Chutes: `chutes/moonshotai/Kimi-K2.6-TEE` (`--chutes`) |
| `Kimi K3` | Moonshot direct: `moonshot/kimi-k3` (`--moonshot`); DeepInfra: `deepinfra/moonshotai/Kimi-K3` (`--deepinfra`); KubeTEE: `kubetee/moonshotai/kimi-k3` (`--kubetee`); Engy: `engy/kimi-k3` (`--engy`); Moonmath ZRO: `moonmath/kimi-k3` (`--moonmath`) |
| `Kimi K3 TEE` | Chutes: `chutes/moonshotai/Kimi-K3-TEE` (`--chutes`) |
| `Mistral Nemo Instruct 2407 TEE` | Chutes: `chutes/unsloth/Mistral-Nemo-Instruct-2407-TEE` (`--chutes`) |
| `Nemotron 3 Nano Omni 30B TEE` | Chutes: `chutes/Nemotron-3-Nano-Omni-30B-TEE` (`--chutes`) |
| `o3` | OpenAI direct: `openai/o3` (`--openai`); Azure OpenAI |
| `o4-mini` | OpenAI direct: `openai/o4-mini` (`--openai`); Azure OpenAI |
| `Qwen3 235B A22B Thinking 2507 TEE` | Chutes: `chutes/Qwen/Qwen3-235B-A22B-Thinking-2507-TEE` (`--chutes`) |
| `Qwen3 32B TEE` | Chutes: `chutes/Qwen/Qwen3-32B-TEE` (`--chutes`) |
| `Qwen3.5 397B A17B TEE` | Chutes: `chutes/Qwen/Qwen3.5-397B-A17B-TEE` (`--chutes`) |
| `Qwen3.6 27B TEE` | Chutes: `chutes/Qwen/Qwen3.6-27B-TEE` (`--chutes`); NEAR confidential inference: `near/Qwen/Qwen3.6-27B-FP8` (`--near`) |

KubeTEE also advertises `deepseek/deepseek-v4-flash-0731`,
`qwen/qwen3.5-397b-a17b`, and `xiaomi/mimo-v2.5`. They are not listed as
sources because GM has not reviewed exact model equivalence, pricing, and
capability limits for those KubeTEE variants. An upstream catalog entry alone
is not a safe mining route.
