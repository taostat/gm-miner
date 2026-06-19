# gm miner terms (acceptable use)

`gmcli deploy` shows a summary of these terms and records your acceptance once,
before your provider keys are first baked into your TEE. Acceptance is recorded
locally in `~/.gmcli/config.json` and on the gm registry's miner record (keyed
to your hotkey). When this document's version changes, `gmcli` asks you to
accept again.

## 1. Provider-account compliance (your representation)

By proceeding you confirm that your provider accounts and API keys permit you
to supply capacity through gm, and that doing so does not breach the provider's
terms. You are solely responsible for your accounts' compliance; gm is not
liable for any action a provider takes against your account.

## 2. What "supplying capacity" means

As a gm miner you supply inference capacity from upstream model providers
(such as Anthropic, OpenAI, or Google) by running a gm miner image in a
confidential VM. Your provider API keys are encrypted to your TEE and are never
seen by gm operators, validators, or the gateway. You — not gm — hold the
commercial relationship with each provider.

## 3. Acceptable use

- Supply only capacity you are authorised to supply under your own provider
  agreements.
- Do not present capacity you do not control as your own.
- Keep your provider accounts in good standing for as long as you offer their
  models through gm.

## 4. No warranty from gm on your provider relationship

gm does not represent that supplying capacity through gm is permitted under any
particular provider's terms — that judgement is yours. gm is not a party to
your provider agreements and is not liable for a provider suspending, rate-
limiting, or closing your account.

## 5. Changes

These terms are versioned. A material change bumps the version; `gmcli`
re-prompts for acceptance at the next deploy. The accepted version is recorded
against your hotkey so the version in force at each acceptance is auditable.
