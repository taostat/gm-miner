# KubeTEE attestation fixtures

- `attestation.json`: one `GET https://llm.kubetee.ai/v1/attestation?nonce=<nonce>`
  response, captured 2026-09-27 (pod `litellm-5959f596d-l4qkl`). It carries the
  TDX quote, the CC event log, the echoed nonce and the TLS-possession proof.
- `session_leaf.der`: the leaf certificate `llm.kubetee.ai` presented on the TLS
  session that response arrived on.
- `collateral.json`: the Intel `QuoteCollateralV3` for that quote, fetched the
  same day from Phala's PCCS. Tests verify the quote offline at a fixed time
  inside its validity window.

`test_ca.der`, `test_leaf.der` and `test_leaf_key.pk8` are a throwaway PKI for
the tests' local TLS upstream: a root trusted only by those tests and an RSA
leaf for `llm.kubetee.ai` it signed. The key protects nothing.
