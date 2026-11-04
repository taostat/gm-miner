# KubeTEE attestation fixtures

- `attestation.json`: one `GET https://llm.kubetee.ai/v1/attestation?nonce=<nonce>`
  response, captured verbatim 2026-11-04 (pod `litellm-5dcbc54579-7rm6g`). It
  is `kubetee.attestation.v1` evidence: the TDX quote, the CC event log, the
  echoed nonce, the TLS-possession proof, and the `keyset` and `bindings` whose
  statement the quote's `report_data` binds.
- `session_leaf.der`: the leaf certificate `llm.kubetee.ai` serves. The
  response's `tls_cert_sha256` and its keyset's `spki_sha256` both name it.
- `collateral.json`: the Intel `QuoteCollateralV3` for that quote, fetched the
  same day from Phala's PCCS. Tests verify the quote offline at a fixed time
  inside its validity window.

`ec_session_leaf.der` and `ec_session_leaf_key.pk8` are a throwaway P-256
certificate/key pair (self-signed; the key protects nothing) for the
`ES256` TLS-possession proof tests: a per-boot serving key is EC P-256, so
the proof carries ECDSA over SHA-256 rather than RS256.

`test_ca.der`, `test_leaf.der` and `test_leaf_key.pk8` are a throwaway PKI for
the tests' local TLS upstream: a root trusted only by those tests and an RSA
leaf for `llm.kubetee.ai` it signed. The key protects nothing.

`ec_short_der_leaf.der` and `ec_short_der_signature.der` are a deterministic,
valid P-256/SHA-256 possession proof whose DER encoding is exactly 64 bytes.
This catches dispatch that mistakes every 64-byte signature for raw `r||s`.
`generate_short_der_fixture.py` reproduces them with Python `cryptography`:
it chooses an on-curve point R with a 29-byte x-coordinate r and a 29-byte s,
then derives Q = r^-1(sR - SHA256(nonce)G). No random signing or search for
short signature integers is involved. The nonce is the recorded fixture nonce.
A fixed throwaway Ed25519 issuer signs a certificate containing Q; its chain
is not trusted or used by this possession-proof unit test. The private key
for Q is not known. This fixture proves signature encoding handling only,
not a supplier attestation or TLS handshake.
