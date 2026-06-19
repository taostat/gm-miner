# Security Policy

## Reporting a vulnerability

Report security issues privately. **Do not open a public GitHub issue for
a vulnerability.**

Email **security@saygm.com** with:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected component(s) and version/commit, and
- any suggested remediation.

If you prefer, open a private advisory via GitHub's
[Security Advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/about-coordinated-disclosure-of-security-vulnerabilities)
feature on this repository.

We ask that you give us a reasonable window to investigate and ship a fix
before any public disclosure.

## Response expectations

| Stage | Target |
|---|---|
| Acknowledgement of report | within 3 business days |
| Initial assessment / severity triage | within 7 business days |
| Status updates during investigation | at least every 7 days |
| Fix or mitigation for confirmed high-severity issues | as soon as practical, coordinated with the reporter |

## Supported versions

gmcli ships from `main`; the CLI binary and miner container image both
track the latest release. Security fixes land on `main` and are rolled out
from there. Older commits are not separately patched.

| Version | Supported |
|---|---|
| `main` (latest) | Yes |
| older commits | No |

## Trust model

The miner container (`image/`) runs inside an Intel TDX Trusted Execution
Environment (TEE) on Phala Cloud. Provider API keys (Anthropic, OpenAI,
Google, Chutes) are baked into the container's encrypted environment at deploy time
via `gmcli set-api-keys` and are never transmitted to gm operators or the
registry. Reports that concern the confidentiality or integrity guarantees
of the TEE boundary — attestation verification, key handling, or enclave
isolation — are treated as high severity.

The node secret (`GM_NODE_SECRET`) is generated per-worker by the CLI and
embedded in the compose env; it is used by Envoy to authenticate inbound
requests from the gateway. Reports involving node secret exposure or
bypass of this check are likewise high severity.
