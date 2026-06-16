# Contributing to gm-miner

Thanks for your interest in contributing. gm-miner is the operator CLI
(`gmcli`) and miner container image for the gm Bittensor subnet. Read
`CLAUDE.md` before making changes — it documents the layout, key
conventions, and build commands.

By participating you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Install the Rust toolchain:

```bash
rustup update stable
```

Install the git hooks once after cloning:

```bash
prek install
```

Run the hooks before committing:

```bash
prek run
```

## Building, testing, and linting

```bash
# build
cargo build --all-targets

# lint
cargo clippy --all-targets --all-features -- -D warnings

# format check
cargo fmt --all --check

# tests (wiremock for registry HTTP; no real Phala Cloud / Docker required)
cargo test --all-features

# supply-chain
cargo deny check
```

## Commit and PR conventions

- Use **imperative mood** subject lines, ≤72 characters, one logical change
  per commit.
- Work on **feature branches**; never push directly to `main`. Open a pull
  request and let CI run.
- **Do not** add `Co-Authored-By` trailers or AI-attribution lines to
  commits or PR descriptions.
- Describe what the code does now — not discarded approaches or prior
  iterations. Use plain, factual language.
- Fix every warning from linters, type checkers, and compilers before
  committing. A clean output is the baseline.

## Comments

Default to no comment. Add one only when the *why* is non-obvious — a
hidden constraint, a subtle invariant, or a workaround. Never explain
*what* well-named code already says.
