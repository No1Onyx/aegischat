# Fuzzing the crypto core

libFuzzer targets for the attacker-controlled parsing / decrypt paths.
The quick, always-on version of these checks lives in
`core-crypto/tests/adversarial.rs` and runs on stable in CI; this directory is
for continuous / deep campaigns (best on Linux).

## Setup

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Run

```bash
cd core-crypto
cargo +nightly fuzz run ratchet_decrypt          # wire-message decode + Double Ratchet
cargo +nightly fuzz run wire_message_parse       # structure-aware: raw key/nonce/ct bytes
cargo +nightly fuzz run db_open                  # corrupt encrypted-database file parsing
cargo +nightly fuzz run mnemonic_parse           # BIP-39 identity restore
cargo +nightly fuzz run sealed_envelope_parse    # sealed-sender envelope decode + unseal
```

Add `-- -max_total_time=300` for a timed run, `-jobs=$(nproc)` to parallelise.

## Contract

Every target must run indefinitely without a crash, panic, OOM, or timeout.
A finding = a reproducible input under `fuzz/artifacts/<target>/`; minimise it
with `cargo +nightly fuzz tmin <target> <artifact>` and add it to
`tests/adversarial.rs` as a permanent regression case.
