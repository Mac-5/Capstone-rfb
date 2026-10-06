# rfb_wallet

A non-custodial Bitcoin wallet with a terminal UI (TUI), built on [`bdk_wallet`](https://docs.rs/bdk_wallet).
Supports single-sig (SegWit/Taproot) and configurable N-of-M multisig wallets, syncing via either
your own `bitcoind` node or a remote Esplora server (e.g. `mempool.space`, `blockstream.info`).

For the full architecture writeup, every `bdk_wallet`/`bitcoin` API this project uses and why, and
a complete feature-by-feature demo script, see [`PRESENTATION_GUIDE.md`](./PRESENTATION_GUIDE.md).
This file is just "clone it and get it running."

## Prerequisites

- **Rust** 1.98+ (edition 2024). Install via [rustup](https://rustup.rs) if you don't have it.
- **`bitcoind`** (Bitcoin Core) on your `PATH` — needed both to run the app against a local node
  and to run the test suite (each integration test spins up its own ephemeral regtest node).
  `brew install bitcoin` on macOS, or download from [bitcoincore.org](https://bitcoincore.org).
- No Esplora/remote server setup needed to get started — regtest + your own local `bitcoind` is
  the easiest path and needs no internet access at all.

## Quickstart (regtest — no external dependencies)

```sh
git clone <this repo>
cd rfb-capstone

# Start a local regtest node (separate terminal, leave it running):
mkdir -p ~/bitcoin-regtest
bitcoind -regtest -datadir=$HOME/bitcoin-regtest -daemon -server -fallbackfee=0.0001

# Run the wallet:
cargo run -- --network regtest --rpc-cookie $HOME/bitcoin-regtest/regtest/.cookie
```

First run drops you into a wallet picker (`[n]` to create a new one, walks you through script
type, password, and shows your mnemonic once). Once a wallet exists, press `m` on the Dashboard
to mine yourself some regtest coins to play with — on regtest, unlike mainnet/testnet/signet, you
can do this yourself, no faucet needed.

## Other networks

```sh
# Signet or mainnet against your own bitcoind (uses Bitcoin Core's standard cookie path
# automatically if you don't pass --rpc-cookie):
cargo run -- --network signet

# Any network against a remote Esplora server instead of running your own node:
cargo run -- --network signet --esplora-url https://blockstream.info/signet/api
```

Full flag reference: `cargo run -- --help`.

## Running the tests

```sh
cargo test
```

16 tests: fast unit tests (pure logic, no network) plus integration tests that each spin up a
real, ephemeral `bitcoind` regtest node and exercise the same library functions the TUI calls —
no manual setup beyond having `bitcoind` on `PATH`.

## Project layout

```
src/
  lib.rs        -- library crate root (everything below is unit/integration-testable)
  seed.rs       -- mnemonic, encrypted seed storage, key derivation (BIP32/84/86/48)
  walletdb.rs   -- wallet creation/loading via bdk_wallet + SQLite
  sync.rs       -- chain sync, dispatching to either backend
  send.rs       -- transaction building, PSBT signing, broadcasting
  backend.rs    -- bitcoind-RPC vs. Esplora abstraction
  config.rs     -- on-disk wallet paths, RPC/Esplora connection config
  history.rs    -- transaction history view
  app.rs        -- TUI state machine (bin-only)
  ui.rs         -- TUI rendering (bin-only)
  main.rs       -- CLI entry point (bin-only)
tests/
  wallet_integration.rs  -- end-to-end tests against ephemeral regtest nodes
```

`app.rs`/`ui.rs`/`main.rs` are the binary; everything else is the `rfb_wallet` library, which is
what the integration tests exercise directly (no TUI/terminal involved).
