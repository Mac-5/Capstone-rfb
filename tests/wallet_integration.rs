//! End-to-end integration tests against a real, ephemeral regtest `bitcoind` (one per test,
//! managed by the `bitcoind` crate -- no shared state, no manual node setup required beyond
//! having `bitcoind` on PATH). These exercise the exact same library functions the TUI calls,
//! just without a terminal in the loop.

use anyhow::Result;
use bdk_wallet::bitcoin::{Amount, FeeRate, Network};
use bdk_wallet::keys::bip39::WordCount;
use bdk_wallet::KeychainKind;
use bitcoincore_rpc::RpcApi;
use bitcoind::{BitcoinD, Conf};
use rfb_wallet::backend::Backend;
use rfb_wallet::config::{RpcConfig, WalletPaths};
use rfb_wallet::seed::{ScriptKind, Seed};
use rfb_wallet::{send, sync, walletdb};

fn start_node() -> BitcoinD {
    let exe = bitcoind::exe_path()
        .expect("bitcoind not found: install it (e.g. `brew install bitcoin`) or set BITCOIND_EXE");
    // We only ever use raw RPC calls (generatetoaddress, sendrawtransaction, estimatesmartfee) --
    // none of which need bitcoind's own wallet loaded, so skip it rather than fight whatever
    // wallet-creation default this bitcoind version wants.
    let mut conf = Conf::default();
    conf.wallet = None;
    BitcoinD::with_conf(exe, &conf).expect("failed to start bitcoind")
}

fn rpc_config(node: &BitcoinD) -> RpcConfig {
    RpcConfig {
        url: node.params.rpc_socket.to_string(),
        cookie: Some(node.params.cookie_file.clone()),
        user: None,
        pass: None,
    }
}

/// A second, independent RPC connection wrapped as the generic `Backend` the library actually
/// takes -- `generate_to_address` stays on the raw client since mining isn't part of `Backend`'s
/// API (it's a bitcoind/regtest-only concept, deliberately not something sync/send know about).
fn backend_for(node: &BitcoinD) -> Backend {
    Backend::BitcoindRpc(rpc_config(node).client().expect("rpc client for backend"))
}

fn wallet_paths(tmp: &tempfile::TempDir, name: &str) -> WalletPaths {
    WalletPaths::named(Some(tmp.path().to_path_buf()), Network::Regtest, name).unwrap()
}

#[test]
fn create_and_restore_derive_identical_addresses() -> Result<()> {
    let tmp = tempfile::tempdir()?;

    let paths_a = wallet_paths(&tmp, "original");
    let seed = Seed::generate(WordCount::Words12, None)?;
    let (mut wallet_a, mut conn_a) = walletdb::create(&paths_a, Network::Regtest, &seed, "pw-one", ScriptKind::Segwit)?;
    let addr_a = wallet_a.reveal_next_address(KeychainKind::External).address;
    wallet_a.persist(&mut conn_a)?;

    // Restore the same mnemonic into a completely separate wallet directory and password.
    let mnemonic_words = seed.mnemonic.to_string();
    let paths_b = wallet_paths(&tmp, "restored");
    let seed_restored = Seed::parse(&mnemonic_words, None)?;
    let (mut wallet_b, mut conn_b) = walletdb::create(&paths_b, Network::Regtest, &seed_restored, "pw-two", ScriptKind::Segwit)?;
    let addr_b = wallet_b.reveal_next_address(KeychainKind::External).address;
    wallet_b.persist(&mut conn_b)?;

    assert_eq!(addr_a, addr_b, "same mnemonic must derive the same BIP84 address");
    Ok(())
}

#[test]
fn sync_discovers_mined_funds_and_respects_coinbase_maturity() -> Result<()> {
    let node = start_node();
    let rpc = rpc_config(&node).client()?;
    let backend = backend_for(&node);

    let tmp = tempfile::tempdir()?;
    let paths = wallet_paths(&tmp, "miner");
    let seed = Seed::generate(WordCount::Words12, None)?;
    let (mut wallet, mut conn) = walletdb::create(&paths, Network::Regtest, &seed, "pw", ScriptKind::Segwit)?;
    let addr = wallet.reveal_next_address(KeychainKind::External).address;
    wallet.persist(&mut conn)?;

    // Coinbase matures once tip_height >= coinbase_height + 99 (bdk_chain: `age + 1 < 100` is
    // immature). Mining exactly 100 blocks matures only the height-1 coinbase (100 >= 1 + 99);
    // the height-2 coinbase needs tip >= 101, so it's the cleanest way to get exactly one match.
    rpc.generate_to_address(100, &addr)?;
    let report = sync::sync(&mut wallet, &mut conn, &backend, |_| {})?;
    assert_eq!(report.blocks_connected, 100);

    let balance = wallet.balance();
    assert_eq!(balance.confirmed, Amount::from_sat(50 * 100_000_000));
    assert!(balance.immature.to_sat() > 0, "the other 99 blocks should still be immature");
    Ok(())
}

#[test]
fn send_broadcasts_and_confirms_into_the_recipient_wallet() -> Result<()> {
    let node = start_node();
    let rpc = rpc_config(&node).client()?;
    let backend = backend_for(&node);
    let tmp = tempfile::tempdir()?;

    // Wallet A: fund it with 101 blocks so its first coinbase reward is spendable.
    let paths_a = wallet_paths(&tmp, "sender");
    let seed_a = Seed::generate(WordCount::Words12, None)?;
    let (mut wallet_a, mut conn_a) = walletdb::create(&paths_a, Network::Regtest, &seed_a, "pw", ScriptKind::Segwit)?;
    let addr_a = wallet_a.reveal_next_address(KeychainKind::External).address;
    wallet_a.persist(&mut conn_a)?;
    rpc.generate_to_address(101, &addr_a)?;
    sync::sync(&mut wallet_a, &mut conn_a, &backend, |_| {})?;
    assert!(wallet_a.balance().confirmed.to_sat() > 0);

    // Wallet B: empty, will receive the payment.
    let paths_b = wallet_paths(&tmp, "recipient");
    let seed_b = Seed::generate(WordCount::Words12, None)?;
    let (mut wallet_b, mut conn_b) = walletdb::create(&paths_b, Network::Regtest, &seed_b, "pw", ScriptKind::Segwit)?;
    let addr_b = wallet_b.reveal_next_address(KeychainKind::External).address;
    wallet_b.persist(&mut conn_b)?;

    let amount = Amount::from_sat(100_000);
    let fee_rate = FeeRate::from_sat_per_vb(5).expect("valid fee rate");
    let report = send::send(
        &mut wallet_a,
        &mut conn_a,
        &backend,
        &seed_a,
        Network::Regtest,
        &addr_b,
        amount,
        fee_rate,
        &[],
    )?;

    // Confirm it, then let both sides see the new tip.
    rpc.generate_to_address(1, &addr_a)?;
    sync::sync(&mut wallet_a, &mut conn_a, &backend, |_| {})?;
    sync::sync(&mut wallet_b, &mut conn_b, &backend, |_| {})?;

    assert_eq!(wallet_b.balance().confirmed, amount);
    let sent_tx = wallet_a.get_tx(report.txid).expect("sender should know about its own tx");
    assert!(sent_tx.chain_position.is_confirmed());
    Ok(())
}

#[test]
fn bump_fee_replaces_the_original_unconfirmed_transaction() -> Result<()> {
    let node = start_node();
    let rpc = rpc_config(&node).client()?;
    let backend = backend_for(&node);
    let tmp = tempfile::tempdir()?;

    let paths = wallet_paths(&tmp, "rbf");
    let seed = Seed::generate(WordCount::Words12, None)?;
    let (mut wallet, mut conn) = walletdb::create(&paths, Network::Regtest, &seed, "pw", ScriptKind::Segwit)?;
    let addr = wallet.reveal_next_address(KeychainKind::External).address;
    wallet.persist(&mut conn)?;
    rpc.generate_to_address(100, &addr)?;
    sync::sync(&mut wallet, &mut conn, &backend, |_| {})?;

    let low_fee_rate = FeeRate::from_sat_per_vb(2).expect("valid fee rate");
    let original = send::send(
        &mut wallet,
        &mut conn,
        &backend,
        &seed,
        Network::Regtest,
        &addr,
        Amount::from_sat(50_000),
        low_fee_rate,
        &[],
    )?;

    let high_fee_rate = FeeRate::from_sat_per_vb(20).expect("valid fee rate");
    let replacement = send::bump_fee(&mut wallet, &mut conn, &backend, &seed, Network::Regtest, original.txid, high_fee_rate)?;

    assert_ne!(
        original.txid, replacement.txid,
        "bumping fee must produce a different transaction"
    );
    assert!(
        replacement.fee > original.fee,
        "replacement must pay a higher absolute fee (BIP125 rule 3/4)"
    );

    // Mine: only the replacement should confirm, and sync must notice the original was evicted.
    rpc.generate_to_address(1, &addr)?;
    sync::sync(&mut wallet, &mut conn, &backend, |_| {})?;

    let replacement_tx = wallet.get_tx(replacement.txid).expect("replacement should be known");
    assert!(replacement_tx.chain_position.is_confirmed());

    match wallet.get_tx(original.txid) {
        None => {} // fully forgotten -- also an acceptable outcome of eviction
        Some(original_tx) => assert!(
            !original_tx.chain_position.is_confirmed(),
            "the original, replaced transaction must not have confirmed"
        ),
    }
    Ok(())
}

#[test]
fn taproot_wallet_derives_bech32m_addresses_and_can_send() -> Result<()> {
    let node = start_node();
    let rpc = rpc_config(&node).client()?;
    let backend = backend_for(&node);
    let tmp = tempfile::tempdir()?;

    let paths = wallet_paths(&tmp, "taproot");
    let seed = Seed::generate(WordCount::Words12, None)?;
    let (mut wallet, mut conn) = walletdb::create(&paths, Network::Regtest, &seed, "pw", ScriptKind::Taproot)?;
    let addr = wallet.reveal_next_address(KeychainKind::External).address;
    wallet.persist(&mut conn)?;

    // Taproot (BIP86) addresses are bech32m, witness version 1 -- "bcrt1p..." on regtest, as
    // opposed to BIP84's witness version 0 "bcrt1q...".
    assert!(
        addr.to_string().starts_with("bcrt1p"),
        "expected a Taproot address, got {addr}"
    );
    assert_eq!(rfb_wallet::seed::script_kind_of(&wallet), ScriptKind::Taproot);

    rpc.generate_to_address(100, &addr)?;
    sync::sync(&mut wallet, &mut conn, &backend, |_| {})?;
    assert!(wallet.balance().confirmed.to_sat() > 0);

    // A full send exercises Taproot key-path signing, not just address derivation.
    let fee_rate = FeeRate::from_sat_per_vb(5).expect("valid fee rate");
    let report = send::send(
        &mut wallet,
        &mut conn,
        &backend,
        &seed,
        Network::Regtest,
        &addr,
        Amount::from_sat(50_000),
        fee_rate,
        &[],
    )?;

    rpc.generate_to_address(1, &addr)?;
    sync::sync(&mut wallet, &mut conn, &backend, |_| {})?;
    let sent_tx = wallet.get_tx(report.txid).expect("sender should know about its own tx");
    assert!(sent_tx.chain_position.is_confirmed());
    Ok(())
}

#[test]
fn psbt_export_sign_broadcast_round_trip_works_like_a_direct_send() -> Result<()> {
    use bdk_wallet::bitcoin::psbt::Psbt;

    let node = start_node();
    let rpc = rpc_config(&node).client()?;
    let backend = backend_for(&node);
    let tmp = tempfile::tempdir()?;

    let paths = wallet_paths(&tmp, "airgap");
    let seed = Seed::generate(WordCount::Words12, None)?;
    let (mut wallet, mut conn) = walletdb::create(&paths, Network::Regtest, &seed, "pw", ScriptKind::Segwit)?;
    let addr = wallet.reveal_next_address(KeychainKind::External).address;
    wallet.persist(&mut conn)?;
    rpc.generate_to_address(100, &addr)?;
    sync::sync(&mut wallet, &mut conn, &backend, |_| {})?;

    // "Watch-only side": build an unsigned PSBT and serialize it the way it'd be written to a
    // file for transfer. `build_unsigned` never takes a `Seed` -- it can't touch private keys.
    let fee_rate = FeeRate::from_sat_per_vb(5).expect("valid fee rate");
    let unsigned = send::build_unsigned(&mut wallet, &addr, Amount::from_sat(75_000), fee_rate, &[])?;
    let psbt_text = unsigned.to_string();
    assert!(
        psbt_text.starts_with("cHNi"),
        "a BIP174 PSBT's base64 text always starts with 'cHNi' (the magic bytes); got: {psbt_text}"
    );

    // "Air-gapped signer side": parse the transferred text and sign it. `sign_psbt` takes no
    // RPC client at all -- there is no way for this step to touch the network even by accident.
    let reparsed: Psbt = psbt_text.parse().expect("psbt should round-trip through its text form");
    let (signed, finalized) = send::sign_psbt(&wallet, &seed, Network::Regtest, reparsed)?;
    assert!(finalized, "a single-sig wallet should always fully finalize its own PSBT");
    let signed_text = signed.to_string();

    // Back on the watch-only side: parse the now-signed text and broadcast it.
    let to_broadcast: Psbt = signed_text.parse().expect("signed psbt should round-trip through text too");
    let report = send::broadcast_psbt(&mut wallet, &mut conn, &backend, to_broadcast)?;

    rpc.generate_to_address(1, &addr)?;
    sync::sync(&mut wallet, &mut conn, &backend, |_| {})?;
    let tx = wallet.get_tx(report.txid).expect("broadcast tx should be known to the wallet");
    assert!(tx.chain_position.is_confirmed());
    Ok(())
}

#[test]
fn multisig_2_of_3_requires_two_signatures_before_it_finalizes() -> Result<()> {
    use bdk_wallet::bitcoin::psbt::Psbt;

    let node = start_node();
    let rpc = rpc_config(&node).client()?;
    let backend = backend_for(&node);
    let tmp = tempfile::tempdir()?;

    // Seed A gets the real watch-only wallet (its own sqlite); B and C are bare seeds, exactly
    // like real cosigners who never need the watch-only wallet file -- only their exported
    // public key fragment, and later their own seed to sign with.
    let seed_a = Seed::generate(WordCount::Words12, None)?;
    let seed_b = Seed::generate(WordCount::Words12, None)?;
    let seed_c = Seed::generate(WordCount::Words12, None)?;
    let fragment_b = seed_b.multisig_xpub_fragment(Network::Regtest)?;
    let fragment_c = seed_c.multisig_xpub_fragment(Network::Regtest)?;

    let paths = wallet_paths(&tmp, "multisig");
    let (mut wallet, mut conn) = walletdb::create_multisig(
        &paths,
        Network::Regtest,
        &seed_a,
        "pw",
        2,
        &[fragment_b, fragment_c],
    )?;
    assert_eq!(rfb_wallet::seed::multisig_threshold(&wallet), Some((2, 3)));

    let addr = wallet.reveal_next_address(KeychainKind::External).address;
    wallet.persist(&mut conn)?;
    rpc.generate_to_address(100, &addr)?;
    sync::sync(&mut wallet, &mut conn, &backend, |_| {})?;
    assert!(wallet.balance().confirmed.to_sat() > 0);

    let fee_rate = FeeRate::from_sat_per_vb(5).expect("valid fee rate");
    let unsigned = send::build_unsigned(&mut wallet, &addr, Amount::from_sat(75_000), fee_rate, &[])?;

    // One signature (of the 2 required) should sign what it can without erroring, but not
    // finalize -- the core behavior that makes sequential round-robin co-signing possible.
    let (once_signed, finalized_after_one) = send::sign_psbt(&wallet, &seed_a, Network::Regtest, unsigned)?;
    assert!(!finalized_after_one, "2-of-3 must not finalize after only one signature");

    // Round-trip through text, as it would be when handed to the next cosigner as a file.
    let reparsed: Psbt = once_signed.to_string().parse().expect("psbt should round-trip through its text form");
    let (twice_signed, finalized_after_two) = send::sign_psbt(&wallet, &seed_b, Network::Regtest, reparsed)?;
    assert!(finalized_after_two, "2-of-3 should finalize once a second signer has signed");

    let report = send::broadcast_psbt(&mut wallet, &mut conn, &backend, twice_signed)?;
    rpc.generate_to_address(1, &addr)?;
    sync::sync(&mut wallet, &mut conn, &backend, |_| {})?;
    let tx = wallet.get_tx(report.txid).expect("broadcast tx should be known to the wallet");
    assert!(tx.chain_position.is_confirmed());
    Ok(())
}

#[test]
fn seed_file_rejects_the_wrong_password() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let paths = wallet_paths(&tmp, "locked");
    let seed = Seed::generate(WordCount::Words12, None)?;
    walletdb::create(&paths, Network::Regtest, &seed, "correct horse battery staple", ScriptKind::Segwit)?;

    assert!(Seed::load(&paths.seed_path, "wrong password").is_err());

    let loaded = Seed::load(&paths.seed_path, "correct horse battery staple")?;
    assert_eq!(loaded.mnemonic.to_string(), seed.mnemonic.to_string());
    Ok(())
}
