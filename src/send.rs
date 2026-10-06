use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, OutPoint, Txid};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::signer::SignersContainer;
use bdk_wallet::{KeychainKind, SignOptions};

use crate::backend::Backend;
use crate::seed::Seed;
use crate::walletdb::OpenWallet;

pub struct SendReport {
    pub txid: Txid,
    pub fee: Amount,
    pub fee_rate_sat_vb: f64,
}

/// Build (but do not sign or broadcast) a PSBT paying `amount` to `to`. This is the "watch-only
/// side" half of the air-gapped signing flow -- it only needs the wallet's public descriptors,
/// never the seed, so it works even on an instance of this wallet with no `seed.dat` at all.
///
/// If `selected_utxos` is empty, coin selection and change handling are delegated entirely to
/// bdk_wallet's default `TxBuilder` (branch-and-bound over the wallet's known UTXOs). If it's
/// non-empty, those are the *only* inputs used (coin control) -- the caller is responsible for
/// having picked enough value to cover `amount` plus fees.
pub fn build_unsigned(
    wallet: &mut OpenWallet,
    to: &Address,
    amount: Amount,
    fee_rate: FeeRate,
    selected_utxos: &[OutPoint],
) -> Result<Psbt> {
    let mut builder = wallet.build_tx();
    if !selected_utxos.is_empty() {
        builder.add_utxos(selected_utxos).context("selecting coins")?;
        builder.manually_selected_only();
    }
    builder.add_recipient(to.script_pubkey(), amount);
    builder.fee_rate(fee_rate);
    builder.finish().context("building transaction")
}

/// Build, sign, finalize and broadcast a transaction paying `amount` to `to`. See
/// [`build_unsigned`] for `selected_utxos`.
pub fn send(
    wallet: &mut OpenWallet,
    conn: &mut Connection,
    backend: &Backend,
    seed: &Seed,
    network: bitcoin::Network,
    to: &Address,
    amount: Amount,
    fee_rate: FeeRate,
    selected_utxos: &[OutPoint],
) -> Result<SendReport> {
    let psbt = build_unsigned(wallet, to, amount, fee_rate, selected_utxos)?;
    sign_and_broadcast(wallet, conn, backend, seed, network, psbt)
}

/// Replace an unconfirmed transaction with one paying `fee_rate`, keeping the same recipients
/// (RBF, BIP125). Fails if `txid` is already confirmed or didn't originally signal
/// replaceability -- both enforced by `bdk_wallet::Wallet::build_fee_bump` itself.
pub fn bump_fee(
    wallet: &mut OpenWallet,
    conn: &mut Connection,
    backend: &Backend,
    seed: &Seed,
    network: bitcoin::Network,
    txid: Txid,
    fee_rate: FeeRate,
) -> Result<SendReport> {
    let psbt = {
        let mut builder = wallet.build_fee_bump(txid).context("preparing fee bump")?;
        builder.fee_rate(fee_rate);
        builder.finish().context("building bumped transaction")?
    };
    sign_and_broadcast(wallet, conn, backend, seed, network, psbt)
}

/// Sign a PSBT with this wallet's seed, without broadcasting. This is the "air-gapped signer
/// side" half of the PSBT flow: it never touches the network, only `wallet`'s already-loaded
/// public descriptors (to know which keys apply) and `seed` (to actually derive them). Returns
/// the PSBT (signed in place where possible) and whether every input finalized -- for this
/// wallet's single-sig descriptors, a `false` here means `psbt` wasn't built against a UTXO set
/// this wallet actually owns, not that more signatures are needed from elsewhere.
///
/// Reconstructs the private keymap from `seed` on the fly -- see [`Seed::keymap_for`] for why
/// the loaded wallet alone cannot sign.
pub fn sign_psbt(
    wallet: &OpenWallet,
    seed: &Seed,
    network: bitcoin::Network,
    mut psbt: Psbt,
) -> Result<(Psbt, bool)> {
    let script_kind = crate::seed::script_kind_of(wallet);
    let external_keymap = seed.keymap_for(network, KeychainKind::External, script_kind)?;
    let internal_keymap = seed.keymap_for(network, KeychainKind::Internal, script_kind)?;

    let secp = wallet.secp_ctx();
    let external_signers = SignersContainer::build(
        external_keymap,
        wallet.public_descriptor(KeychainKind::External),
        secp,
    );
    let internal_signers = SignersContainer::build(
        internal_keymap,
        wallet.public_descriptor(KeychainKind::Internal),
        secp,
    );

    let finalized = wallet
        .sign_with_signers(
            &mut psbt,
            &[&external_signers, &internal_signers],
            SignOptions::default(),
        )
        .context("signing transaction")?;
    Ok((psbt, finalized))
}

/// Extract and broadcast an already-fully-signed PSBT, then record it in the wallet's own view
/// the same way a normal [`send`] would. This is the step that needs network access -- kept
/// separate from [`sign_psbt`] so signing itself never requires it.
pub fn broadcast_psbt(
    wallet: &mut OpenWallet,
    conn: &mut Connection,
    backend: &Backend,
    psbt: Psbt,
) -> Result<SendReport> {
    let tx = psbt.extract_tx().context("extracting finalized transaction")?;
    let fee = wallet.calculate_fee(&tx).context("calculating fee")?;
    let actual_fee_rate = wallet
        .calculate_fee_rate(&tx)
        .map(|fr| bdk_wallet::floating_rate!(fr))
        .unwrap_or(0.0);

    let txid = backend.broadcast(&tx)?;

    // Record the just-broadcast transaction as unconfirmed in the wallet's own view so
    // `balance`/`history` reflect it immediately, without waiting for the next `sync`.
    wallet.apply_unconfirmed_txs([(tx, unix_now())]);
    wallet.persist(conn).context("persisting wallet state")?;

    Ok(SendReport {
        txid,
        fee,
        fee_rate_sat_vb: actual_fee_rate,
    })
}

/// Shared by [`send`] and [`bump_fee`], which only differ in how the unsigned PSBT gets built.
fn sign_and_broadcast(
    wallet: &mut OpenWallet,
    conn: &mut Connection,
    backend: &Backend,
    seed: &Seed,
    network: bitcoin::Network,
    psbt: Psbt,
) -> Result<SendReport> {
    let (psbt, finalized) = sign_psbt(wallet, seed, network, psbt)?;
    if !finalized {
        bail!("could not finalize the transaction -- not all inputs could be signed");
    }
    broadcast_psbt(wallet, conn, backend, psbt)
}

fn unix_now() -> u64 {
    std::time::UNIX_EPOCH.elapsed().expect("system clock").as_secs()
}
