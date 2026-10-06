use anyhow::{Context, Result};
use bdk_bitcoind_rpc::Emitter;
use bdk_esplora::EsploraExt;
use bdk_wallet::rusqlite::Connection;

use crate::backend::Backend;
use crate::walletdb::OpenWallet;

/// Stop gap for Esplora's keychain scan: how many consecutive unused script pubkeys to check
/// past the last used one before giving up on finding more activity. `bdk_wallet`'s own default
/// address-index lookahead is 25, but that means up to 50 HTTP requests (both keychains) just to
/// create one empty wallet -- enough to trip rate limits on public Esplora servers (e.g.
/// Blockstream's unauthenticated-usage cap). 5 is still a generous gap for a wallet that hasn't
/// had many addresses used out of order, while being far gentler on public servers.
const ESPLORA_STOP_GAP: usize = 5;
/// How many HTTP requests `bdk_esplora` is allowed to have in flight at once during a scan.
const ESPLORA_PARALLEL_REQUESTS: usize = 5;

pub struct SyncReport {
    pub blocks_connected: u32,
    pub tip_height: u32,
}

/// Bring the wallet's view of the chain up to date, dispatching to whichever backend is
/// configured. The two backends work completely differently under the hood (bitcoind replays
/// raw blocks; Esplora answers script-pubkey queries over HTTP) but converge on the same
/// `bdk_wallet::Update` being applied, so callers never need to care which one is active.
///
/// `progress` fires on the calling thread, at every meaningful step (one call per connected
/// block for bitcoind; one call per scanned script pubkey for Esplora), so the caller can redraw
/// between calls. Without this a multi-minute Esplora gap scan would otherwise leave the caller
/// with nothing to show but one static "working" message the entire time -- indistinguishable
/// from a genuine hang. (The Esplora path uses a worker thread internally to satisfy its API's
/// `'static` closure requirement, but `progress` itself is only ever invoked here, synchronously.)
pub fn sync<F: FnMut(&str) + Send>(
    wallet: &mut OpenWallet,
    conn: &mut Connection,
    backend: &Backend,
    mut progress: F,
) -> Result<SyncReport> {
    match backend {
        Backend::BitcoindRpc(rpc) => sync_bitcoind(wallet, conn, rpc, &mut progress),
        Backend::Esplora(client) => sync_esplora(wallet, conn, client, &mut progress),
    }
}

/// Walk the chain from the wallet's last-known tip up to `bitcoind`'s current tip, applying
/// each connected block to the wallet, then pull in the current mempool. Persists after every
/// block and once more after the mempool pass so an interrupted sync can resume.
fn sync_bitcoind<F: FnMut(&str) + Send>(
    wallet: &mut OpenWallet,
    conn: &mut Connection,
    rpc: &bitcoincore_rpc::Client,
    progress: &mut F,
) -> Result<SyncReport> {
    let wallet_tip = wallet.latest_checkpoint();
    let start_height = wallet_tip.height();

    let mut emitter = Emitter::new(
        rpc,
        wallet_tip,
        start_height,
        wallet
            .transactions()
            .filter(|tx| tx.chain_position.is_unconfirmed()),
    );

    let mut blocks_connected = 0u32;
    while let Some(event) = emitter.next_block().context("fetching next block from bitcoind")? {
        let height = event.block_height();
        let connected_to = event.connected_to();
        progress(&format!("Connected block {height}"));
        wallet
            .apply_block_connected_to(&event.block, height, connected_to)
            .context("applying block to wallet")?;
        wallet.persist(conn).context("persisting wallet state")?;
        blocks_connected += 1;
    }

    progress("Checking mempool");
    let mempool = emitter.mempool().context("fetching mempool from bitcoind")?;
    wallet.apply_evicted_txs(mempool.evicted);
    wallet.apply_unconfirmed_txs(mempool.update);
    wallet.persist(conn).context("persisting wallet state")?;

    Ok(SyncReport {
        blocks_connected,
        tip_height: wallet.latest_checkpoint().height(),
    })
}

/// Query Esplora for this wallet's keychains. Always a full scan (rather than switching to a
/// cheaper revealed-spks-only sync once some addresses are known) -- simpler, and safe to repeat
/// since Esplora just confirms "nothing new past the stop gap" on an already-synced wallet.
fn sync_esplora<F: FnMut(&str) + Send>(
    wallet: &mut OpenWallet,
    conn: &mut Connection,
    client: &bdk_esplora::esplora_client::BlockingClient,
    progress: &mut F,
) -> Result<SyncReport> {
    let start_height = wallet.latest_checkpoint().height();

    // `inspect`'s closure must be `'static` (bdk_core boxes it up for later use inside the
    // scan), which rules out directly capturing `progress` -- it only borrows for this call.
    // Instead the closure (running on a worker thread, since `full_scan` blocks) reports each
    // scanned spk over a channel, and this thread drains it into `progress` as messages arrive,
    // giving live updates without making the rest of the app concurrent.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let request = wallet
        .start_full_scan()
        .inspect(move |keychain, spk_index, _script| {
            let _ = tx.send(format!("Scanning {keychain:?} index {spk_index}"));
        });

    let client = client.clone();
    let handle = std::thread::spawn(move || {
        client
            .full_scan(request, ESPLORA_STOP_GAP, ESPLORA_PARALLEL_REQUESTS)
            .map_err(|e| anyhow::anyhow!("scanning esplora: {e}"))
    });

    for message in rx {
        progress(&message);
    }
    let update = handle
        .join()
        .map_err(|_| anyhow::anyhow!("esplora scan thread panicked"))??;

    progress("Applying update");
    wallet.apply_update(update).context("applying esplora update to wallet")?;
    wallet.persist(conn).context("persisting wallet state")?;

    let tip_height = wallet.latest_checkpoint().height();
    Ok(SyncReport {
        blocks_connected: tip_height.saturating_sub(start_height),
        tip_height,
    })
}
