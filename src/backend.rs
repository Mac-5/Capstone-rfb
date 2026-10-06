//! Abstracts "where chain data comes from and transactions go to" so the rest of the wallet
//! (sync, send, fee estimation) doesn't need to know whether it's talking to a local `bitcoind`
//! or a remote Esplora server. Mining is the one operation that's inherently bitcoind/regtest-
//! only; everything else is covered uniformly.

use anyhow::{Context, Result};
use bdk_esplora::esplora_client;
use bdk_wallet::bitcoin::{FeeRate, Transaction, Txid};
use bitcoincore_rpc::RpcApi;

use crate::config::{EsploraConfig, RpcConfig};

pub enum Backend {
    BitcoindRpc(bitcoincore_rpc::Client),
    Esplora(esplora_client::BlockingClient),
}

pub enum BackendConfig {
    BitcoindRpc(RpcConfig),
    Esplora(EsploraConfig),
}

impl BackendConfig {
    pub fn client(&self) -> Result<Backend> {
        match self {
            BackendConfig::BitcoindRpc(cfg) => Ok(Backend::BitcoindRpc(cfg.client()?)),
            BackendConfig::Esplora(cfg) => Ok(Backend::Esplora(cfg.client())),
        }
    }
}

impl Backend {
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        match self {
            Backend::BitcoindRpc(rpc) => {
                rpc.send_raw_transaction(tx).context("broadcasting transaction to bitcoind")
            }
            Backend::Esplora(client) => {
                client
                    .broadcast(tx)
                    .map_err(|e| anyhow::anyhow!("broadcasting transaction to esplora: {e}"))?;
                Ok(tx.compute_txid())
            }
        }
    }

    /// Best-effort fee rate for confirmation within `target_blocks`. `None` means the backend
    /// has no opinion yet (e.g. an empty regtest mempool) -- callers should fall back to a
    /// floor rate rather than treating this as an error.
    pub fn estimate_fee_rate(&self, target_blocks: u16) -> Result<Option<FeeRate>> {
        match self {
            Backend::BitcoindRpc(rpc) => match rpc.estimate_smart_fee(target_blocks, None) {
                Ok(res) => Ok(res.fee_rate.map(|btc_per_kvb| {
                    let sat_per_vb = (btc_per_kvb.to_sat() as f64 / 1000.0).ceil().max(1.0) as u64;
                    FeeRate::from_sat_per_vb(sat_per_vb).unwrap_or(FeeRate::BROADCAST_MIN)
                })),
                Err(_) => Ok(None),
            },
            Backend::Esplora(client) => {
                let estimates = match client.get_fee_estimates() {
                    Ok(e) => e,
                    Err(_) => return Ok(None),
                };
                Ok(pick_esplora_fee_rate(&estimates, target_blocks))
            }
        }
    }

    /// The one operation that's inherently bitcoind-specific: mining is meaningless against a
    /// block explorer API. Returns `None` for an Esplora backend so callers can give a clear
    /// "this only works with bitcoind" message instead of a confusing one.
    pub fn as_bitcoind_rpc(&self) -> Option<&bitcoincore_rpc::Client> {
        match self {
            Backend::BitcoindRpc(rpc) => Some(rpc),
            Backend::Esplora(_) => None,
        }
    }
}

/// Esplora's `/fee-estimates` reports sat/vB directly, keyed by confirmation target in blocks --
/// pulled out of [`Backend::estimate_fee_rate`] as a pure function so the selection logic (no
/// network calls involved) can be unit-tested without a live server.
fn pick_esplora_fee_rate(estimates: &std::collections::HashMap<u16, f64>, target_blocks: u16) -> Option<FeeRate> {
    // Pick the tightest target available that's still at or beyond what was asked for; if
    // nothing covers the target (e.g. only a 2-block estimate exists but 6 was asked for),
    // fall back to whatever the fastest-confirming estimate is rather than giving up entirely.
    let sat_per_vb = estimates
        .iter()
        .filter(|&(&blocks, _)| blocks <= target_blocks)
        .max_by_key(|&(&blocks, _)| blocks)
        .or_else(|| estimates.iter().min_by_key(|&(&blocks, _)| blocks))
        .map(|(_, rate)| rate.ceil().max(1.0) as u64);
    sat_per_vb.and_then(FeeRate::from_sat_per_vb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_tightest_target_at_or_beyond_what_was_asked() {
        let estimates = std::collections::HashMap::from([(2, 10.0), (6, 5.0), (144, 1.0)]);
        // Asking for 6-block confirmation should pick exactly the 6-block estimate (5 sat/vB),
        // not the faster-but-pricier 2-block one or the slower-but-cheaper 144-block one.
        assert_eq!(
            pick_esplora_fee_rate(&estimates, 6),
            FeeRate::from_sat_per_vb(5)
        );
    }

    #[test]
    fn falls_back_to_fastest_estimate_when_nothing_covers_the_target() {
        // Only faster-than-asked-for estimates exist (e.g. a 1-block target with no 1-block
        // estimate available) -- should still return something rather than `None`.
        let estimates = std::collections::HashMap::from([(6, 5.0), (144, 1.0)]);
        assert_eq!(
            pick_esplora_fee_rate(&estimates, 1),
            FeeRate::from_sat_per_vb(5)
        );
    }

    #[test]
    fn empty_estimates_yield_no_opinion() {
        let estimates = std::collections::HashMap::new();
        assert_eq!(pick_esplora_fee_rate(&estimates, 6), None);
    }

    #[test]
    fn esplora_backend_has_no_bitcoind_rpc_escape_hatch() {
        // Constructing a BlockingClient doesn't connect anywhere -- safe to build with a bogus
        // URL just to exercise `as_bitcoind_rpc`'s branch without needing a live server.
        let client = esplora_client::Builder::new("http://localhost:0").build_blocking();
        let backend = Backend::Esplora(client);
        assert!(
            backend.as_bitcoind_rpc().is_none(),
            "mine must not be reachable through an Esplora backend"
        );
    }

    #[test]
    fn fractional_sat_per_vb_rounds_up_rather_than_underpaying() {
        let estimates = std::collections::HashMap::from([(6, 1.2)]);
        // Rounding down to 1 sat/vB here would under-pay what Esplora actually estimated.
        assert_eq!(
            pick_esplora_fee_rate(&estimates, 6),
            FeeRate::from_sat_per_vb(2)
        );
    }
}
