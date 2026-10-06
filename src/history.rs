use bdk_wallet::chain::ChainPosition;
use bdk_wallet::bitcoin::{SignedAmount, Txid};

use crate::walletdb::OpenWallet;

pub enum TxStatus {
    Confirmed { height: u32, confirmations: u32 },
    Unconfirmed,
}

pub struct HistoryEntry {
    pub txid: Txid,
    pub net: SignedAmount,
    pub status: TxStatus,
}

/// Wallet-relative transaction history, most recent first.
pub fn history(wallet: &OpenWallet) -> Vec<HistoryEntry> {
    let tip_height = wallet.latest_checkpoint().height();
    let mut entries: Vec<HistoryEntry> = wallet
        .transactions()
        .map(|canonical_tx| {
            let (sent, received) = wallet.sent_and_received(&canonical_tx.tx_node.tx);
            let net = received.to_signed().expect("amount within i64 range")
                - sent.to_signed().expect("amount within i64 range");
            let status = match canonical_tx.chain_position {
                ChainPosition::Confirmed { anchor, .. } => TxStatus::Confirmed {
                    height: anchor.block_id.height,
                    confirmations: tip_height.saturating_sub(anchor.block_id.height) + 1,
                },
                ChainPosition::Unconfirmed { .. } => TxStatus::Unconfirmed,
            };
            HistoryEntry {
                txid: canonical_tx.tx_node.txid,
                net,
                status,
            }
        })
        .collect();

    entries.sort_by(|a, b| match (&a.status, &b.status) {
        (TxStatus::Unconfirmed, TxStatus::Confirmed { .. }) => std::cmp::Ordering::Less,
        (TxStatus::Confirmed { .. }, TxStatus::Unconfirmed) => std::cmp::Ordering::Greater,
        (TxStatus::Confirmed { height: ha, .. }, TxStatus::Confirmed { height: hb, .. }) => {
            hb.cmp(ha)
        }
        (TxStatus::Unconfirmed, TxStatus::Unconfirmed) => std::cmp::Ordering::Equal,
    });
    entries
}
