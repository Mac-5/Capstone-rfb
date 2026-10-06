use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::Network;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{PersistedWallet, Wallet};

use crate::config::WalletPaths;
use crate::seed::{ScriptKind, Seed};

pub type OpenWallet = PersistedWallet<Connection>;

/// Create a brand-new wallet database from `seed`, persist the seed file next to it, and
/// return the freshly created (and already-persisted) wallet.
pub fn create(
    paths: &WalletPaths,
    network: Network,
    seed: &Seed,
    password: &str,
    script_kind: ScriptKind,
) -> Result<(OpenWallet, Connection)> {
    if paths.db_path.exists() {
        bail!(
            "a wallet database already exists at {} -- delete it first or use a different --data-dir",
            paths.db_path.display()
        );
    }

    let mut conn = Connection::open(&paths.db_path)
        .with_context(|| format!("creating sqlite database at {}", paths.db_path.display()))?;
    let wallet = match script_kind {
        ScriptKind::Segwit => {
            let (external, internal) = seed.bip84_templates();
            Wallet::create(external, internal)
                .network(network)
                .create_wallet(&mut conn)
                .context("initializing wallet")?
        }
        ScriptKind::Taproot => {
            let (external, internal) = seed.bip86_templates();
            Wallet::create(external, internal)
                .network(network)
                .create_wallet(&mut conn)
                .context("initializing wallet")?
        }
        ScriptKind::Multisig => {
            bail!("multisig wallets must be created via `create_multisig`, not `create`")
        }
    };

    seed.save(&paths.seed_path, password)?;
    Ok((wallet, conn))
}

/// Create a brand-new multisig (BIP48 `wsh(sortedmulti(...))`) wallet database: `seed`'s own key
/// plus `cosigners`' pasted-in public key fragments (see [`Seed::multisig_xpub_fragment`]),
/// requiring `threshold`-of-`cosigners.len() + 1` signatures to spend. Otherwise identical to
/// [`create`] -- same existence guard, same seed-file persistence at the end.
pub fn create_multisig(
    paths: &WalletPaths,
    network: Network,
    seed: &Seed,
    password: &str,
    threshold: usize,
    cosigners: &[String],
) -> Result<(OpenWallet, Connection)> {
    if paths.db_path.exists() {
        bail!(
            "a wallet database already exists at {} -- delete it first or use a different --data-dir",
            paths.db_path.display()
        );
    }

    let mut conn = Connection::open(&paths.db_path)
        .with_context(|| format!("creating sqlite database at {}", paths.db_path.display()))?;
    let (external, internal) = seed.multisig_descriptors(network, threshold, cosigners)?;
    let wallet = Wallet::create(external, internal)
        .network(network)
        .create_wallet(&mut conn)
        .context("initializing multisig wallet")?;

    seed.save(&paths.seed_path, password)?;
    Ok((wallet, conn))
}

/// Open a previously-created wallet's public state (no private keys).
pub fn load(paths: &WalletPaths, network: Network) -> Result<(OpenWallet, Connection)> {
    if !paths.db_path.exists() {
        bail!(
            "no wallet found at {} -- run `create` or `restore` first",
            paths.db_path.display()
        );
    }
    let mut conn = Connection::open(&paths.db_path)
        .with_context(|| format!("opening sqlite database at {}", paths.db_path.display()))?;
    let wallet = Wallet::load()
        .check_network(network)
        .load_wallet(&mut conn)
        .context("loading wallet")?
        .context("wallet database exists but contains no wallet data")?;
    Ok((wallet, conn))
}
