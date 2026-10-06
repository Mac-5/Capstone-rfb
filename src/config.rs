use std::path::PathBuf;

use anyhow::{Context, Result};
use bitcoin::Network;

/// Name used for the single wallet that lives directly under `<data_dir>/<network>/`
/// (`wallet.sqlite` there, not in a named subdirectory). Keeping this layout for the first
/// wallet means existing data created before multi-wallet support still loads unchanged.
pub const DEFAULT_WALLET_NAME: &str = "default";

/// Filesystem layout and RPC connection details for one named wallet on one network.
///
/// Everything lives under `<data_dir>/<network>/` (the "default" wallet directly there, any
/// other name in its own subdirectory):
/// - `wallet.sqlite`  public wallet state (descriptors, UTXOs, tx graph, chain) via bdk_wallet.
/// - `seed.dat`       the mnemonic + passphrase, kept separate from the public state on purpose
///                     (bdk_wallet does not persist private key material into its own database).
pub struct WalletPaths {
    pub db_path: PathBuf,
    pub seed_path: PathBuf,
}

impl WalletPaths {
    /// Resolve paths for `name` under `data_dir`/`network`, creating the directory if needed.
    pub fn named(data_dir: Option<PathBuf>, network: Network, name: &str) -> Result<Self> {
        let network_dir = network_dir(data_dir, network)?;
        let dir = if name == DEFAULT_WALLET_NAME {
            network_dir
        } else {
            network_dir.join(name)
        };
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating wallet data directory at {}", dir.display()))?;
        Ok(Self {
            db_path: dir.join("wallet.sqlite"),
            seed_path: dir.join("seed.dat"),
        })
    }

    /// A fresh, always-valid path for a new PSBT file: `<wallet dir>/psbt/<prefix>-<unix
    /// time>.psbt`. Lives inside this wallet's own already-proven-persistent directory (not
    /// `/tmp`, which isn't reliably persistent across process launches in every environment --
    /// discovered the hard way), and always includes a filename, so it can never collide with
    /// the two real mistakes that are easy to make typing a path by hand: pointing at a bare
    /// directory, or a path that doesn't exist yet because nothing created it.
    pub fn new_psbt_path(&self, prefix: &str) -> Result<PathBuf> {
        let dir = self.db_path.parent().context("wallet database path has no parent directory")?.join("psbt");
        std::fs::create_dir_all(&dir).with_context(|| format!("creating PSBT directory at {}", dir.display()))?;
        let unix_time = std::time::UNIX_EPOCH.elapsed().expect("system clock").as_secs();
        Ok(dir.join(format!("{prefix}-{unix_time}.psbt")))
    }

    /// Permanently delete this wallet's files from disk: the sqlite database (and any
    /// WAL/SHM/journal sidecar files sqlite may have left behind) and the encrypted seed file.
    /// Also removes the now-empty containing directory -- harmless to attempt even for the
    /// "default" wallet, whose files live directly in the shared network directory alongside any
    /// other named wallets, since `remove_dir` only succeeds when the directory is empty.
    pub fn delete(&self) -> Result<()> {
        let db_name = self
            .db_path
            .file_name()
            .context("wallet database path has no file name")?
            .to_string_lossy()
            .into_owned();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = self.db_path.with_file_name(format!("{db_name}{suffix}"));
            if path.exists() {
                std::fs::remove_file(&path).with_context(|| format!("deleting {}", path.display()))?;
            }
        }
        if self.seed_path.exists() {
            std::fs::remove_file(&self.seed_path)
                .with_context(|| format!("deleting {}", self.seed_path.display()))?;
        }
        if let Some(dir) = self.db_path.parent() {
            let _ = std::fs::remove_dir(dir);
        }
        Ok(())
    }

    /// Every wallet name that already exists under `data_dir`/`network`, sorted, "default" first.
    pub fn list(data_dir: Option<PathBuf>, network: Network) -> Result<Vec<String>> {
        let network_dir = network_dir(data_dir, network)?;
        let mut names = Vec::new();

        if network_dir.join("wallet.sqlite").exists() {
            names.push(DEFAULT_WALLET_NAME.to_string());
        }
        if let Ok(entries) = std::fs::read_dir(&network_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && path.join("wallet.sqlite").exists() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        names.push(name.to_string());
                    }
                }
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}

fn network_dir(data_dir: Option<PathBuf>, network: Network) -> Result<PathBuf> {
    let base = match data_dir {
        Some(p) => p,
        None => dirs::home_dir()
            .context("could not determine home directory; pass --data-dir explicitly")?
            .join(".rfb_wallet"),
    };
    Ok(base.join(network_dir_name(network)))
}

fn network_dir_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet3",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

/// Connection details for a local (or remote) `bitcoind` JSON-RPC endpoint.
pub struct RpcConfig {
    pub url: String,
    pub cookie: Option<PathBuf>,
    pub user: Option<String>,
    pub pass: Option<String>,
}

impl RpcConfig {
    pub fn client(&self) -> Result<bitcoincore_rpc::Client> {
        use bitcoincore_rpc::Auth;

        let auth = match (&self.cookie, &self.user, &self.pass) {
            (Some(path), _, _) => Auth::CookieFile(path.clone()),
            (None, Some(user), Some(pass)) => Auth::UserPass(user.clone(), pass.clone()),
            (None, None, None) => Auth::None,
            _ => anyhow::bail!("rpc auth: provide both --rpc-user and --rpc-pass, or neither"),
        };
        bitcoincore_rpc::Client::new(&self.url, auth).context("connecting to bitcoind RPC")
    }
}

pub fn default_rpc_url(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "127.0.0.1:8332",
        Network::Testnet | Network::Testnet4 => "127.0.0.1:18332",
        Network::Signet => "127.0.0.1:38332",
        Network::Regtest => "127.0.0.1:18443",
    }
}

/// Connection details for a remote Esplora (block explorer) server -- an alternative to running
/// your own `bitcoind`. Works on any network with a public instance (e.g. mempool.space), but
/// has no mining capability, so it can't stand in for `bitcoind` on regtest.
pub struct EsploraConfig {
    pub url: String,
}

impl EsploraConfig {
    pub fn client(&self) -> bdk_esplora::esplora_client::BlockingClient {
        // Without an explicit timeout, an unreachable or slow server hangs this request
        // forever -- and since the TUI is single-threaded and synchronous, that means the
        // *entire application* freezes with no way to cancel, not just this one sync. 30s is
        // generous enough for a real (if slow) server while still eventually giving up.
        bdk_esplora::esplora_client::Builder::new(&self.url)
            .timeout(30)
            .build_blocking()
    }
}
