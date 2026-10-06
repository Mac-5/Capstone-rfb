mod app;
mod ui;

use std::path::PathBuf;

use anyhow::Result;
use bdk_wallet::bitcoin::Network;
use clap::Parser;

use rfb_wallet::backend::BackendConfig;
use rfb_wallet::config::{self, EsploraConfig, RpcConfig};

#[derive(Parser)]
#[command(name = "rfb_wallet", about = "A non-custodial BIP84 SegWit Bitcoin wallet (TUI)")]
struct Cli {
    /// Bitcoin network to operate on.
    #[arg(long, default_value = "regtest")]
    network: Network,

    /// Directory holding per-network wallet data. Defaults to ~/.rfb_wallet.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Esplora server URL (e.g. https://mempool.space/api) -- an alternative to --rpc-* for
    /// syncing/broadcasting without running your own bitcoind. Mining (regtest) still needs
    /// bitcoind, since Esplora is a read/broadcast-only block explorer API.
    #[arg(long)]
    esplora_url: Option<String>,

    /// bitcoind RPC host:port. Defaults to the standard port for --network. Ignored if
    /// --esplora-url is given.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Path to bitcoind's .cookie file. Defaults to Bitcoin Core's standard per-network path.
    #[arg(long)]
    rpc_cookie: Option<PathBuf>,

    #[arg(long)]
    rpc_user: Option<String>,

    #[arg(long)]
    rpc_pass: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let network = cli.network;
    let backend_cfg = match cli.esplora_url {
        Some(url) => BackendConfig::Esplora(EsploraConfig { url }),
        None => BackendConfig::BitcoindRpc(RpcConfig {
            url: cli.rpc_url.unwrap_or_else(|| config::default_rpc_url(network).to_string()),
            cookie: cli.rpc_cookie.or_else(|| default_cookie_path(network)),
            user: cli.rpc_user,
            pass: cli.rpc_pass,
        }),
    };

    let mut terminal = ratatui::init();
    // Enabling mouse capture is what lets the Dashboard's "[click to copy]" hint actually
    // respond to a click; the trade-off (documented where it's handled, `App::handle_mouse`) is
    // that it takes over the terminal's own native click-and-drag text selection everywhere in
    // the app while this is active. Always paired with disabling it before handing the terminal
    // back, same as the raw-mode/alternate-screen setup `ratatui::init`/`restore` already pairs.
    let _ = ratatui::crossterm::execute!(std::io::stdout(), ratatui::crossterm::event::EnableMouseCapture);
    let result = app::run(&mut terminal, cli.data_dir, network, backend_cfg);
    let _ = ratatui::crossterm::execute!(std::io::stdout(), ratatui::crossterm::event::DisableMouseCapture);
    ratatui::restore();
    result
}

fn default_cookie_path(network: Network) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    #[cfg(target_os = "macos")]
    let base = home.join("Library/Application Support/Bitcoin");
    #[cfg(not(target_os = "macos"))]
    let base = home.join(".bitcoin");

    let path = match network {
        Network::Bitcoin => base.join(".cookie"),
        Network::Testnet => base.join("testnet3").join(".cookie"),
        Network::Testnet4 => base.join("testnet4").join(".cookie"),
        Network::Signet => base.join("signet").join(".cookie"),
        Network::Regtest => base.join("regtest").join(".cookie"),
    };
    path.exists().then_some(path)
}
