use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Txid};
use bdk_wallet::keys::bip39::WordCount;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, LocalOutput};
use bitcoincore_rpc::RpcApi;
use ratatui::crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use ratatui::DefaultTerminal;

use rfb_wallet::backend::{Backend, BackendConfig};
use rfb_wallet::config::WalletPaths;
use rfb_wallet::history::{self, HistoryEntry, TxStatus};
use rfb_wallet::seed::{ScriptKind, Seed};
use rfb_wallet::send::{self, SendReport};
use rfb_wallet::sync::{self, SyncReport};
use rfb_wallet::walletdb::{self, OpenWallet};

use crate::ui;

/// Top-level application state. Owns everything the UI needs to render and everything a
/// keypress might mutate. There is deliberately no background thread: every long-running
/// action (sync, send, mine) runs synchronously on the input-handling path, with a "Working..."
/// status drawn to the screen first so the UI doesn't look frozen without explanation.
pub struct App {
    pub network: Network,
    pub data_dir: Option<PathBuf>,
    pub backend_cfg: BackendConfig,
    pub screen: Screen,
    pub status: Status,
    pub wallet: Option<WalletSession>,
    pub should_quit: bool,
    /// The most recent "interesting" value worth a one-click copy (an address, an exported
    /// multisig key) -- set alongside `status` whenever such a value is shown, cleared whenever
    /// a Dashboard action doesn't produce one. Paired with `copy_hint_rect` for mouse hit-testing.
    pub last_copyable: Option<String>,
    /// Screen coordinates of the clickable status box on the Dashboard, recomputed every render
    /// (`render_dashboard` owns the actual layout math) -- `None` whenever there's nothing
    /// copyable to click on, so a stray click elsewhere is simply ignored.
    pub copy_hint_rect: Option<Rect>,
}

pub enum Status {
    Idle,
    Working(String),
    Info(String),
    Error(String),
}

/// Everything that only exists once a wallet is created/restored/loaded. Carries its own
/// name and paths so switching wallets is just swapping this struct out for another.
pub struct WalletSession {
    pub name: String,
    pub paths: WalletPaths,
    pub wallet: OpenWallet,
    pub conn: Connection,
    pub history_cache: Vec<HistoryEntry>,
    pub history_state: ListState,
    /// Decrypted seed, cached in memory after the first password prompt this session so
    /// subsequent sends don't re-prompt. Never written back to disk; cleared by switching away
    /// from this wallet (a fresh `WalletSession` just doesn't have one).
    pub unlocked_seed: Option<Seed>,
    /// The most recent PSBT file this session wrote or read, if any -- used to auto-chain the
    /// next step's "read from" field (export's output becomes sign's input, sign's output
    /// becomes the next signer's input or broadcast's input) so the common sequential flow needs
    /// no manual path-typing at all.
    pub last_psbt_path: Option<PathBuf>,
}

impl WalletSession {
    fn new(name: String, paths: WalletPaths, wallet: OpenWallet, conn: Connection) -> Self {
        let history_cache = history::history(&wallet);
        let mut history_state = ListState::default();
        if !history_cache.is_empty() {
            history_state.select(Some(0));
        }
        Self {
            name,
            paths,
            wallet,
            conn,
            history_cache,
            history_state,
            unlocked_seed: None,
            last_psbt_path: None,
        }
    }

    fn refresh_history(&mut self) {
        self.history_cache = history::history(&self.wallet);
        if self.history_cache.is_empty() {
            self.history_state.select(None);
        } else if self.history_state.selected().is_none() {
            self.history_state.select(Some(0));
        }
    }

    pub fn select_next(&mut self) {
        let len = self.history_cache.len();
        if len == 0 {
            return;
        }
        let next = match self.history_state.selected() {
            Some(i) if i + 1 < len => i + 1,
            Some(i) => i,
            None => 0,
        };
        self.history_state.select(Some(next));
    }

    pub fn select_prev(&mut self) {
        if self.history_cache.is_empty() {
            return;
        }
        let prev = match self.history_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.history_state.select(Some(prev));
    }
}

#[derive(Clone)]
pub enum Screen {
    /// Lists every wallet found under this data dir/network, plus actions to create/restore
    /// another. Used both at startup (when there's more than one, or none) and as an in-app
    /// switcher reachable from the Dashboard with `w`.
    WalletPicker {
        names: Vec<String>,
        selected: usize,
    },
    /// Reached from `WalletPicker` with `d` -- a deliberate extra step before anything is
    /// deleted, since this is the one in-app action with no undo (short of still having the
    /// mnemonic to restore from).
    ConfirmDeleteWallet {
        name: String,
        /// Where to return the cursor afterward if the user cancels.
        names: Vec<String>,
        selected: usize,
    },
    MnemonicReveal(String),
    NameInput {
        purpose: NamePurpose,
        name: String,
    },
    /// Choose SegWit vs Taproot vs Multisig before a new wallet's keys are ever derived --
    /// unlike the password, this can't be changed later without starting over, since it
    /// determines the derivation path itself.
    ScriptTypeChoice {
        purpose: NamePurpose,
        name: String,
        choice: ScriptKind,
    },
    /// Multisig only: collect the total number of cosigners (N) and signing threshold (M)
    /// before asking for each cosigner's key.
    MultisigConfig {
        purpose: NamePurpose,
        name: String,
        total: String,
        threshold: String,
        focus: MultisigConfigField,
    },
    /// Multisig only: collect each of the `total - 1` other cosigners' exported public key
    /// fragments (this wallet's own key is derived automatically from its seed, not pasted in).
    MultisigCosigners {
        purpose: NamePurpose,
        name: String,
        total: usize,
        threshold: usize,
        cosigners: Vec<String>,
        current: String,
        error: Option<String>,
    },
    /// Collects (and confirms) the password used to encrypt this wallet's seed file, on the
    /// way to either `do_create_named` (purpose = Create) or the mnemonic-entry `Restore` form
    /// (purpose = Restore, which carries the password forward to encrypt what gets typed there).
    SetPassword(SetPasswordForm),
    Restore(RestoreForm),
    Dashboard,
    /// Derive and display this wallet's BIP48 multisig account key, to copy into a *different*
    /// wallet instance being set up as a multisig cosigner. Works on any wallet, not just
    /// multisig ones -- any seed can serve as a cosigner key source.
    ExportMultisigKey(ExportMultisigKeyForm),
    /// Apply this wallet's signature to a (possibly already partially-signed) multisig PSBT and
    /// report how many of the threshold signatures are now present. Doesn't broadcast -- same
    /// as the generic Import+Sign screen, `p` / `ImportBroadcastPsbt` remains the one broadcast
    /// step regardless of how many signing rounds preceded it.
    MultisigSign(MultisigSignForm),
    /// Browse the wallet's UTXOs and pick which ones to spend (coin control). Reached from the
    /// Dashboard with `u`; `s` here proceeds to `Send` with the selected outpoints attached,
    /// leaving automatic coin selection in place if none are selected.
    CoinPicker {
        coins: Vec<LocalOutput>,
        selected: Vec<bool>,
        cursor: usize,
    },
    Send(SendForm),
    /// Replace-by-fee on the History panel's currently-selected (unconfirmed) transaction.
    BumpFee(BumpFeeForm),
    /// Build an unsigned PSBT and write it to a file -- the watch-only half of the air-gapped
    /// signing flow. Needs only this wallet's public descriptors, never its seed.
    ExportPsbt(ExportPsbtForm),
    /// Read a PSBT file, sign it with this wallet's seed, and write the result to another file
    /// -- the air-gapped-signer half. Never touches the network.
    ImportSignPsbt(ImportSignForm),
    /// Read an already-fully-signed PSBT file and broadcast it -- closes the loop back on the
    /// watch-only side.
    ImportBroadcastPsbt(ImportBroadcastForm),
    Mine(MineForm),
}

impl Default for Screen {
    fn default() -> Self {
        Screen::WalletPicker {
            names: Vec::new(),
            selected: 0,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum NamePurpose {
    #[default]
    Create,
    Restore,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum PasswordField {
    #[default]
    Password,
    Confirm,
}

impl PasswordField {
    fn next(self) -> Self {
        match self {
            PasswordField::Password => PasswordField::Confirm,
            PasswordField::Confirm => PasswordField::Password,
        }
    }
}

/// Params collected on the multisig creation/restoration path, carried through
/// `SetPasswordForm`/`RestoreForm` the same way `script_kind` already is.
#[derive(Clone)]
pub struct MultisigParams {
    pub threshold: usize,
    /// Other cosigners' exported `[fingerprint/path]xpub...` fragments. This wallet's own key
    /// is derived from its seed at creation time, not stored here.
    pub cosigners: Vec<String>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum MultisigConfigField {
    #[default]
    Total,
    Threshold,
}

impl MultisigConfigField {
    fn next(self) -> Self {
        match self {
            MultisigConfigField::Total => MultisigConfigField::Threshold,
            MultisigConfigField::Threshold => MultisigConfigField::Total,
        }
    }
}

#[derive(Clone, Default)]
pub struct ExportMultisigKeyForm {
    pub password: String,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum MultisigSignField {
    #[default]
    InPath,
    OutPath,
    Password,
}

impl MultisigSignField {
    fn next(self) -> Self {
        match self {
            MultisigSignField::InPath => MultisigSignField::OutPath,
            MultisigSignField::OutPath => MultisigSignField::Password,
            MultisigSignField::Password => MultisigSignField::InPath,
        }
    }
}

#[derive(Clone, Default)]
pub struct MultisigSignForm {
    pub in_path: String,
    pub out_path: String,
    pub password: String,
    pub focus: MultisigSignField,
    pub error: Option<String>,
}

impl MultisigSignForm {
    fn active_field_mut(&mut self) -> &mut String {
        match self.focus {
            MultisigSignField::InPath => &mut self.in_path,
            MultisigSignField::OutPath => &mut self.out_path,
            MultisigSignField::Password => &mut self.password,
        }
    }
}

#[derive(Clone, Default)]
pub struct SetPasswordForm {
    pub name: String,
    pub purpose: NamePurpose,
    pub script_kind: ScriptKind,
    pub multisig: Option<MultisigParams>,
    pub password: String,
    pub confirm: String,
    pub focus: PasswordField,
}

impl SetPasswordForm {
    fn active_field_mut(&mut self) -> &mut String {
        match self.focus {
            PasswordField::Password => &mut self.password,
            PasswordField::Confirm => &mut self.confirm,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum RestoreField {
    #[default]
    Mnemonic,
    Passphrase,
}

impl RestoreField {
    fn next(self) -> Self {
        match self {
            RestoreField::Mnemonic => RestoreField::Passphrase,
            RestoreField::Passphrase => RestoreField::Mnemonic,
        }
    }
}

#[derive(Clone, Default)]
pub struct RestoreForm {
    pub name: String,
    pub password: String,
    pub script_kind: ScriptKind,
    pub multisig: Option<MultisigParams>,
    pub mnemonic: String,
    pub passphrase: String,
    pub focus: RestoreField,
}

impl RestoreForm {
    fn active_field_mut(&mut self) -> &mut String {
        match self.focus {
            RestoreField::Mnemonic => &mut self.mnemonic,
            RestoreField::Passphrase => &mut self.passphrase,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum SendField {
    #[default]
    To,
    Sats,
    FeeRate,
    Password,
}

impl SendField {
    fn next(self) -> Self {
        match self {
            SendField::To => SendField::Sats,
            SendField::Sats => SendField::FeeRate,
            SendField::FeeRate => SendField::Password,
            SendField::Password => SendField::To,
        }
    }

    fn prev(self) -> Self {
        match self {
            SendField::To => SendField::Password,
            SendField::Sats => SendField::To,
            SendField::FeeRate => SendField::Sats,
            SendField::Password => SendField::FeeRate,
        }
    }
}

#[derive(Clone, Default)]
pub struct SendForm {
    pub to: String,
    pub sats: String,
    pub fee_rate: String,
    /// Only needed if the wallet hasn't been unlocked yet this session (see
    /// `WalletSession::unlocked_seed`). Left blank once already unlocked.
    pub password: String,
    /// Empty means automatic coin selection (bdk_wallet's default); non-empty means these are
    /// the *only* inputs used, set via the `CoinPicker` screen reachable with `c`.
    pub coins: Vec<OutPoint>,
    pub focus: SendField,
    pub error: Option<String>,
}

impl SendForm {
    fn active_field_mut(&mut self) -> &mut String {
        match self.focus {
            SendField::To => &mut self.to,
            SendField::Sats => &mut self.sats,
            SendField::FeeRate => &mut self.fee_rate,
            SendField::Password => &mut self.password,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum BumpFeeField {
    #[default]
    FeeRate,
    Password,
}

impl BumpFeeField {
    fn next(self) -> Self {
        match self {
            BumpFeeField::FeeRate => BumpFeeField::Password,
            BumpFeeField::Password => BumpFeeField::FeeRate,
        }
    }
}

#[derive(Clone)]
pub struct BumpFeeForm {
    pub txid: Txid,
    pub old_fee_rate_sat_vb: f64,
    pub fee_rate: String,
    pub password: String,
    pub focus: BumpFeeField,
    pub error: Option<String>,
}

impl BumpFeeForm {
    fn active_field_mut(&mut self) -> &mut String {
        match self.focus {
            BumpFeeField::FeeRate => &mut self.fee_rate,
            BumpFeeField::Password => &mut self.password,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum ExportPsbtField {
    #[default]
    To,
    Sats,
    FeeRate,
    Path,
}

impl ExportPsbtField {
    fn next(self) -> Self {
        match self {
            ExportPsbtField::To => ExportPsbtField::Sats,
            ExportPsbtField::Sats => ExportPsbtField::FeeRate,
            ExportPsbtField::FeeRate => ExportPsbtField::Path,
            ExportPsbtField::Path => ExportPsbtField::To,
        }
    }

    fn prev(self) -> Self {
        match self {
            ExportPsbtField::To => ExportPsbtField::Path,
            ExportPsbtField::Sats => ExportPsbtField::To,
            ExportPsbtField::FeeRate => ExportPsbtField::Sats,
            ExportPsbtField::Path => ExportPsbtField::FeeRate,
        }
    }
}

#[derive(Clone, Default)]
pub struct ExportPsbtForm {
    pub to: String,
    pub sats: String,
    pub fee_rate: String,
    pub path: String,
    pub focus: ExportPsbtField,
    pub error: Option<String>,
}

impl ExportPsbtForm {
    fn active_field_mut(&mut self) -> &mut String {
        match self.focus {
            ExportPsbtField::To => &mut self.to,
            ExportPsbtField::Sats => &mut self.sats,
            ExportPsbtField::FeeRate => &mut self.fee_rate,
            ExportPsbtField::Path => &mut self.path,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum ImportSignField {
    #[default]
    InPath,
    OutPath,
    Password,
}

impl ImportSignField {
    fn next(self) -> Self {
        match self {
            ImportSignField::InPath => ImportSignField::OutPath,
            ImportSignField::OutPath => ImportSignField::Password,
            ImportSignField::Password => ImportSignField::InPath,
        }
    }
}

#[derive(Clone, Default)]
pub struct ImportSignForm {
    pub in_path: String,
    pub out_path: String,
    pub password: String,
    pub focus: ImportSignField,
    pub error: Option<String>,
}

impl ImportSignForm {
    fn active_field_mut(&mut self) -> &mut String {
        match self.focus {
            ImportSignField::InPath => &mut self.in_path,
            ImportSignField::OutPath => &mut self.out_path,
            ImportSignField::Password => &mut self.password,
        }
    }
}

#[derive(Clone, Default)]
pub struct ImportBroadcastForm {
    pub path: String,
    pub error: Option<String>,
}

#[derive(Clone, Default)]
pub struct MineForm {
    pub blocks: String,
}

/// Drive the application until the user quits. Owns the terminal for the whole session.
pub fn run(
    terminal: &mut DefaultTerminal,
    data_dir: Option<PathBuf>,
    network: Network,
    backend_cfg: BackendConfig,
) -> Result<()> {
    let mut app = App {
        network,
        data_dir,
        backend_cfg,
        screen: Screen::default(),
        status: Status::Idle,
        wallet: None,
        should_quit: false,
        last_copyable: None,
        copy_hint_rect: None,
    };
    app.status = Status::Working("Loading wallet...".to_string());
    let _ = terminal.draw(|f| ui::render(f, &mut app));
    app.screen = app.startup_screen(terminal);

    terminal.draw(|f| ui::render(f, &mut app))?;
    while !app.should_quit {
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                app.handle_key(terminal, key)?;
            }
            Event::Mouse(mouse) => app.handle_mouse(mouse),
            _ => {}
        }
        terminal.draw(|f| ui::render(f, &mut app))?;
    }
    Ok(())
}

impl App {
    /// Auto-load the only wallet that exists (the common case), otherwise show the picker --
    /// empty-handed if there are none yet, or for a real choice if there's more than one.
    fn startup_screen(&mut self, terminal: &mut DefaultTerminal) -> Screen {
        match WalletPaths::list(self.data_dir.clone(), self.network) {
            Ok(names) if names.len() == 1 => match self.do_load_named(terminal, &names[0]) {
                Ok(()) => Screen::Dashboard,
                Err(e) => {
                    self.status = Status::Error(format!("{e:#}"));
                    self.wallet_picker_screen()
                }
            },
            Ok(names) => Screen::WalletPicker { names, selected: 0 },
            Err(e) => {
                self.status = Status::Error(format!("{e:#}"));
                Screen::WalletPicker {
                    names: Vec::new(),
                    selected: 0,
                }
            }
        }
    }

    fn wallet_picker_screen(&self) -> Screen {
        let names = WalletPaths::list(self.data_dir.clone(), self.network).unwrap_or_default();
        let selected = self
            .wallet
            .as_ref()
            .and_then(|s| names.iter().position(|n| n == &s.name))
            .unwrap_or(0);
        Screen::WalletPicker { names, selected }
    }

    /// A left click landing inside `copy_hint_rect` (the Dashboard's status box, only set while
    /// it's showing something copyable) copies `last_copyable` to the system clipboard. Anywhere
    /// else, or with nothing copyable active, a click is simply ignored -- this app has no other
    /// mouse-driven controls.
    fn handle_mouse(&mut self, mouse: MouseEvent) {
        if mouse.kind != MouseEventKind::Down(MouseButton::Left) {
            return;
        }
        let Some(rect) = self.copy_hint_rect else { return };
        let hit = mouse.column >= rect.x
            && mouse.column < rect.x + rect.width
            && mouse.row >= rect.y
            && mouse.row < rect.y + rect.height;
        if !hit {
            return;
        }
        let Some(value) = self.last_copyable.clone() else { return };
        copy_to_clipboard(&value);
        self.status = Status::Info(format!("Copied to clipboard: {value}"));
    }

    fn handle_key(&mut self, terminal: &mut DefaultTerminal, key: KeyEvent) -> Result<()> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return Ok(());
        }

        let screen = std::mem::take(&mut self.screen);
        self.screen = match screen {
            Screen::WalletPicker { names, selected } => {
                self.handle_wallet_picker_key(terminal, key, names, selected)
            }
            Screen::ConfirmDeleteWallet { name, names, selected } => {
                self.handle_confirm_delete_wallet_key(key, name, names, selected)
            }
            Screen::MnemonicReveal(mnemonic) => handle_mnemonic_reveal_key(key, mnemonic),
            Screen::NameInput { purpose, name } => self.handle_name_input_key(key, purpose, name),
            Screen::ScriptTypeChoice { purpose, name, choice } => {
                self.handle_script_type_choice_key(key, purpose, name, choice)
            }
            Screen::MultisigConfig { purpose, name, total, threshold, focus } => {
                self.handle_multisig_config_key(key, purpose, name, total, threshold, focus)
            }
            Screen::MultisigCosigners { purpose, name, total, threshold, cosigners, current, error } => self
                .handle_multisig_cosigners_key(key, purpose, name, total, threshold, cosigners, current, error),
            Screen::SetPassword(form) => self.handle_set_password_key(terminal, key, form),
            Screen::Restore(form) => self.handle_restore_key(terminal, key, form),
            Screen::Dashboard => self.handle_dashboard_key(terminal, key),
            Screen::CoinPicker { coins, selected, cursor } => {
                self.handle_coin_picker_key(key, coins, selected, cursor)
            }
            Screen::Send(form) => self.handle_send_key(terminal, key, form),
            Screen::BumpFee(form) => self.handle_bump_fee_key(terminal, key, form),
            Screen::ExportPsbt(form) => self.handle_export_psbt_key(terminal, key, form),
            Screen::ImportSignPsbt(form) => self.handle_import_sign_key(terminal, key, form),
            Screen::ImportBroadcastPsbt(form) => self.handle_import_broadcast_key(terminal, key, form),
            Screen::Mine(form) => self.handle_mine_key(terminal, key, form),
            Screen::ExportMultisigKey(form) => self.handle_export_multisig_key_key(terminal, key, form),
            Screen::MultisigSign(form) => self.handle_multisig_sign_key(terminal, key, form),
        };
        Ok(())
    }

    fn handle_wallet_picker_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        names: Vec<String>,
        mut selected: usize,
    ) -> Screen {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc => {
                if self.wallet.is_some() {
                    return Screen::Dashboard;
                }
            }
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Down => {
                if selected + 1 < names.len() {
                    selected += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(name) = names.get(selected).cloned() {
                    self.status = Status::Working(format!("Loading and syncing wallet '{name}'..."));
                    let _ = terminal.draw(|f| ui::render(f, self));
                    match self.do_load_named(terminal, &name) {
                        Ok(()) => return Screen::Dashboard,
                        Err(e) => self.status = Status::Error(format!("{e:#}")),
                    }
                }
            }
            KeyCode::Char('n') => {
                return Screen::NameInput {
                    purpose: NamePurpose::Create,
                    name: String::new(),
                }
            }
            KeyCode::Char('r') => {
                return Screen::NameInput {
                    purpose: NamePurpose::Restore,
                    name: String::new(),
                }
            }
            KeyCode::Char('d') => {
                if let Some(name) = names.get(selected).cloned() {
                    return Screen::ConfirmDeleteWallet { name, names, selected };
                }
            }
            _ => {}
        }
        Screen::WalletPicker { names, selected }
    }

    fn handle_confirm_delete_wallet_key(
        &mut self,
        key: KeyEvent,
        name: String,
        names: Vec<String>,
        selected: usize,
    ) -> Screen {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => match self.do_delete_named(&name) {
                Ok(()) => {
                    self.status = Status::Info(format!("Wallet '{name}' deleted."));
                    return self.wallet_picker_screen();
                }
                Err(e) => {
                    self.status = Status::Error(format!("{e:#}"));
                    return Screen::WalletPicker { names, selected };
                }
            },
            KeyCode::Char('n') | KeyCode::Esc => return Screen::WalletPicker { names, selected },
            _ => {}
        }
        Screen::ConfirmDeleteWallet { name, names, selected }
    }

    fn handle_name_input_key(&mut self, key: KeyEvent, purpose: NamePurpose, mut name: String) -> Screen {
        match key.code {
            KeyCode::Esc => return self.wallet_picker_screen(),
            KeyCode::Backspace => {
                name.pop();
            }
            KeyCode::Char(c) if c.is_ascii_alphanumeric() || c == '-' || c == '_' => name.push(c),
            KeyCode::Enter => {
                let trimmed = name.trim().to_string();
                if trimmed.is_empty() {
                    self.status = Status::Error("wallet name cannot be empty".to_string());
                    return Screen::NameInput { purpose, name };
                }
                return Screen::ScriptTypeChoice {
                    purpose,
                    name: trimmed,
                    choice: ScriptKind::default(),
                };
            }
            _ => {}
        }
        Screen::NameInput { purpose, name }
    }

    fn handle_script_type_choice_key(
        &mut self,
        key: KeyEvent,
        purpose: NamePurpose,
        name: String,
        choice: ScriptKind,
    ) -> Screen {
        let toggled = match choice {
            ScriptKind::Segwit => ScriptKind::Taproot,
            ScriptKind::Taproot => ScriptKind::Multisig,
            ScriptKind::Multisig => ScriptKind::Segwit,
        };
        match key.code {
            KeyCode::Esc => return self.wallet_picker_screen(),
            KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                return Screen::ScriptTypeChoice { purpose, name, choice: toggled }
            }
            KeyCode::Enter => {
                return match choice {
                    ScriptKind::Multisig => Screen::MultisigConfig {
                        purpose,
                        name,
                        total: String::new(),
                        threshold: String::new(),
                        focus: MultisigConfigField::default(),
                    },
                    ScriptKind::Segwit | ScriptKind::Taproot => Screen::SetPassword(SetPasswordForm {
                        name,
                        purpose,
                        script_kind: choice,
                        multisig: None,
                        password: String::new(),
                        confirm: String::new(),
                        focus: PasswordField::default(),
                    }),
                }
            }
            _ => {}
        }
        Screen::ScriptTypeChoice { purpose, name, choice }
    }

    fn handle_multisig_config_key(
        &mut self,
        key: KeyEvent,
        purpose: NamePurpose,
        name: String,
        mut total: String,
        mut threshold: String,
        mut focus: MultisigConfigField,
    ) -> Screen {
        let active = match focus {
            MultisigConfigField::Total => &mut total,
            MultisigConfigField::Threshold => &mut threshold,
        };
        match key.code {
            KeyCode::Esc => return self.wallet_picker_screen(),
            KeyCode::Tab => focus = focus.next(),
            KeyCode::Backspace => {
                active.pop();
            }
            KeyCode::Char(c) if c.is_ascii_digit() => active.push(c),
            KeyCode::Enter => {
                let total_n: usize = match total.trim().parse() {
                    Ok(n) if (2..=15).contains(&n) => n,
                    _ => {
                        self.status = Status::Error("total signers must be a number from 2 to 15".to_string());
                        return Screen::MultisigConfig { purpose, name, total, threshold, focus };
                    }
                };
                let threshold_m: usize = match threshold.trim().parse() {
                    Ok(m) if m >= 1 && m <= total_n => m,
                    _ => {
                        self.status =
                            Status::Error(format!("threshold must be a number from 1 to {total_n}"));
                        return Screen::MultisigConfig { purpose, name, total, threshold, focus };
                    }
                };
                return Screen::MultisigCosigners {
                    purpose,
                    name,
                    total: total_n,
                    threshold: threshold_m,
                    cosigners: Vec::new(),
                    current: String::new(),
                    error: None,
                };
            }
            _ => {}
        }
        Screen::MultisigConfig { purpose, name, total, threshold, focus }
    }

    fn handle_multisig_cosigners_key(
        &mut self,
        key: KeyEvent,
        purpose: NamePurpose,
        name: String,
        total: usize,
        threshold: usize,
        mut cosigners: Vec<String>,
        mut current: String,
        mut error: Option<String>,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return self.wallet_picker_screen(),
            KeyCode::Backspace => {
                current.pop();
            }
            KeyCode::Char(c) => current.push(c),
            KeyCode::Enter => {
                error = None;
                let candidate = current.trim().to_string();
                if let Err(e) = validate_cosigner_fragment(&candidate, self.network) {
                    error = Some(e);
                    return Screen::MultisigCosigners { purpose, name, total, threshold, cosigners, current, error };
                }
                cosigners.push(candidate);
                current = String::new();
                if cosigners.len() == total - 1 {
                    return Screen::SetPassword(SetPasswordForm {
                        name,
                        purpose,
                        script_kind: ScriptKind::Multisig,
                        multisig: Some(MultisigParams { threshold, cosigners }),
                        password: String::new(),
                        confirm: String::new(),
                        focus: PasswordField::default(),
                    });
                }
            }
            _ => {}
        }
        Screen::MultisigCosigners { purpose, name, total, threshold, cosigners, current, error }
    }

    fn handle_set_password_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: SetPasswordForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return self.wallet_picker_screen(),
            KeyCode::Tab => form.focus = form.focus.next(),
            KeyCode::Backspace => {
                form.active_field_mut().pop();
            }
            KeyCode::Char(c) => form.active_field_mut().push(c),
            KeyCode::Enter => {
                if form.password.is_empty() {
                    self.status = Status::Error("password cannot be empty".to_string());
                    return Screen::SetPassword(form);
                }
                if form.password != form.confirm {
                    self.status = Status::Error("passwords don't match".to_string());
                    return Screen::SetPassword(form);
                }
                match form.purpose {
                    NamePurpose::Create => {
                        self.status = Status::Working("Creating wallet...".to_string());
                        let _ = terminal.draw(|f| ui::render(f, self));
                        match self.do_create_named(&form.name, &form.password, form.script_kind, form.multisig.clone()) {
                            Ok(mnemonic) => return Screen::MnemonicReveal(mnemonic),
                            Err(e) => {
                                self.status = Status::Error(format!("{e:#}"));
                                return Screen::SetPassword(form);
                            }
                        }
                    }
                    NamePurpose::Restore => {
                        return Screen::Restore(RestoreForm {
                            name: form.name,
                            password: form.password,
                            script_kind: form.script_kind,
                            multisig: form.multisig,
                            ..Default::default()
                        })
                    }
                }
            }
            _ => {}
        }
        Screen::SetPassword(form)
    }

    fn handle_restore_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: RestoreForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return self.wallet_picker_screen(),
            KeyCode::Tab => form.focus = form.focus.next(),
            KeyCode::Backspace => {
                form.active_field_mut().pop();
            }
            KeyCode::Char(c) => form.active_field_mut().push(c),
            KeyCode::Enter => {
                let passphrase = (!form.passphrase.is_empty()).then(|| form.passphrase.clone());
                self.status = Status::Working("Restoring wallet...".to_string());
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_restore_named(
                    &form.name,
                    &form.mnemonic,
                    passphrase,
                    &form.password,
                    form.script_kind,
                    form.multisig.clone(),
                ) {
                    Ok(()) => return Screen::Dashboard,
                    Err(e) => self.status = Status::Error(format!("{e:#}")),
                }
            }
            _ => {}
        }
        Screen::Restore(form)
    }

    fn handle_dashboard_key(&mut self, terminal: &mut DefaultTerminal, key: KeyEvent) -> Screen {
        // Cleared on every keypress so a stale value can't be clicked after moving on to some
        // unrelated action; whichever branch below produces a fresh copyable value sets it again.
        self.last_copyable = None;
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('w') => return self.wallet_picker_screen(),
            KeyCode::Char('a') => match self.do_address() {
                Ok(addr) => {
                    self.status = Status::Info(format!("Address: {addr}"));
                    self.last_copyable = Some(addr.to_string());
                }
                Err(e) => self.status = Status::Error(format!("{e:#}")),
            },
            KeyCode::Char('s') => {
                self.status = Status::Working("Syncing...".to_string());
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_sync(terminal) {
                    Ok(report) => {
                        self.status = Status::Info(format!(
                            "Connected {} block(s); tip height {}",
                            report.blocks_connected, report.tip_height
                        ))
                    }
                    Err(e) => self.status = Status::Error(format!("{e:#}")),
                }
            }
            KeyCode::Char('n') => return Screen::Send(SendForm::default()),
            KeyCode::Char('u') => {
                if let Some(session) = &self.wallet {
                    let coins: Vec<LocalOutput> = session.wallet.list_unspent().collect();
                    let selected = vec![false; coins.len()];
                    return Screen::CoinPicker { coins, selected, cursor: 0 };
                }
            }
            KeyCode::Char('b') => match self.selected_unconfirmed_txid() {
                Ok(txid) => {
                    let old_fee_rate_sat_vb = self
                        .wallet
                        .as_ref()
                        .and_then(|session| {
                            let tx = session.wallet.get_tx(txid)?;
                            let rate = session.wallet.calculate_fee_rate(&tx.tx_node.tx).ok()?;
                            Some(bdk_wallet::floating_rate!(rate))
                        })
                        .unwrap_or(0.0);
                    return Screen::BumpFee(BumpFeeForm {
                        txid,
                        old_fee_rate_sat_vb,
                        fee_rate: String::new(),
                        password: String::new(),
                        focus: BumpFeeField::FeeRate,
                        error: None,
                    });
                }
                Err(e) => self.status = Status::Error(e),
            },
            KeyCode::Char('e') => {
                return Screen::ExportPsbt(ExportPsbtForm {
                    path: self.default_new_psbt_path("unsigned"),
                    ..Default::default()
                })
            }
            KeyCode::Char('i') => {
                return Screen::ImportSignPsbt(ImportSignForm {
                    in_path: self.default_in_psbt_path(),
                    out_path: self.default_new_psbt_path("signed"),
                    ..Default::default()
                })
            }
            KeyCode::Char('p') => {
                return Screen::ImportBroadcastPsbt(ImportBroadcastForm {
                    path: self.default_in_psbt_path(),
                    ..Default::default()
                })
            }
            KeyCode::Char('m') => {
                return Screen::Mine(MineForm {
                    blocks: "1".to_string(),
                })
            }
            KeyCode::Char('k') => return Screen::ExportMultisigKey(ExportMultisigKeyForm::default()),
            KeyCode::Char('c') => {
                return Screen::MultisigSign(MultisigSignForm {
                    in_path: self.default_in_psbt_path(),
                    out_path: self.default_new_psbt_path("signed"),
                    ..Default::default()
                })
            }
            KeyCode::Down => {
                if let Some(session) = &mut self.wallet {
                    session.select_next();
                }
            }
            KeyCode::Up => {
                if let Some(session) = &mut self.wallet {
                    session.select_prev();
                }
            }
            _ => {}
        }
        Screen::Dashboard
    }

    fn handle_coin_picker_key(
        &mut self,
        key: KeyEvent,
        coins: Vec<LocalOutput>,
        mut selected: Vec<bool>,
        mut cursor: usize,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return Screen::Dashboard,
            KeyCode::Up => cursor = cursor.saturating_sub(1),
            KeyCode::Down => {
                if cursor + 1 < coins.len() {
                    cursor += 1;
                }
            }
            KeyCode::Char(' ') => {
                if let Some(slot) = selected.get_mut(cursor) {
                    *slot = !*slot;
                }
            }
            KeyCode::Char('s') => {
                let chosen: Vec<OutPoint> = coins
                    .iter()
                    .zip(&selected)
                    .filter(|&(_, &is_selected)| is_selected)
                    .map(|(c, _)| c.outpoint)
                    .collect();
                return Screen::Send(SendForm {
                    coins: chosen,
                    ..Default::default()
                });
            }
            _ => {}
        }
        Screen::CoinPicker { coins, selected, cursor }
    }

    /// The txid under the History panel's cursor, if any and if it's still unconfirmed (only
    /// unconfirmed transactions can be fee-bumped -- `bdk_wallet` would reject a confirmed one
    /// anyway, but failing here gives a clearer message than propagating its error).
    fn selected_unconfirmed_txid(&self) -> Result<Txid, String> {
        let session = self.wallet.as_ref().ok_or("no wallet loaded")?;
        let index = session.history_state.selected().ok_or("select a transaction in History first")?;
        let entry = session
            .history_cache
            .get(index)
            .ok_or("select a transaction in History first")?;
        match entry.status {
            TxStatus::Unconfirmed => Ok(entry.txid),
            TxStatus::Confirmed { .. } => Err("that transaction is already confirmed -- can't bump its fee".to_string()),
        }
    }

    fn handle_bump_fee_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: BumpFeeForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return Screen::Dashboard,
            KeyCode::Tab => form.focus = form.focus.next(),
            KeyCode::Backspace => {
                form.active_field_mut().pop();
            }
            KeyCode::Char(c) => form.active_field_mut().push(c),
            KeyCode::Enter => {
                form.error = None;
                let fee_rate: f64 = match form.fee_rate.trim().parse() {
                    Ok(v) => v,
                    Err(_) => {
                        form.error = Some("fee rate must be a number".to_string());
                        return Screen::BumpFee(form);
                    }
                };
                let password = (!form.password.is_empty()).then(|| form.password.clone());
                self.status = Status::Working("Building and broadcasting bumped transaction...".to_string());
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_bump_fee(form.txid, fee_rate, password) {
                    Ok(report) => {
                        self.status = Status::Info(format!(
                            "Replacement broadcast {} -- fee {} ({:.2} sat/vB)",
                            report.txid, report.fee, report.fee_rate_sat_vb
                        ));
                        return Screen::Dashboard;
                    }
                    Err(e) => form.error = Some(format!("{e:#}")),
                }
            }
            _ => {}
        }
        Screen::BumpFee(form)
    }

    fn handle_export_psbt_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: ExportPsbtForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return Screen::Dashboard,
            KeyCode::Tab => form.focus = form.focus.next(),
            KeyCode::BackTab => form.focus = form.focus.prev(),
            KeyCode::Backspace => {
                form.active_field_mut().pop();
            }
            KeyCode::Char(c) => form.active_field_mut().push(c),
            KeyCode::Enter => {
                form.error = None;
                let sats: u64 = match form.sats.trim().parse() {
                    Ok(v) => v,
                    Err(_) => {
                        form.error = Some("amount must be a whole number of satoshis".to_string());
                        return Screen::ExportPsbt(form);
                    }
                };
                let fee_rate_override: Option<f64> = if form.fee_rate.trim().is_empty() {
                    None
                } else {
                    match form.fee_rate.trim().parse() {
                        Ok(v) => Some(v),
                        Err(_) => {
                            form.error = Some("fee rate must be a number".to_string());
                            return Screen::ExportPsbt(form);
                        }
                    }
                };
                self.status = Status::Working("Building unsigned PSBT...".to_string());
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_export_psbt(&form.to, sats, fee_rate_override, &form.path) {
                    Ok(resolved) => {
                        self.status = Status::Info(format!("Unsigned PSBT written to {}", resolved.display()));
                        return Screen::Dashboard;
                    }
                    Err(e) => form.error = Some(format!("{e:#}")),
                }
            }
            _ => {}
        }
        Screen::ExportPsbt(form)
    }

    fn handle_import_sign_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: ImportSignForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return Screen::Dashboard,
            KeyCode::Tab => form.focus = form.focus.next(),
            KeyCode::Backspace => {
                form.active_field_mut().pop();
            }
            KeyCode::Char(c) => form.active_field_mut().push(c),
            KeyCode::Enter => {
                form.error = None;
                let password = (!form.password.is_empty()).then(|| form.password.clone());
                self.status = Status::Working("Signing PSBT...".to_string());
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_import_sign_psbt(&form.in_path, &form.out_path, password) {
                    Ok((finalized, resolved_out)) => {
                        self.status = Status::Info(format!(
                            "{} PSBT written to {}",
                            if finalized { "Signed, finalized" } else { "Partially signed" },
                            resolved_out.display()
                        ));
                        return Screen::Dashboard;
                    }
                    Err(e) => form.error = Some(format!("{e:#}")),
                }
            }
            _ => {}
        }
        Screen::ImportSignPsbt(form)
    }

    fn handle_multisig_sign_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: MultisigSignForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return Screen::Dashboard,
            KeyCode::Tab => form.focus = form.focus.next(),
            KeyCode::Backspace => {
                form.active_field_mut().pop();
            }
            KeyCode::Char(c) => form.active_field_mut().push(c),
            KeyCode::Enter => {
                form.error = None;
                let password = (!form.password.is_empty()).then(|| form.password.clone());
                self.status = Status::Working("Co-signing PSBT...".to_string());
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_multisig_sign_psbt(&form.in_path, &form.out_path, password) {
                    Ok((finalized, Some((collected, threshold, total)), resolved_out)) => {
                        self.status = Status::Info(format!(
                            "{collected} of {threshold} signatures collected (n={total}) -- {} -- written to {}",
                            if finalized { "ready to broadcast" } else { "needs more signatures" },
                            resolved_out.display()
                        ));
                        return Screen::Dashboard;
                    }
                    Ok((finalized, None, resolved_out)) => {
                        self.status = Status::Info(format!(
                            "{} PSBT written to {} (not a multisig wallet)",
                            if finalized { "Signed, finalized" } else { "Partially signed" },
                            resolved_out.display()
                        ));
                        return Screen::Dashboard;
                    }
                    Err(e) => form.error = Some(format!("{e:#}")),
                }
            }
            _ => {}
        }
        Screen::MultisigSign(form)
    }

    fn handle_export_multisig_key_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: ExportMultisigKeyForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return Screen::Dashboard,
            KeyCode::Backspace => {
                form.password.pop();
            }
            KeyCode::Char(c) => form.password.push(c),
            KeyCode::Enter => {
                form.error = None;
                let password = (!form.password.is_empty()).then(|| form.password.clone());
                self.status = Status::Working("Deriving multisig key...".to_string());
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_export_multisig_key(password) {
                    Ok(fragment) => {
                        self.status = Status::Info(format!("My multisig key (copy to a cosigner): {fragment}"));
                        self.last_copyable = Some(fragment);
                        return Screen::Dashboard;
                    }
                    Err(e) => form.error = Some(format!("{e:#}")),
                }
            }
            _ => {}
        }
        Screen::ExportMultisigKey(form)
    }

    fn handle_import_broadcast_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: ImportBroadcastForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return Screen::Dashboard,
            KeyCode::Backspace => {
                form.path.pop();
            }
            KeyCode::Char(c) => form.path.push(c),
            KeyCode::Enter => {
                form.error = None;
                self.status = Status::Working("Broadcasting signed PSBT...".to_string());
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_import_broadcast_psbt(&form.path) {
                    Ok(report) => {
                        self.status = Status::Info(format!(
                            "Broadcast {} -- fee {} ({:.2} sat/vB)",
                            report.txid, report.fee, report.fee_rate_sat_vb
                        ));
                        return Screen::Dashboard;
                    }
                    Err(e) => form.error = Some(format!("{e:#}")),
                }
            }
            _ => {}
        }
        Screen::ImportBroadcastPsbt(form)
    }

    fn handle_send_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: SendForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return Screen::Dashboard,
            KeyCode::Tab => form.focus = form.focus.next(),
            KeyCode::BackTab => form.focus = form.focus.prev(),
            KeyCode::Backspace => {
                form.active_field_mut().pop();
            }
            KeyCode::Char(c) => form.active_field_mut().push(c),
            KeyCode::Enter => {
                form.error = None;
                let sats: u64 = match form.sats.trim().parse() {
                    Ok(v) => v,
                    Err(_) => {
                        form.error = Some("amount must be a whole number of satoshis".to_string());
                        return Screen::Send(form);
                    }
                };
                let fee_rate_override: Option<f64> = if form.fee_rate.trim().is_empty() {
                    None
                } else {
                    match form.fee_rate.trim().parse() {
                        Ok(v) => Some(v),
                        Err(_) => {
                            form.error = Some("fee rate must be a number".to_string());
                            return Screen::Send(form);
                        }
                    }
                };
                let to = form.to.trim().to_string();
                let password = (!form.password.is_empty()).then(|| form.password.clone());
                self.status = Status::Working("Building and broadcasting transaction...".to_string());
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_send(&to, sats, fee_rate_override, password, &form.coins) {
                    Ok(report) => {
                        self.status = Status::Info(format!(
                            "Broadcast {} -- fee {} ({:.2} sat/vB)",
                            report.txid, report.fee, report.fee_rate_sat_vb
                        ));
                        return Screen::Dashboard;
                    }
                    Err(e) => form.error = Some(format!("{e:#}")),
                }
            }
            _ => {}
        }
        Screen::Send(form)
    }

    fn handle_mine_key(
        &mut self,
        terminal: &mut DefaultTerminal,
        key: KeyEvent,
        mut form: MineForm,
    ) -> Screen {
        match key.code {
            KeyCode::Esc => return Screen::Dashboard,
            KeyCode::Backspace => {
                form.blocks.pop();
            }
            KeyCode::Char(c) if c.is_ascii_digit() => form.blocks.push(c),
            KeyCode::Enter => {
                let n: u64 = form.blocks.trim().parse().unwrap_or(1).max(1);
                self.status = Status::Working(format!("Mining {n} block(s)..."));
                let _ = terminal.draw(|f| ui::render(f, self));
                match self.do_mine(n) {
                    Ok(()) => self.status = Status::Info(format!("Mined {n} block(s)")),
                    Err(e) => self.status = Status::Error(format!("{e:#}")),
                }
                return Screen::Dashboard;
            }
            _ => {}
        }
        Screen::Mine(form)
    }

    /// Permanently delete `name`'s files from disk (see `WalletPaths::delete`). If it's the
    /// currently-loaded wallet, unload it first so the app isn't left holding an open sqlite
    /// connection to a file that no longer exists.
    fn do_delete_named(&mut self, name: &str) -> Result<()> {
        let paths = WalletPaths::named(self.data_dir.clone(), self.network, name)?;
        if self.wallet.as_ref().is_some_and(|s| s.name == name) {
            self.wallet = None;
        }
        paths.delete()
    }

    fn do_create_named(
        &mut self,
        name: &str,
        password: &str,
        script_kind: ScriptKind,
        multisig: Option<MultisigParams>,
    ) -> Result<String> {
        let paths = WalletPaths::named(self.data_dir.clone(), self.network, name)?;
        let seed = Seed::generate(WordCount::Words12, None)?;
        let (mut wallet, mut conn) = match multisig {
            Some(params) => walletdb::create_multisig(
                &paths,
                self.network,
                &seed,
                password,
                params.threshold,
                &params.cosigners,
            )?,
            None => walletdb::create(&paths, self.network, &seed, password, script_kind)?,
        };
        let addr = wallet.reveal_next_address(KeychainKind::External);
        wallet.persist(&mut conn)?;
        let mnemonic = seed.mnemonic.to_string();
        let mut session = WalletSession::new(name.to_string(), paths, wallet, conn);
        session.unlocked_seed = Some(seed);
        self.wallet = Some(session);
        self.status = Status::Info(format!("Wallet '{name}' created. First address: {}", addr.address));
        Ok(mnemonic)
    }

    fn do_restore_named(
        &mut self,
        name: &str,
        mnemonic_words: &str,
        passphrase: Option<String>,
        password: &str,
        script_kind: ScriptKind,
        multisig: Option<MultisigParams>,
    ) -> Result<()> {
        let paths = WalletPaths::named(self.data_dir.clone(), self.network, name)?;
        let seed = Seed::parse(mnemonic_words, passphrase)?;
        let (mut wallet, mut conn) = match multisig {
            Some(params) => walletdb::create_multisig(
                &paths,
                self.network,
                &seed,
                password,
                params.threshold,
                &params.cosigners,
            )?,
            None => walletdb::create(&paths, self.network, &seed, password, script_kind)?,
        };
        let addr = wallet.reveal_next_address(KeychainKind::External);
        wallet.persist(&mut conn)?;
        let mut session = WalletSession::new(name.to_string(), paths, wallet, conn);
        session.unlocked_seed = Some(seed);
        self.wallet = Some(session);
        self.status = Status::Info(format!(
            "Wallet '{name}' restored. First address: {}. Press 's' to sync and discover funds.",
            addr.address
        ));
        Ok(())
    }

    /// Load `name` and immediately sync it, so switching wallets always shows fresh state
    /// without a separate manual `s`. A load failure is a hard error (propagated); a sync
    /// failure afterward is not -- the wallet is still usable, just possibly stale, and that's
    /// reflected in the status message rather than blocking the switch.
    fn do_load_named(&mut self, terminal: &mut DefaultTerminal, name: &str) -> Result<()> {
        let paths = WalletPaths::named(self.data_dir.clone(), self.network, name)?;
        let (wallet, conn) = walletdb::load(&paths, self.network)?;
        self.wallet = Some(WalletSession::new(name.to_string(), paths, wallet, conn));
        match self.do_sync(terminal) {
            Ok(report) => {
                self.status = Status::Info(format!(
                    "Loaded wallet '{name}'. Connected {} block(s); tip height {}",
                    report.blocks_connected, report.tip_height
                ));
            }
            Err(e) => {
                self.status = Status::Error(format!("Loaded wallet '{name}', but sync failed: {e:#}"));
            }
        }
        Ok(())
    }

    /// A fresh auto-generated PSBT path inside the current wallet's own directory, for
    /// pre-filling a "write to" field so the common case needs no typing at all. Empty string
    /// (falls back to requiring manual entry) if no wallet is loaded or the directory couldn't
    /// be created -- never a hard error just for populating a default.
    fn default_new_psbt_path(&self, prefix: &str) -> String {
        self.wallet
            .as_ref()
            .and_then(|s| s.paths.new_psbt_path(prefix).ok())
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    /// The last PSBT path this session touched, for pre-filling a "read from" field -- chains
    /// export's output into sign's input, and one signer's output into the next signer's input
    /// or the final broadcast, without retyping a path by hand at each step.
    fn default_in_psbt_path(&self) -> String {
        self.wallet
            .as_ref()
            .and_then(|s| s.last_psbt_path.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    fn do_address(&mut self) -> Result<Address> {
        let session = self.wallet.as_mut().context("no wallet loaded")?;
        let addr = session.wallet.next_unused_address(KeychainKind::External);
        session.wallet.persist(&mut session.conn)?;
        Ok(addr.address)
    }

    fn do_sync(&mut self, terminal: &mut DefaultTerminal) -> Result<SyncReport> {
        let backend = self.backend_cfg.client()?;
        let wallet_name = self.wallet.as_ref().context("no wallet loaded")?.name.clone();
        let network = self.network;
        let session = self.wallet.as_mut().context("no wallet loaded")?;

        // Redrawing on every single progress call (potentially one per scanned script pubkey)
        // would make a large scan slower, not just noisier -- so this throttles to at most one
        // redraw per ~150ms, which still reads as "live" to a human but doesn't thrash the
        // terminal. The closure only captures owned/Copy values plus `terminal`, never `self`,
        // since `session` above already holds `self.wallet` mutably borrowed.
        let mut last_drawn = std::time::Instant::now() - std::time::Duration::from_secs(1);
        let report = sync::sync(&mut session.wallet, &mut session.conn, &backend, |message| {
            if last_drawn.elapsed() >= std::time::Duration::from_millis(150) {
                let _ = terminal.draw(|f| ui::render_progress(f, &wallet_name, network, message));
                last_drawn = std::time::Instant::now();
            }
        })?;
        session.refresh_history();
        Ok(report)
    }

    fn do_send(
        &mut self,
        to: &str,
        sats: u64,
        fee_rate_override: Option<f64>,
        password: Option<String>,
        coins: &[OutPoint],
    ) -> Result<SendReport> {
        let session = self.wallet.as_ref().context("no wallet loaded")?;
        let seed = match &session.unlocked_seed {
            Some(cached) => cached.clone(),
            None => {
                let password = password.context("this wallet is locked -- enter its password to send")?;
                Seed::load(&session.paths.seed_path, &password)?
            }
        };
        if let Some(session) = self.wallet.as_mut() {
            session.unlocked_seed = Some(seed.clone());
        }
        let backend = self.backend_cfg.client()?;
        let address = Address::from_str(to)
            .context("invalid address")?
            .require_network(self.network)
            .context("address does not match network")?;
        let amount = Amount::from_sat(sats);
        let fee_rate = resolve_fee_rate(&backend, fee_rate_override)?;
        let network = self.network;
        let session = self.wallet.as_mut().context("no wallet loaded")?;
        let report = send::send(
            &mut session.wallet,
            &mut session.conn,
            &backend,
            &seed,
            network,
            &address,
            amount,
            fee_rate,
            coins,
        )?;
        session.refresh_history();
        Ok(report)
    }

    fn do_bump_fee(&mut self, txid: Txid, fee_rate_sat_vb: f64, password: Option<String>) -> Result<SendReport> {
        let session = self.wallet.as_ref().context("no wallet loaded")?;
        let seed = match &session.unlocked_seed {
            Some(cached) => cached.clone(),
            None => {
                let password = password.context("this wallet is locked -- enter its password to send")?;
                Seed::load(&session.paths.seed_path, &password)?
            }
        };
        if let Some(session) = self.wallet.as_mut() {
            session.unlocked_seed = Some(seed.clone());
        }
        let backend = self.backend_cfg.client()?;
        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate_sat_vb.ceil() as u64).context("fee rate too high")?;
        let network = self.network;
        let session = self.wallet.as_mut().context("no wallet loaded")?;
        let report = send::bump_fee(&mut session.wallet, &mut session.conn, &backend, &seed, network, txid, fee_rate)?;
        session.refresh_history();
        Ok(report)
    }

    /// Returns the actual (normalized) path written to, so the caller can show the user exactly
    /// where the file landed rather than echoing back whatever they typed verbatim.
    fn do_export_psbt(&mut self, to: &str, sats: u64, fee_rate_override: Option<f64>, path: &str) -> Result<PathBuf> {
        let backend = self.backend_cfg.client()?;
        let address = Address::from_str(to)
            .context("invalid address")?
            .require_network(self.network)
            .context("address does not match network")?;
        let amount = Amount::from_sat(sats);
        let fee_rate = resolve_fee_rate(&backend, fee_rate_override)?;
        let session = self.wallet.as_mut().context("no wallet loaded")?;
        let psbt = send::build_unsigned(&mut session.wallet, &address, amount, fee_rate, &[])?;
        let resolved = normalize_path(path);
        std::fs::write(&resolved, psbt.to_string())
            .with_context(|| format!("writing PSBT file to {}", resolved.display()))?;
        session.last_psbt_path = Some(resolved.clone());
        Ok(resolved)
    }

    /// Returns whether the PSBT finalized (always true for a correctly password-unlocked
    /// single-sig wallet; see [`send::sign_psbt`]) and the actual (normalized) output path.
    fn do_import_sign_psbt(&mut self, in_path: &str, out_path: &str, password: Option<String>) -> Result<(bool, PathBuf)> {
        let resolved_in = normalize_path(in_path);
        let text = std::fs::read_to_string(&resolved_in)
            .with_context(|| format!("reading PSBT file at {}", resolved_in.display()))?;
        let psbt: Psbt = text.trim().parse().context("parsing PSBT")?;

        let session = self.wallet.as_ref().context("no wallet loaded")?;
        let seed = match &session.unlocked_seed {
            Some(cached) => cached.clone(),
            None => {
                let password = password.context("this wallet is locked -- enter its password to sign")?;
                Seed::load(&session.paths.seed_path, &password)?
            }
        };
        if let Some(session) = self.wallet.as_mut() {
            session.unlocked_seed = Some(seed.clone());
        }

        let network = self.network;
        let session = self.wallet.as_mut().context("no wallet loaded")?;
        let (signed_psbt, finalized) = send::sign_psbt(&session.wallet, &seed, network, psbt)?;
        let resolved_out = normalize_path(out_path);
        std::fs::write(&resolved_out, signed_psbt.to_string())
            .with_context(|| format!("writing signed PSBT file to {}", resolved_out.display()))?;
        session.last_psbt_path = Some(resolved_out.clone());
        Ok((finalized, resolved_out))
    }

    /// Same as [`do_import_sign_psbt`](Self::do_import_sign_psbt), but also reports how many of
    /// the wallet's threshold signatures are present afterward, for multisig wallets. The count
    /// comes from the first input's `partial_sigs` -- representative since this wallet's own
    /// UTXOs all share the same cosigner set.
    fn do_multisig_sign_psbt(
        &mut self,
        in_path: &str,
        out_path: &str,
        password: Option<String>,
    ) -> Result<(bool, Option<(usize, usize, usize)>, PathBuf)> {
        let resolved_in = normalize_path(in_path);
        let text = std::fs::read_to_string(&resolved_in)
            .with_context(|| format!("reading PSBT file at {}", resolved_in.display()))?;
        let psbt: Psbt = text.trim().parse().context("parsing PSBT")?;

        let session = self.wallet.as_ref().context("no wallet loaded")?;
        let seed = match &session.unlocked_seed {
            Some(cached) => cached.clone(),
            None => {
                let password = password.context("this wallet is locked -- enter its password to sign")?;
                Seed::load(&session.paths.seed_path, &password)?
            }
        };
        if let Some(session) = self.wallet.as_mut() {
            session.unlocked_seed = Some(seed.clone());
        }

        let network = self.network;
        let session = self.wallet.as_mut().context("no wallet loaded")?;
        let tally = rfb_wallet::seed::multisig_threshold(&session.wallet);
        let (signed_psbt, finalized) = send::sign_psbt(&session.wallet, &seed, network, psbt)?;
        let collected = tally.map(|(threshold, total)| {
            let n = signed_psbt.inputs.first().map(|i| i.partial_sigs.len()).unwrap_or(0);
            (n, threshold, total)
        });
        let resolved_out = normalize_path(out_path);
        std::fs::write(&resolved_out, signed_psbt.to_string())
            .with_context(|| format!("writing signed PSBT file to {}", resolved_out.display()))?;
        session.last_psbt_path = Some(resolved_out.clone());
        Ok((finalized, collected, resolved_out))
    }

    fn do_export_multisig_key(&mut self, password: Option<String>) -> Result<String> {
        let session = self.wallet.as_ref().context("no wallet loaded")?;
        let seed = match &session.unlocked_seed {
            Some(cached) => cached.clone(),
            None => {
                let password = password.context("this wallet is locked -- enter its password to export")?;
                Seed::load(&session.paths.seed_path, &password)?
            }
        };
        if let Some(session) = self.wallet.as_mut() {
            session.unlocked_seed = Some(seed.clone());
        }
        seed.multisig_xpub_fragment(self.network)
    }

    fn do_import_broadcast_psbt(&mut self, path: &str) -> Result<SendReport> {
        let resolved = normalize_path(path);
        let text = std::fs::read_to_string(&resolved)
            .with_context(|| format!("reading PSBT file at {}", resolved.display()))?;
        let psbt: Psbt = text.trim().parse().context("parsing PSBT")?;
        let backend = self.backend_cfg.client()?;
        let session = self.wallet.as_mut().context("no wallet loaded")?;
        let report = send::broadcast_psbt(&mut session.wallet, &mut session.conn, &backend, psbt)?;
        session.refresh_history();
        Ok(report)
    }

    fn do_mine(&mut self, blocks: u64) -> Result<()> {
        anyhow::ensure!(self.network == Network::Regtest, "mine only works on --network regtest");
        let addr = self.do_address()?;
        let backend = self.backend_cfg.client()?;
        let rpc = backend
            .as_bitcoind_rpc()
            .context("mine only works with the bitcoind RPC backend, not Esplora")?;
        rpc.generate_to_address(blocks, &addr)
            .context("generatetoaddress failed")?;
        Ok(())
    }
}

fn handle_mnemonic_reveal_key(key: KeyEvent, mnemonic: String) -> Screen {
    match key.code {
        KeyCode::Enter => Screen::Dashboard,
        _ => Screen::MnemonicReveal(mnemonic),
    }
}

/// Writes `text` to the system clipboard via the OSC 52 terminal escape sequence -- the
/// standard way a TUI (no GUI toolkit, no OS clipboard API available) asks the *terminal
/// emulator itself* to set the clipboard. Supported by most modern terminals (Warp, iTerm2,
/// Kitty, WezTerm, Alacritty); a terminal that doesn't understand it just ignores the sequence,
/// so this never risks corrupting the display even where it's a no-op.
fn copy_to_clipboard(text: &str) {
    use base64::Engine as _;
    use std::io::Write as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let _ = write!(std::io::stdout(), "\x1b]52;c;{encoded}\x07");
    let _ = std::io::stdout().flush();
}

fn resolve_fee_rate(backend: &Backend, override_sat_vb: Option<f64>) -> Result<FeeRate> {
    if let Some(rate) = override_sat_vb {
        return FeeRate::from_sat_per_vb(rate.ceil() as u64).context("fee rate too high");
    }
    Ok(backend
        .estimate_fee_rate(6)
        .unwrap_or(None)
        .unwrap_or(FeeRate::BROADCAST_MIN))
}

/// Turn whatever a human typed into a path field into something the filesystem will actually
/// recognize: trims surrounding whitespace (an invisible leading space from a copy-paste reads
/// as a completely different, nonexistent relative path) and expands a leading `~` to the home
/// directory (shells do this automatically; raw keystrokes typed into this TUI's own text fields
/// never go through a shell, so without this `~/foo` is read literally as a folder named `~`).
fn normalize_path(input: &str) -> PathBuf {
    let trimmed = input.trim();
    match trimmed.strip_prefix('~') {
        Some(rest) if rest.is_empty() => dirs::home_dir().unwrap_or_else(|| PathBuf::from(trimmed)),
        Some(rest) if rest.starts_with('/') => dirs::home_dir()
            .map(|home| home.join(rest.trim_start_matches('/')))
            .unwrap_or_else(|| PathBuf::from(trimmed)),
        _ => PathBuf::from(trimmed),
    }
}

/// Validate a pasted-in cosigner key fragment (`[fingerprint/path]xpub...`) the same way it'll
/// actually be used -- by parsing it inside a throwaway single-key `sortedmulti`. This guarantees
/// "if it was accepted here, it will also parse when the real multisig descriptor is built."
fn validate_cosigner_fragment(candidate: &str, network: Network) -> std::result::Result<(), String> {
    use bdk_wallet::bitcoin::NetworkKind;
    use bdk_wallet::descriptor::IntoWalletDescriptor;
    use bitcoin::secp256k1::Secp256k1;

    if candidate.is_empty() {
        return Err("cosigner key cannot be empty".to_string());
    }
    let probe = format!("wsh(sortedmulti(1,{candidate}/0/*))");
    let secp = Secp256k1::new();
    probe
        .into_wallet_descriptor(&secp, NetworkKind::from(network))
        .map(|_| ())
        .map_err(|e| format!("not a valid cosigner key: {e}"))
}
