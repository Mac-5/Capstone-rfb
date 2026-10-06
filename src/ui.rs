use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState, Padding, Paragraph, Wrap};
use ratatui::Frame;
use bdk_wallet::bitcoin::Amount;
use bdk_wallet::LocalOutput;

use crate::app::{
    App, BumpFeeField, BumpFeeForm, ExportMultisigKeyForm, ExportPsbtField, ExportPsbtForm, ImportBroadcastForm,
    ImportSignField, ImportSignForm, MineForm, MultisigConfigField, MultisigSignField, MultisigSignForm,
    NamePurpose, PasswordField, RestoreField, RestoreForm, Screen, SendField, SendForm, SetPasswordForm, Status,
};
use rfb_wallet::history::TxStatus;
use rfb_wallet::seed::ScriptKind;

// Shared palette -- kept to five colors with a consistent meaning everywhere they appear, rather
// than picking colors ad hoc per screen: accent = focus/emphasis, muted = secondary/de-emphasized
// (hints, unfocused borders), positive/warning/danger = the same traffic-light vocabulary
// `status_line` already uses, now reused for borders and list items too.
const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;
const POSITIVE: Color = Color::Green;
const WARNING: Color = Color::Yellow;
const DANGER: Color = Color::Red;

/// Render a password field's contents masked, so a shoulder-surfer (or a screen recording)
/// doesn't see what was typed -- length is still visible, which is an acceptable trade-off here.
fn mask(s: &str) -> String {
    "*".repeat(s.chars().count())
}

/// The standard block every screen builds on: rounded corners and a little horizontal breathing
/// room so text doesn't sit flush against the border (there's no room to spare for *vertical*
/// padding too -- a lot of these are exactly 3 rows tall, sized for one line of content between
/// top and bottom borders), plus a bold title. Chain `.border_style(...)` on top for focus/status
/// coloring.
fn block(title: impl Into<String>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .padding(Padding::horizontal(1))
        .title(title.into())
        .title_style(Style::default().add_modifier(Modifier::BOLD))
}

/// Dim, secondary-info styling for the one-line key-binding hint at the bottom of every screen --
/// de-emphasized relative to the screen's actual content.
fn hint(text: impl Into<String>) -> Paragraph<'static> {
    // Split on explicit newlines into separate `Line`s ourselves -- wrapping the whole string in
    // one `Span` (as an earlier version of this did) silently drops embedded `\n`s instead of
    // breaking the line, since a `Span` is inherently single-line; multi-line hints (the
    // dashboard's two-row key list) would collapse onto one row and run together.
    let lines: Vec<Line<'static>> = text
        .into()
        .lines()
        .map(|line| Line::from(Span::styled(line.to_string(), Style::default().fg(MUTED))))
        .collect();
    Paragraph::new(lines)
}

/// Shared list-selection highlight: a solid accent-colored bar rather than raw reverse-video,
/// which stays legible and consistent regardless of the user's terminal color scheme.
fn highlight_style() -> Style {
    Style::default().bg(ACCENT).fg(Color::Black).add_modifier(Modifier::BOLD)
}

/// Border color for a boxed status line, matching `status_line`'s own text color -- the box
/// itself telegraphs idle/working/success/error at a glance, not just the text inside it.
fn status_border_style(app: &App) -> Style {
    match &app.status {
        Status::Idle => Style::default().fg(MUTED),
        Status::Working(_) => Style::default().fg(WARNING),
        Status::Info(_) => Style::default().fg(POSITIVE),
        Status::Error(_) => Style::default().fg(DANGER),
    }
}

/// Caps content width and centers it, instead of every box stretching edge-to-edge on a wide
/// monitor -- a terminal that's 300 columns wide shouldn't mean a one-line text field is also
/// 300 columns wide. Only engages when the real terminal is actually wider than the cap; a
/// narrow terminal gets its full width exactly as before. Height is left untouched (capping it
/// too would waste vertical space most screens, especially lists, actually need).
fn content_area(frame: &Frame) -> Rect {
    let area = frame.area();
    const MAX_WIDTH: u16 = 140;
    let width = area.width.min(MAX_WIDTH);
    let x = area.x + (area.width - width) / 2;
    Rect { x, y: area.y, width, height: area.height }
}

/// A heavier border for the handful of screens that deserve to visually stand out as "stop and
/// pay attention" -- currently just the one-time mnemonic reveal and the irreversible delete
/// confirmation.
fn block_emphasis(title: impl Into<String>) -> Block<'static> {
    block(title).border_type(BorderType::Thick)
}

pub fn render(frame: &mut Frame, app: &mut App) {
    // Screen is cheap to clone (small strings/forms) and cloning it here sidesteps a
    // borrow-checker fight between "match on app.screen" and "pass &mut app to a renderer".
    match app.screen.clone() {
        Screen::WalletPicker { names, selected } => render_wallet_picker(frame, app, &names, selected),
        Screen::ConfirmDeleteWallet { name, .. } => render_confirm_delete_wallet(frame, app, &name),
        Screen::MnemonicReveal(mnemonic) => render_mnemonic_reveal(frame, &mnemonic),
        Screen::NameInput { purpose, name } => render_name_input(frame, app, purpose, &name),
        Screen::ScriptTypeChoice { name, choice, .. } => render_script_type_choice(frame, app, &name, choice),
        Screen::MultisigConfig { name, total, threshold, focus, .. } => {
            render_multisig_config(frame, app, &name, &total, &threshold, focus)
        }
        Screen::MultisigCosigners { name, total, threshold, cosigners, current, error, .. } => {
            render_multisig_cosigners(frame, app, &name, total, threshold, &cosigners, &current, error.as_deref())
        }
        Screen::SetPassword(form) => render_set_password(frame, app, &form),
        Screen::Restore(form) => render_restore(frame, app, &form),
        Screen::Dashboard => render_dashboard(frame, app),
        Screen::CoinPicker { coins, selected, cursor } => {
            render_coin_picker(frame, app, &coins, &selected, cursor)
        }
        Screen::Send(form) => render_send(frame, app, &form),
        Screen::BumpFee(form) => render_bump_fee(frame, app, &form),
        Screen::ExportPsbt(form) => render_export_psbt(frame, app, &form),
        Screen::ImportSignPsbt(form) => render_import_sign(frame, app, &form),
        Screen::ImportBroadcastPsbt(form) => render_import_broadcast(frame, app, &form),
        Screen::Mine(form) => render_mine(frame, app, &form),
        Screen::ExportMultisigKey(form) => render_export_multisig_key(frame, app, &form),
        Screen::MultisigSign(form) => render_multisig_sign(frame, app, &form),
    }
}

/// Minimal standalone redraw used while a sync is in progress. Deliberately doesn't take `&mut
/// App`: the progress closure that calls this only has owned/`Copy` values pulled out ahead of
/// time (wallet name, network) plus the terminal, since `&mut App` isn't available -- the active
/// `WalletSession` is already borrowed out of it for the duration of the sync call.
pub fn render_progress(frame: &mut Frame, wallet_name: &str, network: bdk_wallet::bitcoin::Network, message: &str) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(content_area(frame));

    frame.render_widget(block(format!(" ₿ rfb_wallet -- {network:?} -- wallet '{wallet_name}' ")), outer[0]);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("… working: {message}"),
            Style::default().fg(WARNING),
        )))
        .block(block(" Status ").border_style(Style::default().fg(WARNING))),
        outer[1],
    );
}

fn status_line(app: &App) -> Line<'static> {
    match &app.status {
        Status::Idle => Line::from(""),
        Status::Working(m) => Line::from(Span::styled(format!("… working: {m}"), Style::default().fg(WARNING))),
        Status::Info(m) => Line::from(Span::styled(format!("✓ {m}"), Style::default().fg(POSITIVE))),
        Status::Error(m) => {
            Line::from(Span::styled(format!("✗ error: {m}"), Style::default().fg(DANGER)))
        }
    }
}

fn error_line(text: &str) -> Paragraph<'static> {
    Paragraph::new(Span::styled(text.to_string(), Style::default().fg(DANGER).add_modifier(Modifier::BOLD)))
}

fn field_border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(MUTED)
    }
}

fn render_wallet_picker(frame: &mut Frame, app: &App, names: &[String], selected: usize) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3), Constraint::Length(1)])
        .split(content_area(frame));

    let items: Vec<ListItem> = if names.is_empty() {
        vec![ListItem::new(Span::styled("No wallets found here yet.", Style::default().fg(MUTED)))]
    } else {
        names
            .iter()
            .map(|n| {
                let current = app.wallet.as_ref().map(|s| s.name.as_str()) == Some(n.as_str());
                let label = if current {
                    Line::from(vec![
                        Span::raw(format!("{n}  ")),
                        Span::styled("(currently loaded)", Style::default().fg(POSITIVE).add_modifier(Modifier::ITALIC)),
                    ])
                } else {
                    Line::from(n.clone())
                };
                ListItem::new(label)
            })
            .collect()
    };

    let mut state = ListState::default();
    if !names.is_empty() {
        state.select(Some(selected));
    }
    let list = List::new(items)
        .block(block(format!(" Wallets -- {:?} ", app.network)))
        .highlight_style(highlight_style());
    frame.render_stateful_widget(list, chunks[0], &mut state);

    frame.render_widget(
        Paragraph::new(status_line(app)).block(block(" Status ").border_style(status_border_style(app))),
        chunks[1],
    );

    let help = match (app.wallet.is_some(), names.is_empty()) {
        (true, false) => "Enter: load  [n] new  [r] restore  [d] delete  Esc: back  [q] quit",
        (true, true) => "Enter: load  [n] new  [r] restore  Esc: back  [q] quit",
        (false, false) => "Enter: load  [n] new  [r] restore  [d] delete  [q] quit",
        (false, true) => "Enter: load  [n] new  [r] restore  [q] quit",
    };
    frame.render_widget(hint(help), chunks[2]);
}

fn render_confirm_delete_wallet(frame: &mut Frame, app: &App, name: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3), Constraint::Length(1)])
        .split(content_area(frame));

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("Delete wallet '{name}'?"),
            Style::default().add_modifier(Modifier::BOLD).fg(DANGER),
        )),
        Line::from(""),
        Line::from("This removes its database and encrypted seed file from disk. There is no undo --"),
        Line::from("recovery is only possible if you still have its mnemonic to restore from."),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(block_emphasis(" Confirm delete ").border_style(Style::default().fg(DANGER)))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(status_line(app)).block(block(" Status ").border_style(status_border_style(app))),
        chunks[1],
    );
    frame.render_widget(hint("[y] delete permanently   [n]/Esc: cancel"), chunks[2]);
}

fn render_name_input(frame: &mut Frame, app: &App, purpose: NamePurpose, name: &str) {
    let title = match purpose {
        NamePurpose::Create => " New wallet name ",
        NamePurpose::Restore => " Name for the restored wallet ",
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(1)])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(name).block(block(title).border_style(field_border_style(true))),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(status_line(app)), chunks[1]);
    frame.render_widget(hint("Enter: continue   Esc: cancel"), chunks[2]);
}

fn render_script_type_choice(frame: &mut Frame, app: &App, name: &str, choice: ScriptKind) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3), Constraint::Length(1)])
        .split(content_area(frame));

    let option_line = |kind: ScriptKind, desc: &str| {
        let marker = if kind == choice { "(x)" } else { "( )" };
        let style = if kind == choice {
            Style::default().add_modifier(Modifier::BOLD).fg(ACCENT)
        } else {
            Style::default().fg(MUTED)
        };
        Line::from(Span::styled(format!("{marker} {}  --  {desc}", kind.label()), style))
    };

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("Script type for wallet '{name}':"),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        option_line(ScriptKind::Segwit, "addresses like bc1q...; widest wallet/exchange support"),
        option_line(ScriptKind::Taproot, "addresses like bc1p...; smaller multisig/complex-script fees"),
        option_line(ScriptKind::Multisig, "N-of-M: requires multiple signatures to spend, e.g. 2-of-3"),
        Line::from(""),
        Line::from(Span::styled(
            "This can't be changed later without restoring into a new wallet -- it picks the derivation path itself.",
            Style::default().fg(MUTED),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(block(" Script type ")).wrap(Wrap { trim: false }),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(status_line(app)), chunks[1]);
    frame.render_widget(hint("up/down: toggle   Enter: continue   Esc: cancel"), chunks[2]);
}

fn render_multisig_config(
    frame: &mut Frame,
    app: &App,
    name: &str,
    total: &str,
    threshold: &str,
    focus: MultisigConfigField,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(1), Constraint::Length(1)])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(total).block(
            block(format!(" Total cosigners for '{name}' (2-15) "))
                .border_style(field_border_style(focus == MultisigConfigField::Total)),
        ),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(threshold).block(
            block(" Signatures required to spend (threshold) ")
                .border_style(field_border_style(focus == MultisigConfigField::Threshold)),
        ),
        chunks[1],
    );
    frame.render_widget(Paragraph::new(status_line(app)), chunks[2]);
    frame.render_widget(hint("Tab: switch field   Enter: continue   Esc: cancel"), chunks[3]);
}

fn render_multisig_cosigners(
    frame: &mut Frame,
    app: &App,
    name: &str,
    total: usize,
    threshold: usize,
    cosigners: &[String],
    current: &str,
    error: Option<&str>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(content_area(frame));

    let mut items: Vec<ListItem> = cosigners
        .iter()
        .enumerate()
        .map(|(i, k)| ListItem::new(format!("{}. {k}", i + 1)))
        .collect();
    if items.is_empty() {
        items.push(ListItem::new(Span::styled("(none entered yet)", Style::default().fg(MUTED))));
    }
    frame.render_widget(
        List::new(items).block(block(format!(" Cosigners entered for '{name}' ({}-of-{total}) ", threshold))),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(current).block(
            block(format!(
                " Cosigner key {} of {} -- paste [fingerprint/path]xpub... ",
                cosigners.len() + 1,
                total - 1
            ))
            .border_style(field_border_style(true)),
        ),
        chunks[1],
    );

    if let Some(err) = error {
        frame.render_widget(error_line(err), chunks[2]);
    }

    frame.render_widget(Paragraph::new(status_line(app)), chunks[3]);
    frame.render_widget(
        hint("Get this from another wallet instance's [k] screen.   Enter: add   Esc: cancel"),
        chunks[4],
    );
}

fn render_set_password(frame: &mut Frame, app: &App, form: &SetPasswordForm) {
    let title = match form.purpose {
        NamePurpose::Create => " Set a password to encrypt this wallet's seed ",
        NamePurpose::Restore => " Set a password to encrypt the restored seed ",
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(mask(&form.password))
            .block(block(title).border_style(field_border_style(form.focus == PasswordField::Password))),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(mask(&form.confirm))
            .block(block(" Confirm password ").border_style(field_border_style(form.focus == PasswordField::Confirm))),
        chunks[1],
    );
    frame.render_widget(Paragraph::new(status_line(app)), chunks[2]);
    frame.render_widget(hint("Tab: switch field   Enter: continue   Esc: cancel"), chunks[3]);
}

fn render_mnemonic_reveal(frame: &mut Frame, mnemonic: &str) {
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Mnemonic -- the ONLY backup of your funds:",
            Style::default().add_modifier(Modifier::BOLD).fg(WARNING),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {mnemonic}"),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Anyone with these words can spend your bitcoin. Write them down, offline."),
        Line::from(""),
        Line::from(Span::styled(
            "Press Enter once you've saved it.",
            Style::default().add_modifier(Modifier::ITALIC).fg(MUTED),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(block_emphasis(" Wallet created ").border_style(Style::default().fg(WARNING)))
            .wrap(Wrap { trim: false }),
        content_area(frame),
    );
}

fn render_restore(frame: &mut Frame, app: &App, form: &RestoreForm) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(form.name.as_str())
            .block(block(format!(" Restoring as ({}) ", form.script_kind.label()))),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(form.mnemonic.as_str())
            .block(block(" Mnemonic ").border_style(field_border_style(form.focus == RestoreField::Mnemonic))),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(form.passphrase.as_str()).block(
            block(" Passphrase (optional) ").border_style(field_border_style(form.focus == RestoreField::Passphrase)),
        ),
        chunks[2],
    );
    frame.render_widget(Paragraph::new(status_line(app)), chunks[3]);
    frame.render_widget(hint("Tab: switch field   Enter: restore   Esc: back"), chunks[4]);
}

fn render_dashboard(frame: &mut Frame, app: &mut App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(content_area(frame));

    let header = if let Some(session) = &app.wallet {
        let kind_label = match rfb_wallet::seed::multisig_threshold(&session.wallet) {
            Some((k, n)) => format!("{} {k}-of-{n}", rfb_wallet::seed::script_kind_of(&session.wallet).label()),
            None => rfb_wallet::seed::script_kind_of(&session.wallet).label().to_string(),
        };
        format!(
            " ₿ rfb_wallet -- {:?} -- wallet '{}' ({kind_label})   tip height {} ",
            app.network,
            session.name,
            session.wallet.latest_checkpoint().height()
        )
    } else {
        format!(" ₿ rfb_wallet -- {:?} ", app.network)
    };
    frame.render_widget(block(header).border_style(Style::default().fg(ACCENT)), outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(outer[1]);

    render_balance_panel(frame, app, body[0]);
    render_history_panel(frame, app, body[1]);

    // When there's something worth a one-click copy (just set by the action that produced
    // `status`), append a visible hint to the same line and remember this box's exact screen
    // coordinates so a mouse click can be hit-tested against it -- see `App::handle_mouse`.
    let mut status_spans = status_line(app).spans;
    if app.last_copyable.is_some() {
        status_spans.push(Span::styled(
            "  [click to copy]",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(status_spans)).block(block(" Status ").border_style(status_border_style(app))),
        outer[2],
    );
    app.copy_hint_rect = app.last_copyable.is_some().then_some(outer[2]);

    frame.render_widget(
        hint(
            "[a] addr  [s] sync  [n] send  [u] coins  [b] bump fee  [m] mine  [w] wallets  [up/down] history  [q] quit\n\
             [e] export psbt  [i] import+sign psbt  [p] publish signed psbt  [k] show my key  [c] co-sign psbt",
        ),
        outer[3],
    );
}

fn render_balance_panel(frame: &mut Frame, app: &App, area: Rect) {
    let lines = if let Some(session) = &app.wallet {
        let b = session.wallet.balance();
        vec![
            Line::from(vec![
                Span::raw("Confirmed:  "),
                Span::styled(format!("{}", b.confirmed), Style::default().fg(POSITIVE)),
            ]),
            Line::from(vec![
                Span::raw("Pending:    "),
                Span::styled(format!("{}", b.trusted_pending + b.untrusted_pending), Style::default().fg(WARNING)),
            ]),
            Line::from(vec![
                Span::raw("Immature:   "),
                Span::styled(format!("{}", b.immature), Style::default().fg(MUTED)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                format!("Total:      {}", b.total()),
                Style::default().add_modifier(Modifier::BOLD).fg(ACCENT),
            )),
        ]
    } else {
        vec![Line::from(Span::styled("No wallet loaded", Style::default().fg(MUTED)))]
    };
    frame.render_widget(Paragraph::new(lines).block(block(" Balance ")), area);
}

fn render_history_panel(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(session) = &mut app.wallet else {
        frame.render_widget(
            Paragraph::new(Span::styled("No wallet loaded", Style::default().fg(MUTED))).block(block(" History ")),
            area,
        );
        return;
    };

    if session.history_cache.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("No transactions yet. Press 's' to sync.", Style::default().fg(MUTED)))
                .block(block(" History ")),
            area,
        );
        return;
    }

    let items: Vec<ListItem> = session
        .history_cache
        .iter()
        .map(|e| {
            let status = match &e.status {
                TxStatus::Confirmed { confirmations, .. } => format!("confirmed ({confirmations})"),
                TxStatus::Unconfirmed => "unconfirmed".to_string(),
            };
            let (sign, color) = if e.net.is_negative() { ("", DANGER) } else { ("+", POSITIVE) };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{}  ", e.txid)),
                Span::styled(format!("{sign}{}", e.net), Style::default().fg(color)),
                Span::styled(format!("  {status}"), Style::default().fg(MUTED)),
            ]))
        })
        .collect();

    let list = List::new(items).block(block(" History ")).highlight_style(highlight_style());

    frame.render_stateful_widget(list, area, &mut session.history_state);
}

/// `confirmed (N)` / `unconfirmed` / `immature coinbase (N/100)` -- the same vocabulary as the
/// History panel, plus the coinbase-maturity call-out coin control specifically needs: picking
/// an immature coinbase as a manually-selected input builds a transaction that bitcoind will
/// reject outright (`bad-txns-premature-spend-of-coinbase`), so this is the one place in the UI
/// where hiding that distinction would actively mislead the user into a guaranteed-failing send.
fn coin_status_label(app: &App, coin: &LocalOutput, tip_height: u32) -> String {
    let confirmations = match &coin.chain_position {
        bdk_wallet::chain::ChainPosition::Confirmed { anchor, .. } => {
            Some(tip_height.saturating_sub(anchor.block_id.height) + 1)
        }
        bdk_wallet::chain::ChainPosition::Unconfirmed { .. } => None,
    };
    let is_coinbase = app
        .wallet
        .as_ref()
        .and_then(|s| s.wallet.get_tx(coin.outpoint.txid))
        .is_some_and(|tx| tx.tx_node.tx.is_coinbase());

    match confirmations {
        None => "unconfirmed".to_string(),
        Some(n) if is_coinbase && n < 100 => format!("immature coinbase ({n}/100)"),
        Some(n) => format!("confirmed ({n})"),
    }
}

fn render_coin_picker(frame: &mut Frame, app: &App, coins: &[LocalOutput], selected: &[bool], cursor: usize) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3), Constraint::Length(1)])
        .split(content_area(frame));

    let tip_height = app
        .wallet
        .as_ref()
        .map(|s| s.wallet.latest_checkpoint().height())
        .unwrap_or(0);

    let items: Vec<ListItem> = if coins.is_empty() {
        vec![ListItem::new(Span::styled("No UTXOs in this wallet yet.", Style::default().fg(MUTED)))]
    } else {
        coins
            .iter()
            .zip(selected)
            .map(|(c, &is_selected)| {
                let mark = if is_selected { "[x]" } else { "[ ]" };
                let status = coin_status_label(app, c, tip_height);
                let color = if status.starts_with("immature") || status == "unconfirmed" { WARNING } else { POSITIVE };
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{mark} {}  {}  ", c.outpoint, c.txout.value)),
                    Span::styled(status, Style::default().fg(color)),
                ]))
            })
            .collect()
    };

    let mut state = ListState::default();
    if !coins.is_empty() {
        state.select(Some(cursor));
    }
    let total: Amount = coins
        .iter()
        .zip(selected)
        .filter(|&(_, &is_selected)| is_selected)
        .map(|(c, _)| c.txout.value)
        .sum();
    let list = List::new(items)
        .block(block(format!(" Coins -- {total} selected ")))
        .highlight_style(highlight_style());
    frame.render_stateful_widget(list, chunks[0], &mut state);

    frame.render_widget(Paragraph::new(status_line(app)), chunks[1]);
    frame.render_widget(hint("Space: toggle   [s] send with selected   [up/down] move   Esc: back"), chunks[2]);
}

fn render_send(frame: &mut Frame, app: &App, form: &SendForm) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(content_area(frame));

    let to_title = if form.coins.is_empty() {
        " To address ".to_string()
    } else {
        format!(" To address (coin control: {} input(s)) ", form.coins.len())
    };
    frame.render_widget(
        Paragraph::new(form.to.as_str())
            .block(block(to_title).border_style(field_border_style(form.focus == SendField::To))),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(form.sats.as_str())
            .block(block(" Amount (sats) ").border_style(field_border_style(form.focus == SendField::Sats))),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(form.fee_rate.as_str()).block(
            block(" Fee rate sat/vB (blank = auto) ").border_style(field_border_style(form.focus == SendField::FeeRate)),
        ),
        chunks[2],
    );

    let already_unlocked = app.wallet.as_ref().is_some_and(|s| s.unlocked_seed.is_some());
    let password_title = if already_unlocked {
        " Password (already unlocked this session -- leave blank) "
    } else {
        " Password (required to sign) "
    };
    frame.render_widget(
        Paragraph::new(mask(&form.password))
            .block(block(password_title).border_style(field_border_style(form.focus == SendField::Password))),
        chunks[3],
    );

    if let Some(err) = &form.error {
        frame.render_widget(error_line(err), chunks[4]);
    }

    frame.render_widget(Paragraph::new(status_line(app)), chunks[5]);
    frame.render_widget(hint("Tab/Shift+Tab: switch field   Enter: send   Esc: cancel"), chunks[6]);
}

fn render_bump_fee(frame: &mut Frame, app: &App, form: &BumpFeeForm) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(form.fee_rate.as_str()).block(
            block(format!(" New fee rate sat/vB (currently ~{:.2}) ", form.old_fee_rate_sat_vb))
                .border_style(field_border_style(form.focus == BumpFeeField::FeeRate)),
        ),
        chunks[0],
    );

    let already_unlocked = app.wallet.as_ref().is_some_and(|s| s.unlocked_seed.is_some());
    let password_title = if already_unlocked {
        " Password (already unlocked this session -- leave blank) "
    } else {
        " Password (required to sign) "
    };
    frame.render_widget(
        Paragraph::new(mask(&form.password))
            .block(block(password_title).border_style(field_border_style(form.focus == BumpFeeField::Password))),
        chunks[1],
    );

    if let Some(err) = &form.error {
        frame.render_widget(error_line(err), chunks[2]);
    }

    frame.render_widget(Paragraph::new(status_line(app)), chunks[3]);
    frame.render_widget(
        hint(format!("Bumping {}   Tab: switch field   Enter: broadcast   Esc: cancel", form.txid)),
        chunks[4],
    );
}

fn render_export_psbt(frame: &mut Frame, app: &App, form: &ExportPsbtForm) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(form.to.as_str())
            .block(block(" To address ").border_style(field_border_style(form.focus == ExportPsbtField::To))),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(form.sats.as_str())
            .block(block(" Amount (sats) ").border_style(field_border_style(form.focus == ExportPsbtField::Sats))),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(form.fee_rate.as_str()).block(
            block(" Fee rate sat/vB (blank = auto) ")
                .border_style(field_border_style(form.focus == ExportPsbtField::FeeRate)),
        ),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new(form.path.as_str()).block(
            block(" Write unsigned PSBT to (file path) ")
                .border_style(field_border_style(form.focus == ExportPsbtField::Path)),
        ),
        chunks[3],
    );

    if let Some(err) = &form.error {
        frame.render_widget(error_line(err), chunks[4]);
    }

    frame.render_widget(Paragraph::new(status_line(app)), chunks[5]);
    frame.render_widget(hint("No seed needed for this step. Tab: switch field   Enter: export   Esc: cancel"), chunks[6]);
}

fn render_import_sign(frame: &mut Frame, app: &App, form: &ImportSignForm) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(form.in_path.as_str()).block(
            block(" Read PSBT from (file path) ").border_style(field_border_style(form.focus == ImportSignField::InPath)),
        ),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(form.out_path.as_str()).block(
            block(" Write signed PSBT to (file path) ")
                .border_style(field_border_style(form.focus == ImportSignField::OutPath)),
        ),
        chunks[1],
    );

    let already_unlocked = app.wallet.as_ref().is_some_and(|s| s.unlocked_seed.is_some());
    let password_title = if already_unlocked {
        " Password (already unlocked this session -- leave blank) "
    } else {
        " Password (required to sign) "
    };
    frame.render_widget(
        Paragraph::new(mask(&form.password))
            .block(block(password_title).border_style(field_border_style(form.focus == ImportSignField::Password))),
        chunks[2],
    );

    if let Some(err) = &form.error {
        frame.render_widget(error_line(err), chunks[3]);
    }

    frame.render_widget(Paragraph::new(status_line(app)), chunks[4]);
    frame.render_widget(hint("No network needed for this step. Tab: switch field   Enter: sign   Esc: cancel"), chunks[5]);
}

fn render_import_broadcast(frame: &mut Frame, app: &App, form: &ImportBroadcastForm) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(2), Constraint::Min(1), Constraint::Length(1)])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(form.path.as_str()).block(
            block(" Read signed PSBT from (file path) ").border_style(field_border_style(true)),
        ),
        chunks[0],
    );

    if let Some(err) = &form.error {
        frame.render_widget(error_line(err), chunks[1]);
    }

    frame.render_widget(Paragraph::new(status_line(app)), chunks[2]);
    frame.render_widget(hint("Enter: broadcast   Esc: cancel"), chunks[3]);
}

fn render_export_multisig_key(frame: &mut Frame, app: &App, form: &ExportMultisigKeyForm) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(2), Constraint::Min(1), Constraint::Length(1)])
        .split(content_area(frame));

    let already_unlocked = app.wallet.as_ref().is_some_and(|s| s.unlocked_seed.is_some());
    let password_title = if already_unlocked {
        " Password (already unlocked this session -- leave blank) "
    } else {
        " Password (required to derive this key) "
    };
    frame.render_widget(
        Paragraph::new(mask(&form.password)).block(block(password_title).border_style(field_border_style(true))),
        chunks[0],
    );

    if let Some(err) = &form.error {
        frame.render_widget(error_line(err), chunks[1]);
    }

    frame.render_widget(Paragraph::new(status_line(app)), chunks[2]);
    frame.render_widget(hint("Any wallet's seed can export a cosigner key. Enter: show key   Esc: cancel"), chunks[3]);
}

fn render_multisig_sign(frame: &mut Frame, app: &App, form: &MultisigSignForm) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(form.in_path.as_str()).block(
            block(" Read PSBT from (file path) ").border_style(field_border_style(form.focus == MultisigSignField::InPath)),
        ),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(form.out_path.as_str()).block(
            block(" Write co-signed PSBT to (file path) ")
                .border_style(field_border_style(form.focus == MultisigSignField::OutPath)),
        ),
        chunks[1],
    );

    let already_unlocked = app.wallet.as_ref().is_some_and(|s| s.unlocked_seed.is_some());
    let password_title = if already_unlocked {
        " Password (already unlocked this session -- leave blank) "
    } else {
        " Password (required to sign) "
    };
    frame.render_widget(
        Paragraph::new(mask(&form.password))
            .block(block(password_title).border_style(field_border_style(form.focus == MultisigSignField::Password))),
        chunks[2],
    );

    if let Some(err) = &form.error {
        frame.render_widget(error_line(err), chunks[3]);
    }

    frame.render_widget(Paragraph::new(status_line(app)), chunks[4]);
    frame.render_widget(
        hint("Adds this wallet's signature; repeat per signer until threshold is met. Tab: switch field   Enter: sign   Esc: cancel"),
        chunks[5],
    );
}

fn render_mine(frame: &mut Frame, app: &App, form: &MineForm) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(1)])
        .split(content_area(frame));

    frame.render_widget(
        Paragraph::new(form.blocks.as_str())
            .block(block(" Blocks to mine (regtest) ").border_style(field_border_style(true))),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(status_line(app)), chunks[1]);
    frame.render_widget(hint("Enter: mine   Esc: cancel"), chunks[2]);
}
