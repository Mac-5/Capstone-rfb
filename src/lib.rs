//! Core wallet logic, split out of the `rfb_wallet` binary so it's testable without a terminal.
//!
//! The TUI (`app`/`ui` modules, and `main.rs` itself) lives only in the binary target and is
//! not part of this library -- it's presentation on top of what's exposed here.

pub mod backend;
pub mod config;
pub mod history;
pub mod seed;
pub mod send;
pub mod sync;
pub mod walletdb;
