use std::io::Write as _;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use argon2::Argon2;
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv};
use bdk_wallet::bitcoin::NetworkKind;
use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
use bdk_wallet::keys::{GeneratableKey, GeneratedKey};
use bdk_wallet::miniscript::descriptor::{
    Descriptor, DescriptorPublicKey, DescriptorSecretKey, DescriptorXKey, KeyMap, Wildcard, WshInner,
};
use bdk_wallet::miniscript::Segwitv0;
use bdk_wallet::template::{Bip84, Bip86};
use bdk_wallet::KeychainKind;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

use crate::walletdb::OpenWallet;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Which BIP output-script template a wallet's keys are derived under. Not stored anywhere of
/// its own -- a loaded wallet's own public descriptor already says which one it is (see
/// [`script_kind_of`]), so this only needs to be chosen once, at creation/restoration time.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum ScriptKind {
    /// BIP84 native SegWit: `wpkh(...)`, addresses like `bc1q...`.
    #[default]
    Segwit,
    /// BIP86 Taproot: `tr(...)`, addresses like `bc1p...`.
    Taproot,
    /// BIP48 native SegWit multisig: `wsh(sortedmulti(...))`, addresses like `bc1q...`
    /// (P2WSH, longer than single-sig P2WPKH). M-of-N isn't stored on this variant -- it's
    /// read back out of the wallet's own descriptor, see [`multisig_threshold`].
    Multisig,
}

impl ScriptKind {
    pub fn label(self) -> &'static str {
        match self {
            ScriptKind::Segwit => "SegWit (BIP84)",
            ScriptKind::Taproot => "Taproot (BIP86)",
            ScriptKind::Multisig => "Multisig (BIP48)",
        }
    }
}

/// Inspect an already-loaded wallet's own descriptor to recover which [`ScriptKind`] it uses --
/// the one piece of information `keymap_for` needs that isn't on `Seed` itself.
pub fn script_kind_of(wallet: &OpenWallet) -> ScriptKind {
    match wallet.public_descriptor(KeychainKind::External) {
        Descriptor::Tr(_) => ScriptKind::Taproot,
        Descriptor::Wsh(wsh) if matches!(wsh.as_inner(), WshInner::SortedMulti(_)) => ScriptKind::Multisig,
        _ => ScriptKind::Segwit,
    }
}

/// If `wallet` is a multisig (BIP48 `wsh(sortedmulti(...))`) wallet, its `(threshold, total)` --
/// read directly out of the loaded wallet's own descriptor rather than stored anywhere separate,
/// the same way [`script_kind_of`] recovers the script kind. `None` for any other wallet.
pub fn multisig_threshold(wallet: &OpenWallet) -> Option<(usize, usize)> {
    match wallet.public_descriptor(KeychainKind::External) {
        Descriptor::Wsh(wsh) => match wsh.as_inner() {
            WshInner::SortedMulti(smv) => Some((smv.k(), smv.n())),
            WshInner::Ms(_) => None,
        },
        _ => None,
    }
}

/// The wallet's root secret: a BIP39 mnemonic plus an optional passphrase (BIP39 "25th word").
///
/// This is intentionally never written into the bdk_wallet sqlite database. It is the only
/// copy of the private key material and is kept in its own file, encrypted with a
/// user-supplied password, so the public wallet state (addresses, balances, tx history) can be
/// freely inspected/backed up without exposing spend authority -- and a stolen disk alone isn't
/// enough to steal funds.
#[derive(Clone)]
pub struct Seed {
    pub mnemonic: Mnemonic,
    pub passphrase: Option<String>,
}

impl Seed {
    pub fn generate(word_count: WordCount, passphrase: Option<String>) -> Result<Self> {
        let generated: GeneratedKey<Mnemonic, Segwitv0> =
            Mnemonic::generate((word_count, Language::English))
                .map_err(|_| anyhow::anyhow!("failed to generate mnemonic entropy"))?;
        Ok(Self {
            mnemonic: generated.into_key(),
            passphrase,
        })
    }

    pub fn parse(words: &str, passphrase: Option<String>) -> Result<Self> {
        let mnemonic = Mnemonic::parse_in(Language::English, words.trim())
            .context("invalid mnemonic phrase")?;
        Ok(Self {
            mnemonic,
            passphrase,
        })
    }

    /// Encrypt and persist the seed to disk with owner-only permissions.
    ///
    /// On-disk layout is `[16-byte salt][12-byte nonce][ciphertext]`, all raw bytes (no text
    /// format once encrypted -- there's nothing for a human to read). The key is derived from
    /// `password` via Argon2id with a fresh random salt per file, and the plaintext (mnemonic +
    /// passphrase, same two-line format as before) is sealed with ChaCha20-Poly1305 using a
    /// fresh random nonce. Losing the password doesn't lose the funds -- the mnemonic shown at
    /// creation is the real backup -- it just means restoring from that mnemonic again.
    pub fn save(&self, path: &Path, password: &str) -> Result<()> {
        if path.exists() {
            bail!(
                "refusing to overwrite existing seed file at {}",
                path.display()
            );
        }
        let mut plaintext = self.mnemonic.to_string();
        plaintext.push('\n');
        plaintext.push_str(self.passphrase.as_deref().unwrap_or(""));

        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).context("generating salt")?;
        let key = derive_key(password, &salt)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).context("generating nonce")?;
        let nonce = Nonce::from(nonce_bytes);

        let cipher = ChaCha20Poly1305::new(&key.into());
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| anyhow!("encrypting seed"))?;

        let mut file = std::fs::File::create(path)
            .with_context(|| format!("creating seed file at {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&salt)?;
        file.write_all(&nonce_bytes)?;
        file.write_all(&ciphertext)?;
        Ok(())
    }

    pub fn load(path: &Path, password: &str) -> Result<Self> {
        let data =
            std::fs::read(path).with_context(|| format!("reading seed file at {}", path.display()))?;
        anyhow::ensure!(
            data.len() > SALT_LEN + NONCE_LEN,
            "seed file at {} is too short to be valid",
            path.display()
        );
        let (salt, rest) = data.split_at(SALT_LEN);
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

        let key = derive_key(password, salt)?;
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = Nonce::try_from(nonce_bytes).map_err(|_| anyhow!("seed file is corrupt"))?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| anyhow!("wrong password, or seed file is corrupt"))?;
        let text = String::from_utf8(plaintext).context("decrypted seed is not valid text")?;

        let mut lines = text.lines();
        let words = lines
            .next()
            .context("seed file is empty (missing mnemonic line)")?;
        let mnemonic =
            Mnemonic::parse_in(Language::English, words).context("seed file has an invalid mnemonic")?;
        let passphrase = lines.next().filter(|s| !s.is_empty()).map(str::to_owned);
        Ok(Self {
            mnemonic,
            passphrase,
        })
    }

    fn network_kind(network: Network) -> NetworkKind {
        NetworkKind::from(network)
    }

    /// BIP84 (native SegWit) descriptor templates for this seed: `(external, internal)`.
    /// Passing these straight to `Wallet::create` derives keys hierarchically along
    /// `m/84'/{0,1}'/0'/{0,1}/*` depending on network and keychain.
    pub fn bip84_templates(&self) -> (Bip84<(Mnemonic, Option<String>)>, Bip84<(Mnemonic, Option<String>)>) {
        let key = (self.mnemonic.clone(), self.passphrase.clone());
        (
            Bip84(key.clone(), KeychainKind::External),
            Bip84(key, KeychainKind::Internal),
        )
    }

    /// BIP86 (Taproot) descriptor templates for this seed: `(external, internal)`. Same idea as
    /// [`bip84_templates`](Self::bip84_templates), deriving along `m/86'/{0,1}'/0'/{0,1}/*`
    /// instead.
    pub fn bip86_templates(&self) -> (Bip86<(Mnemonic, Option<String>)>, Bip86<(Mnemonic, Option<String>)>) {
        let key = (self.mnemonic.clone(), self.passphrase.clone());
        (
            Bip86(key.clone(), KeychainKind::External),
            Bip86(key, KeychainKind::Internal),
        )
    }

    /// Re-derive the private key map for one keychain, for signing. The wallet loaded from disk
    /// only knows the *public* descriptor (bdk_wallet does not persist secrets), so signing
    /// reconstructs the keymap from the seed on demand and pairs it with the wallet's own
    /// canonical public descriptor via `SignersContainer::build`. `kind` must match whatever the
    /// wallet was actually created with -- see [`script_kind_of`] to recover it from an
    /// already-loaded wallet.
    pub fn keymap_for(&self, network: Network, keychain: KeychainKind, kind: ScriptKind) -> Result<KeyMap> {
        let secp = Secp256k1::new();
        let key = (self.mnemonic.clone(), self.passphrase.clone());
        let network_kind = Self::network_kind(network);
        match kind {
            ScriptKind::Segwit => {
                let template = Bip84(key, keychain);
                let (_, keymap) = template.into_wallet_descriptor(&secp, network_kind)?;
                Ok(keymap)
            }
            ScriptKind::Taproot => {
                let template = Bip86(key, keychain);
                let (_, keymap) = template.into_wallet_descriptor(&secp, network_kind)?;
                Ok(keymap)
            }
            ScriptKind::Multisig => self.multisig_keymap_for(network, keychain),
        }
    }

    /// Derive this seed's BIP48 P2WSH-multisig account key: `m/48'/coin'/0'/2'`. Shared by
    /// [`multisig_xpub_fragment`](Self::multisig_xpub_fragment) (export, public half),
    /// [`multisig_descriptors`](Self::multisig_descriptors) (wallet creation, needs the xprv for
    /// "my" slot), and [`multisig_keymap_for`](Self::multisig_keymap_for) (signing).
    fn multisig_account_xprv(&self, network: Network) -> Result<(Fingerprint, DerivationPath, Xpriv)> {
        let secp = Secp256k1::new();
        let seed_bytes = self.mnemonic.to_seed(self.passphrase.as_deref().unwrap_or(""));
        let master = Xpriv::new_master(Self::network_kind(network), &seed_bytes).context("deriving master key")?;
        let fingerprint = master.fingerprint(&secp);
        let coin = if network == Network::Bitcoin { 0 } else { 1 };
        let account_path = DerivationPath::from_str(&format!("m/48'/{coin}'/0'/2'")).expect("valid path");
        let account_xprv = master
            .derive_priv(&secp, &account_path)
            .context("deriving BIP48 multisig account key")?;
        Ok((fingerprint, account_path, account_xprv))
    }

    /// This seed's account-level BIP48 multisig public key, in the standard
    /// `[fingerprint/48'/coin'/0'/2']xpub...` export format -- paste this into another wallet
    /// instance being created as a cosigner. Carries no secrets.
    pub fn multisig_xpub_fragment(&self, network: Network) -> Result<String> {
        let secp = Secp256k1::new();
        let (fingerprint, account_path, account_xprv) = self.multisig_account_xprv(network)?;
        let account_xpub = bdk_wallet::bitcoin::bip32::Xpub::from_priv(&secp, &account_xprv);
        Ok(format!("[{fingerprint}/{account_path}]{account_xpub}"))
    }

    /// Build the external/internal `wsh(sortedmulti(threshold, ...))` descriptor strings for a
    /// new multisig wallet: this seed's own key (as an xprv, so `Wallet::create` can derive a
    /// signable wallet the same way the single-sig templates do) plus `cosigners`' pasted-in
    /// `[fingerprint/path]xpub...` fragments (public only -- this seed never sees their keys).
    /// Key order within `sortedmulti` doesn't affect the resulting addresses (it sorts the
    /// derived pubkeys itself), so "mine" is always listed first.
    pub fn multisig_descriptors(&self, network: Network, threshold: usize, cosigners: &[String]) -> Result<(String, String)> {
        let (fingerprint, account_path, account_xprv) = self.multisig_account_xprv(network)?;
        let mut keys = vec![format!("[{fingerprint}/{account_path}]{account_xprv}")];
        keys.extend(cosigners.iter().cloned());

        let external = format!(
            "wsh(sortedmulti({threshold},{}))",
            keys.iter().map(|k| format!("{k}/0/*")).collect::<Vec<_>>().join(",")
        );
        let internal = format!(
            "wsh(sortedmulti({threshold},{}))",
            keys.iter().map(|k| format!("{k}/1/*")).collect::<Vec<_>>().join(",")
        );
        Ok((external, internal))
    }

    /// The signing-time counterpart to [`multisig_descriptors`](Self::multisig_descriptors):
    /// rebuilds just *this* seed's one key as a `KeyMap` entry, without reconstructing the whole
    /// multisig descriptor text (which would require knowing every cosigner's key again --
    /// `SignersContainer::build` only needs a keymap entry that matches one of the pubkeys
    /// already in the wallet's own stored descriptor, not the full key list).
    fn multisig_keymap_for(&self, network: Network, keychain: KeychainKind) -> Result<KeyMap> {
        let secp = Secp256k1::new();
        let (fingerprint, account_path, account_xprv) = self.multisig_account_xprv(network)?;
        let leaf = match keychain {
            KeychainKind::Internal => 1,
            KeychainKind::External => 0,
        };
        let secret_key = DescriptorSecretKey::XPrv(DescriptorXKey {
            origin: Some((fingerprint, account_path)),
            xkey: account_xprv,
            derivation_path: DerivationPath::from(vec![ChildNumber::from_normal_idx(leaf)?]),
            wildcard: Wildcard::Unhardened,
        });
        let public_key: DescriptorPublicKey = secret_key
            .to_public(&secp)
            .map_err(|e| anyhow!("deriving multisig signing key: {e}"))?;
        let mut keymap = KeyMap::new();
        keymap.insert(public_key, secret_key);
        Ok(keymap)
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("deriving key from password: {e:?}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::rusqlite::Connection;
    use bdk_wallet::Wallet;

    #[test]
    fn multisig_descriptors_round_trip_into_a_wallet_with_the_right_threshold() {
        let seed_a = Seed::generate(WordCount::Words12, None).unwrap();
        let seed_b = Seed::generate(WordCount::Words12, None).unwrap();
        let network = Network::Regtest;

        let cosigner_b = seed_b.multisig_xpub_fragment(network).unwrap();
        assert!(cosigner_b.starts_with('['), "export format should carry origin info: {cosigner_b}");
        assert!(cosigner_b.contains("48'/1'/0'/2'") || cosigner_b.contains("48h/1h/0h/2h"));

        let (external, internal) = seed_a.multisig_descriptors(network, 2, &[cosigner_b]).unwrap();
        assert!(external.starts_with("wsh(sortedmulti(2,"));
        assert!(internal.starts_with("wsh(sortedmulti(2,"));

        let mut conn = Connection::open_in_memory().unwrap();
        let wallet = Wallet::create(external, internal)
            .network(network)
            .create_wallet(&mut conn)
            .expect("multisig descriptor should be valid and creatable");

        assert_eq!(script_kind_of(&wallet), ScriptKind::Multisig);
        assert_eq!(multisig_threshold(&wallet), Some((2, 2)));
    }

    #[test]
    fn non_multisig_wallet_reports_no_threshold() {
        let seed = Seed::generate(WordCount::Words12, None).unwrap();
        let network = Network::Regtest;
        let (external, internal) = seed.bip84_templates();
        let mut conn = Connection::open_in_memory().unwrap();
        let wallet = Wallet::create(external, internal)
            .network(network)
            .create_wallet(&mut conn)
            .unwrap();

        assert_eq!(script_kind_of(&wallet), ScriptKind::Segwit);
        assert_eq!(multisig_threshold(&wallet), None);
    }

    #[test]
    fn multisig_keymap_matches_the_descriptor_it_helped_create() {
        // The real correctness property: the hand-rolled signing-time KeyMap must actually
        // match a pubkey inside the wallet's own stored descriptor, or `SignersContainer::build`
        // silently finds nothing to sign with.
        let seed_a = Seed::generate(WordCount::Words12, None).unwrap();
        let seed_b = Seed::generate(WordCount::Words12, None).unwrap();
        let network = Network::Regtest;
        let cosigner_b = seed_b.multisig_xpub_fragment(network).unwrap();
        let (external, internal) = seed_a.multisig_descriptors(network, 2, &[cosigner_b]).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        let wallet = Wallet::create(external, internal)
            .network(network)
            .create_wallet(&mut conn)
            .unwrap();

        let keymap = seed_a.keymap_for(network, KeychainKind::External, ScriptKind::Multisig).unwrap();
        let secp = Secp256k1::new();
        let signers = bdk_wallet::signer::SignersContainer::build(
            keymap,
            wallet.public_descriptor(KeychainKind::External),
            &secp,
        );
        assert_eq!(signers.ids().len(), 1, "seed_a's key should match exactly one signer slot");
    }
}
