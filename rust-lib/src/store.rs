//! The accounts offered, kept in the module's own directory as `accounts.json` with the names
//! given to the wallets they came from: public material only.

use std::collections::BTreeMap;
use std::path::PathBuf;

use logos_signer_interface::Account;
use serde::{Deserialize, Serialize};

use crate::accounts::Offered;

#[derive(Default, Serialize, Deserialize)]
struct File {
    accounts: Vec<Offered>,
    /// Wallet names, by master fingerprint in hex.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    wallets: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct Store {
    path: Option<PathBuf>,
    offered: Vec<Offered>,
    wallets: BTreeMap<String, String>,
}

impl Store {
    /// In memory only, until [`Store::open`].
    pub fn new() -> Self {
        Store::default()
    }

    /// Read `dir/accounts.json`, kept there from now on. A missing file is an empty list.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = dir.into().join("accounts.json");
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<File>(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => return Err(e),
        };
        Ok(Store {
            path: Some(path),
            offered: file.accounts,
            wallets: file.wallets,
        })
    }

    pub fn list(&self) -> &[Offered] {
        &self.offered
    }

    pub fn find(&self, id: &str) -> Option<&Offered> {
        self.offered.iter().find(|o| same(&o.account, id))
    }

    /// Add or replace accounts by id, and save.
    pub fn put(&mut self, add: Vec<Offered>) -> std::io::Result<()> {
        for o in add {
            match self
                .offered
                .iter_mut()
                .find(|have| same(&have.account, &o.account.id))
            {
                Some(have) => *have = o,
                None => self.offered.push(o),
            }
        }
        self.save()
    }

    /// Name an account, or clear its name with None. Whether it changed, saved.
    pub fn rename(&mut self, id: &str, label: Option<String>) -> std::io::Result<bool> {
        let Some(o) = self.offered.iter_mut().find(|o| same(&o.account, id)) else {
            return Ok(false);
        };
        if o.account.label == label {
            return Ok(false);
        }
        o.account.label = label;
        self.save()?;
        Ok(true)
    }

    /// Whether an account went, saved. A wallet's name goes with its last account.
    pub fn remove(&mut self, id: &str) -> std::io::Result<bool> {
        let before = self.offered.len();
        self.offered.retain(|o| !same(&o.account, id));
        let offered = &self.offered;
        self.wallets
            .retain(|fp, _| offered.iter().any(|o| hex::encode(o.fingerprint) == *fp));
        self.save()?;
        Ok(self.offered.len() != before)
    }

    /// The name given to the wallet with this master fingerprint, in hex.
    pub fn wallet_name(&self, fingerprint: &str) -> Option<&str> {
        self.wallets.get(fingerprint).map(String::as_str)
    }

    /// Name a wallet, or clear its name with None. Whether it changed, saved.
    pub fn rename_wallet(
        &mut self,
        fingerprint: &str,
        name: Option<String>,
    ) -> std::io::Result<bool> {
        if self.wallets.get(fingerprint) == name.as_ref() {
            return Ok(false);
        }
        match name {
            Some(name) => self.wallets.insert(fingerprint.to_string(), name),
            None => self.wallets.remove(fingerprint),
        };
        self.save()?;
        Ok(true)
    }

    fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let body = serde_json::to_vec_pretty(&File {
            accounts: self.offered.clone(),
            wallets: self.wallets.clone(),
        })?;
        let tmp = path.with_extension("json.tmp");
        write_private(&tmp, &body)?;
        std::fs::rename(tmp, path)
    }
}

/// Written readable by its owner only (0600 where the system has modes).
fn write_private(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        // A file left from before keeps its mode: set it.
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    options.open(path)?.write_all(body)
}

/// EVM addresses compare without case; other ids exactly.
fn same(a: &Account, id: &str) -> bool {
    if a.family == logos_signer_interface::Family::Evm {
        a.id.eq_ignore_ascii_case(id.trim())
    } else {
        a.id == id.trim()
    }
}
