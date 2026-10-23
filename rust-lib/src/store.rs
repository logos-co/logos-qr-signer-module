//! The accounts offered, kept in the module's own directory as `accounts.sealed.json`: one
//! document per seed (its accounts and the name given to its wallet), sealed under the module's key
//! for that seed from the signer manager and read only while the seed is unlocked. A seed whose key
//! hasn't come yet, such as one just added, is kept in memory until it does.

use std::collections::BTreeMap;
use std::path::PathBuf;

use logos_signer_interface::sealed::SealedDocs;
use logos_signer_interface::wallets::DataKey;
use logos_signer_interface::{Account, SignerError};
use serde::{Deserialize, Serialize};

use crate::accounts::Offered;

/// What the sealed documents are called in their boxes.
const WALLETS: &str = "qr_signer_module wallets";

/// One seed's document.
#[derive(Default, Serialize, Deserialize)]
struct Wallet {
    accounts: Vec<Offered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

fn io(e: SignerError) -> std::io::Error {
    std::io::Error::other(e.message)
}

/// The seed an account comes from: its wallet's master fingerprint, in hex.
pub fn seed_of(o: &Offered) -> String {
    hex::encode(o.fingerprint)
}

pub struct Store {
    /// Each seed's document; the readable ones are in the fields below.
    docs: SealedDocs,
    offered: Vec<Offered>,
    /// Wallet names, by seed.
    wallets: BTreeMap<String, String>,
    /// Added while their seed was sealed and locked: merged in, and saved, once it unlocks.
    waiting: BTreeMap<String, Vec<Offered>>,
}

impl Default for Store {
    fn default() -> Self {
        Store {
            docs: SealedDocs::in_memory(WALLETS),
            offered: Vec::new(),
            wallets: BTreeMap::new(),
            waiting: BTreeMap::new(),
        }
    }
}

impl Store {
    /// In memory only, until [`Store::open`].
    pub fn new() -> Self {
        Store::default()
    }

    /// Read `dir/accounts.sealed.json`, kept there from now on. A missing file is an empty list.
    /// Each seed's document stays sealed until its key arrives ([`Store::unlock`]).
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let docs =
            SealedDocs::load(dir.into().join("accounts.sealed.json"), WALLETS).map_err(io)?;
        Ok(Store {
            docs,
            ..Store::default()
        })
    }

    /// Sealed, and its key not given yet.
    fn is_locked(&self, seed: &str) -> bool {
        self.docs.wanted(seed).is_some()
    }

    /// The seeds whose documents wait for their key, each with the generation it is sealed under,
    /// if it is sealed yet.
    pub fn closed(&self) -> Vec<(String, Option<u32>)> {
        let mut out: Vec<(String, Option<u32>)> = self
            .docs
            .seeds()
            .into_iter()
            .filter(|s| !self.docs.is_open(s))
            .map(|s| {
                let g = self.docs.wanted(&s);
                (s, g)
            })
            .collect();
        for seed in self.waiting.keys() {
            if !out.iter().any(|(s, _)| s == seed) {
                out.push((seed.clone(), None));
            }
        }
        out
    }

    /// A seed's key arrived: its accounts are offered again, with those added meanwhile.
    pub fn unlock(
        &mut self,
        seed: &str,
        box_key: &DataKey,
        current: &DataKey,
    ) -> std::io::Result<()> {
        self.docs.unlock(seed, box_key, current).map_err(io)?;
        let doc: Wallet = self
            .docs
            .get(seed)
            .filter(|b| !b.is_empty())
            .map(serde_json::from_slice)
            .transpose()?
            .unwrap_or_default();
        self.offered.retain(|o| seed_of(o) != seed);
        self.offered.extend(doc.accounts);
        self.wallets.remove(seed);
        if let Some(name) = doc.name {
            self.wallets.insert(seed.to_string(), name);
        }
        if let Some(add) = self.waiting.remove(seed) {
            self.merge(add);
        }
        self.save()
    }

    /// Wallets were locked: nothing of a locked seed is offered. What waits for its key stays.
    pub fn lock(&mut self) {
        self.docs.lock();
        let readable: Vec<String> = self.docs.readable().into_iter().map(|(s, _)| s).collect();
        self.offered.retain(|o| readable.contains(&seed_of(o)));
        self.wallets.retain(|seed, _| readable.contains(seed));
    }

    pub fn list(&self) -> &[Offered] {
        &self.offered
    }

    /// Whether some account comes from this seed, listed or sealed while it is locked.
    pub fn knows(&self, seed: &str) -> bool {
        self.offered.iter().any(|o| seed_of(o) == seed)
            || self.docs.seeds().iter().any(|s| s == seed)
            || self.waiting.contains_key(seed)
    }

    pub fn find(&self, id: &str) -> Option<&Offered> {
        self.offered.iter().find(|o| same(&o.account, id))
    }

    /// Add or replace accounts by id, and save. Those of a seed that is sealed and locked wait,
    /// in memory, until it unlocks.
    pub fn put(&mut self, add: Vec<Offered>) -> std::io::Result<()> {
        let (wait, now): (Vec<Offered>, Vec<Offered>) =
            add.into_iter().partition(|o| self.is_locked(&seed_of(o)));
        for o in wait {
            let accounts = self.waiting.entry(seed_of(&o)).or_default();
            accounts.retain(|have| !same(&have.account, &o.account.id));
            accounts.push(o);
        }
        if now.is_empty() {
            return Ok(());
        }
        let previous = (self.offered.clone(), self.wallets.clone());
        self.merge(now);
        if let Err(e) = self.save() {
            (self.offered, self.wallets) = previous;
            return Err(e);
        }
        Ok(())
    }

    fn merge(&mut self, add: Vec<Offered>) {
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
            .retain(|seed, _| offered.iter().any(|o| seed_of(o) == *seed));
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

    /// Each offered seed's document, sealed under its key, or kept in memory until it comes. A
    /// readable seed with no account left is forgotten.
    fn save(&mut self) -> std::io::Result<()> {
        let mut docs: BTreeMap<String, Wallet> = BTreeMap::new();
        for o in &self.offered {
            docs.entry(seed_of(o)).or_default().accounts.push(o.clone());
        }
        for (seed, doc) in docs.iter_mut() {
            doc.name = self.wallets.get(seed).cloned();
        }
        let gone: Vec<String> = self
            .docs
            .readable()
            .into_iter()
            .map(|(seed, _)| seed)
            .filter(|seed| !docs.contains_key(seed))
            .collect();
        for seed in gone {
            self.docs.remove(&seed).map_err(io)?;
        }
        for (seed, doc) in docs {
            self.docs
                .put(&seed, serde_json::to_vec(&doc)?)
                .map_err(io)?;
        }
        Ok(())
    }
}

/// EVM addresses compare without case; other ids exactly.
fn same(a: &Account, id: &str) -> bool {
    if a.family == logos_signer_interface::Family::Evm {
        a.id.eq_ignore_ascii_case(id.trim())
    } else {
        a.id == id.trim()
    }
}
