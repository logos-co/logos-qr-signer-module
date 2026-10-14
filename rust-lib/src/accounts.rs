//! Accounts from the keys a wallet shows as a QR code: public material only. Ids, paths and xpubs
//! are built as the Keycard Shell's USB module builds them, so both name an account alike.

use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::NetworkKind;
use logos_signer_interface::{Account, Chain, Family};
use sha3::{Digest, Keccak256};

use crate::ur::{Accounts, HdKey, Script};

pub const HARDENED: u32 = 0x8000_0000;

pub fn path_string(path: &[u32]) -> String {
    let mut s = String::from("m");
    for i in path {
        if i & HARDENED != 0 {
            s += &format!("/{}'", i & !HARDENED);
        } else {
            s += &format!("/{i}");
        }
    }
    s
}

/// The indexes of a path such as `m/84'/1'/0'/0/3` (`h` marks a hardened index too).
pub fn parse_path(s: &str) -> Option<Vec<u32>> {
    let rest = s.trim().strip_prefix('m')?;
    rest.split('/')
        .skip(1)
        .map(|step| {
            let (n, hard) = match step.strip_suffix(['\'', 'h']) {
                Some(n) => (n, HARDENED),
                None => (step, 0),
            };
            n.parse::<u32>()
                .ok()
                .filter(|n| *n < HARDENED)
                .map(|n| n | hard)
        })
        .collect()
}

/// An account this signer offers: its public face, and what a request needs to name it to the
/// wallet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Offered {
    pub account: Account,
    /// The wallet's master fingerprint, as requests name it.
    pub fingerprint: [u8; 4],
    /// The compressed public key that signs, hex: the address's key for EVM, the account key for
    /// Bitcoin.
    pub key: String,
    /// Which wallet it is, for what its codes can hold: see [`crate::profile`].
    pub profile: String,
}

fn account_key(k: &HdKey) -> Result<(PublicKey, [u8; 32], Vec<u32>), String> {
    let key = PublicKey::from_slice(&k.key).map_err(|e| format!("a key: {e}"))?;
    let chain: [u8; 32] = k
        .chain_code
        .as_deref()
        .and_then(|c| c.try_into().ok())
        .ok_or("a key came without its chain code")?;
    let path = k
        .origin
        .as_ref()
        .map(|o| o.components.clone())
        .ok_or("a key came without its path")?;
    Ok((key, chain, path))
}

fn bitcoin_account(
    fp: [u8; 4],
    k: &HdKey,
    family: Family,
    profile: &str,
    label: Option<String>,
) -> Result<Offered, String> {
    let (key, chain_code, path) = account_key(k)?;
    let [purpose, coin, account] =
        <[u32; 3]>::try_from(path.as_slice()).map_err(|_| "not an account's path")?;
    let chain = match (coin & !HARDENED, k.use_info.map(|u| u.network)) {
        (_, Some(1)) | (1, None) => Chain::Test,
        _ => Chain::Main,
    };
    let xpub = Xpub {
        network: if chain == Chain::Main {
            NetworkKind::Main
        } else {
            NetworkKind::Test
        },
        depth: 3,
        parent_fingerprint: Fingerprint::from(
            k.parent_fingerprint
                .ok_or("an account key came without its parent's fingerprint")?
                .to_be_bytes(),
        ),
        child_number: ChildNumber::from(account),
        public_key: key,
        chain_code: ChainCode::from(chain_code),
    };
    let fph = hex::encode(fp);
    Ok(Offered {
        account: Account {
            id: format!(
                "qr-{fph}-{}-{}-{}",
                purpose & !HARDENED,
                coin & !HARDENED,
                account & !HARDENED
            ),
            family,
            chain: Some(chain),
            path: Some(path_string(&path)),
            fingerprint: Some(fph),
            address: None,
            xpub: Some(xpub.to_string()),
            label,
            available: true,
        },
        fingerprint: fp,
        key: hex::encode(key.serialize()),
        profile: profile.to_string(),
    })
}

/// The first address, m/44'/60'/0'/0/0, from the account key a wallet shows at m/44'/60'/0'.
fn evm_account(
    fp: [u8; 4],
    k: &HdKey,
    profile: &str,
    label: Option<String>,
) -> Result<Offered, String> {
    let (key, chain_code, path) = account_key(k)?;
    let (key, path) = match path.as_slice() {
        [p, c, a] if *p == HARDENED | 44 && *c == HARDENED | 60 && *a == HARDENED => {
            let xpub = Xpub {
                network: NetworkKind::Main,
                depth: 3,
                parent_fingerprint: Fingerprint::default(),
                child_number: ChildNumber::from(*a),
                public_key: key,
                chain_code: ChainCode::from(chain_code),
            };
            let secp = Secp256k1::verification_only();
            let first = xpub
                .derive_pub(&secp, &[ChildNumber::from(0), ChildNumber::from(0)])
                .map_err(|e| e.to_string())?;
            (first.public_key, [path.clone(), vec![0, 0]].concat())
        }
        [p, c, a, 0, 0] if *p == HARDENED | 44 && *c == HARDENED | 60 && *a == HARDENED => {
            (key, path.clone())
        }
        _ => {
            return Err(format!(
                "an EVM key at {}, not m/44'/60'/0'",
                path_string(&path)
            ))
        }
    };
    let hash = Keccak256::digest(&key.serialize_uncompressed()[1..]);
    let address = format!("0x{}", hex::encode(&hash[12..]));
    Ok(Offered {
        account: Account {
            id: address.clone(),
            family: Family::Evm,
            chain: None,
            path: Some(path_string(&path)),
            fingerprint: Some(hex::encode(fp)),
            address: Some(address),
            xpub: None,
            label,
            available: true,
        },
        fingerprint: fp,
        key: hex::encode(key.serialize()),
        profile: profile.to_string(),
    })
}

/// The accounts of the asked families in what the wallet showed, in that order.
pub fn offered(
    found: &Accounts,
    families: &[Family],
    profile: &str,
    label: Option<&str>,
) -> Result<Vec<Offered>, String> {
    let fp = found.master_fingerprint.to_be_bytes();
    let label = || label.map(str::to_string);
    let mut out = Vec::new();
    for family in families {
        let made = match family {
            Family::Bitcoin | Family::BitcoinTaproot => {
                let script = if *family == Family::Bitcoin {
                    Script::Wpkh
                } else {
                    Script::Tr
                };
                let purpose = if *family == Family::Bitcoin { 84 } else { 86 };
                found
                    .outputs
                    .iter()
                    .find(|o| o.script == script)
                    .map(|o| o.key.clone())
                    .or_else(|| {
                        found
                            .keys
                            .iter()
                            .find(|k| {
                                k.origin.as_ref().and_then(|p| p.components.first())
                                    == Some(&(HARDENED | purpose))
                            })
                            .cloned()
                    })
                    .map(|k| bitcoin_account(fp, &k, *family, profile, label()))
            }
            Family::Evm => found
                .keys
                .iter()
                .chain(found.outputs.iter().map(|o| &o.key))
                .find(|k| {
                    k.origin
                        .as_ref()
                        .is_some_and(|p| p.components.starts_with(&[HARDENED | 44, HARDENED | 60]))
                })
                .map(|k| evm_account(fp, k, profile, label())),
        };
        match made {
            Some(r) => out.push(r?),
            None => {
                return Err(format!(
                    "the code holds no {} account",
                    family_name(*family)
                ))
            }
        }
    }
    Ok(out)
}

pub fn family_name(f: Family) -> &'static str {
    match f {
        Family::Evm => "EVM",
        Family::Bitcoin => "native segwit",
        Family::BitcoinTaproot => "taproot",
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::bip32::{DerivationPath, Xpriv};

    use super::*;
    use crate::ur::{Keypath, Output};

    /// The "abandon … about" mnemonic's root key, from BIP84 and BIP86 at bitcoin/bips 927b6de9915c.
    const ROOT: &str = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";

    fn hdkey(path: &str) -> HdKey {
        let secp = Secp256k1::new();
        let root = Xpriv::from_str(ROOT).unwrap();
        let p = DerivationPath::from_str(path).unwrap();
        let x = root.derive_priv(&secp, &p).unwrap();
        let parent = root
            .derive_priv(&secp, &p.as_ref()[..p.len() - 1].to_vec())
            .unwrap();
        HdKey {
            key: x.private_key.public_key(&secp).serialize().to_vec(),
            chain_code: Some(x.chain_code.to_bytes().to_vec()),
            use_info: None,
            origin: Some(Keypath {
                components: p.into_iter().map(|c| u32::from(*c)).collect(),
                source_fingerprint: Some(0x73c5da0a),
                depth: Some(3),
            }),
            children: None,
            parent_fingerprint: Some(u32::from_be_bytes(parent.fingerprint(&secp).to_bytes())),
            name: None,
        }
    }

    fn shown() -> Accounts {
        Accounts {
            master_fingerprint: 0x73c5da0a,
            outputs: vec![
                Output {
                    script: Script::Wpkh,
                    key: hdkey("m/84'/0'/0'"),
                },
                Output {
                    script: Script::Tr,
                    key: hdkey("m/86'/0'/0'"),
                },
            ],
            keys: vec![hdkey("m/44'/60'/0'")],
            device: None,
        }
    }

    #[test]
    fn the_xpubs_are_the_ones_bip84_and_bip86_publish() {
        let got = offered(
            &shown(),
            &[Family::Bitcoin, Family::BitcoinTaproot],
            "generic",
            None,
        )
        .unwrap();
        // BIP84's and BIP86's account 0 xpubs for the same mnemonic, as xpubs.
        assert_eq!(
            got[0].account.xpub.as_deref(),
            Some("xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V")
        );
        assert_eq!(
            got[1].account.xpub.as_deref(),
            Some("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ")
        );
        assert_eq!(got[0].account.id, "qr-73c5da0a-84-0-0");
        assert_eq!(got[1].account.path.as_deref(), Some("m/86'/0'/0'"));
        assert_eq!(got[0].account.chain, Some(Chain::Main));
    }

    #[test]
    fn the_first_evm_address() {
        let got = offered(&shown(), &[Family::Evm], "keycard_shell", Some("Shell")).unwrap();
        assert_eq!(
            got[0].account.id,
            "0x9858effd232b4033e47d90003d41ec34ecaeda94"
        );
        assert_eq!(got[0].account.path.as_deref(), Some("m/44'/60'/0'/0/0"));
        assert_eq!(got[0].account.label.as_deref(), Some("Shell"));
    }

    #[test]
    fn a_family_the_code_lacks_is_named() {
        let mut a = shown();
        a.outputs.clear();
        let e = offered(&a, &[Family::BitcoinTaproot], "generic", None).unwrap_err();
        assert!(e.contains("taproot"), "{e}");
    }

    #[test]
    fn paths_round_trip() {
        assert_eq!(
            parse_path("m/84'/1'/0'/0/3").unwrap(),
            vec![HARDENED | 84, HARDENED | 1, HARDENED, 0, 3]
        );
        assert_eq!(
            path_string(&parse_path("m/86h/0h/0h").unwrap()),
            "m/86'/0'/0'"
        );
    }
}
