//! The BC-UR types QR wallets speak, as CBOR: what this signer writes (`crypto-psbt`,
//! `eth-sign-request`) and what it reads (`crypto-psbt`, `eth-signature`, and accounts as
//! `crypto-account`, `crypto-output`, `crypto-hdkey` or Keystone's `crypto-multi-accounts`).
//!
//! Written in the CDDL's key order, which the Keycard Shell's decoder requires, under the registry's
//! old names, which every device reads. Read in any order, under old or new names.

use minicbor::data::{Tag, Type};
use minicbor::{Decoder, Encoder};

/// BCR-2020-006, ERC-4527 and Keystone's registry.
pub mod tag {
    pub const UUID: u64 = 37;
    pub const HDKEY: u64 = 303;
    pub const KEYPATH: u64 = 304;
    pub const COININFO: u64 = 305;
    pub const ECKEY: u64 = 306;
    pub const OUTPUT: u64 = 308;
    pub const SH: u64 = 400;
    pub const WSH: u64 = 401;
    pub const PKH: u64 = 403;
    pub const WPKH: u64 = 404;
    pub const TR: u64 = 409;
    pub const MULTI_ACCOUNTS: u64 = 1103;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrError {
    Cbor(String),
    Missing(&'static str),
    Unsupported(String),
}

impl std::fmt::Display for UrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrError::Cbor(m) => write!(f, "malformed CBOR: {m}"),
            UrError::Missing(field) => write!(f, "missing {field}"),
            UrError::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl From<minicbor::decode::Error> for UrError {
    fn from(e: minicbor::decode::Error) -> Self {
        UrError::Cbor(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, UrError>;

const HARDENED: u32 = 0x8000_0000;

/// A BIP32 path as `crypto-keypath`: components with the hardened bit, and the fingerprint of the
/// key it starts from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keypath {
    pub components: Vec<u32>,
    pub source_fingerprint: Option<u32>,
    pub depth: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinInfo {
    /// SLIP-44: 0 Bitcoin, 60 Ethereum.
    pub coin_type: u32,
    /// 0 mainnet, 1 testnet.
    pub network: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HdKey {
    pub key: Vec<u8>,
    pub chain_code: Option<Vec<u8>>,
    pub use_info: Option<CoinInfo>,
    pub origin: Option<Keypath>,
    pub children: Option<Keypath>,
    pub parent_fingerprint: Option<u32>,
    pub name: Option<String>,
}

/// What an output descriptor spends to, as far as this signer cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    Wpkh,
    Tr,
    ShWpkh,
    Pkh,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub script: Script,
    pub key: HdKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accounts {
    pub master_fingerprint: u32,
    pub outputs: Vec<Output>,
    /// Keys with no script around them: EVM accounts, from `crypto-hdkey` or multi-accounts.
    pub keys: Vec<HdKey>,
    pub device: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthDataType {
    /// A legacy transaction, RLP.
    Transaction = 1,
    TypedData = 2,
    /// `personal_sign`.
    RawBytes = 3,
    /// EIP-2718 typed transaction bytes.
    TypedTransaction = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthSignRequest {
    pub request_id: [u8; 16],
    pub sign_data: Vec<u8>,
    pub data_type: EthDataType,
    pub chain_id: Option<i64>,
    pub path: Keypath,
    pub address: Option<[u8; 20]>,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthSignature {
    pub request_id: Option<[u8; 16]>,
    /// r ‖ s ‖ v.
    pub signature: Vec<u8>,
}

/// The registry's old names, which this signer writes; the new ones are read too.
pub fn canonical(ur_type: &str) -> &str {
    match ur_type {
        "psbt" => "crypto-psbt",
        "account-descriptor" => "crypto-account",
        "hdkey" => "crypto-hdkey",
        "output-descriptor" => "crypto-output",
        other => other,
    }
}

fn enc_err<E: std::fmt::Display>(e: minicbor::encode::Error<E>) -> UrError {
    UrError::Cbor(e.to_string())
}

// ── writing ─────────────────────────────────────────────────────────────

fn write_keypath(e: &mut Encoder<&mut Vec<u8>>, p: &Keypath) -> std::result::Result<(), UrError> {
    let fields = 1 + p.source_fingerprint.is_some() as u64 + p.depth.is_some() as u64;
    e.tag(Tag::new(tag::KEYPATH)).map_err(enc_err)?;
    e.map(fields).map_err(enc_err)?;
    e.u8(1)
        .map_err(enc_err)?
        .array(2 * p.components.len() as u64)
        .map_err(enc_err)?;
    for c in &p.components {
        e.u32(c & !HARDENED)
            .map_err(enc_err)?
            .bool(c & HARDENED != 0)
            .map_err(enc_err)?;
    }
    if let Some(fp) = p.source_fingerprint {
        e.u8(2).map_err(enc_err)?.u32(fp).map_err(enc_err)?;
    }
    if let Some(d) = p.depth {
        e.u8(3).map_err(enc_err)?.u8(d).map_err(enc_err)?;
    }
    Ok(())
}

/// `crypto-psbt`: the PSBT as a byte string.
pub fn psbt(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = Encoder::new(&mut out).bytes(bytes);
    out
}

pub fn eth_sign_request(r: &EthSignRequest) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    let fields =
        4 + r.chain_id.is_some() as u64 + r.address.is_some() as u64 + r.origin.is_some() as u64;
    e.map(fields).map_err(enc_err)?;
    e.u8(1)
        .map_err(enc_err)?
        .tag(Tag::new(tag::UUID))
        .map_err(enc_err)?
        .bytes(&r.request_id)
        .map_err(enc_err)?;
    e.u8(2)
        .map_err(enc_err)?
        .bytes(&r.sign_data)
        .map_err(enc_err)?;
    e.u8(3)
        .map_err(enc_err)?
        .u8(r.data_type as u8)
        .map_err(enc_err)?;
    if let Some(c) = r.chain_id {
        e.u8(4).map_err(enc_err)?.i64(c).map_err(enc_err)?;
    }
    e.u8(5).map_err(enc_err)?;
    write_keypath(&mut e, &r.path)?;
    if let Some(a) = &r.address {
        e.u8(6).map_err(enc_err)?.bytes(a).map_err(enc_err)?;
    }
    if let Some(o) = &r.origin {
        e.u8(7).map_err(enc_err)?.str(o).map_err(enc_err)?;
    }
    Ok(out)
}

fn write_hdkey(e: &mut Encoder<&mut Vec<u8>>, k: &HdKey) -> Result<()> {
    let fields = 1
        + k.chain_code.is_some() as u64
        + k.use_info.is_some() as u64
        + k.origin.is_some() as u64
        + k.parent_fingerprint.is_some() as u64
        + k.name.is_some() as u64;
    e.tag(Tag::new(tag::HDKEY))
        .map_err(enc_err)?
        .map(fields)
        .map_err(enc_err)?;
    e.u8(3).map_err(enc_err)?.bytes(&k.key).map_err(enc_err)?;
    if let Some(c) = &k.chain_code {
        e.u8(4).map_err(enc_err)?.bytes(c).map_err(enc_err)?;
    }
    if let Some(u) = &k.use_info {
        e.u8(5)
            .map_err(enc_err)?
            .tag(Tag::new(tag::COININFO))
            .map_err(enc_err)?
            .map(2)
            .map_err(enc_err)?;
        e.u8(1)
            .map_err(enc_err)?
            .u32(u.coin_type)
            .map_err(enc_err)?
            .u8(2)
            .map_err(enc_err)?
            .i32(u.network)
            .map_err(enc_err)?;
    }
    if let Some(o) = &k.origin {
        e.u8(6).map_err(enc_err)?;
        write_keypath(e, o)?;
    }
    if let Some(p) = k.parent_fingerprint {
        e.u8(8).map_err(enc_err)?.u32(p).map_err(enc_err)?;
    }
    if let Some(n) = &k.name {
        e.u8(9).map_err(enc_err)?.str(n).map_err(enc_err)?;
    }
    Ok(())
}

/// Keystone's `crypto-multi-accounts`, as a wallet shows its accounts: for the emulator and tests.
pub fn multi_accounts(a: &Accounts) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.map(2 + a.device.is_some() as u64).map_err(enc_err)?;
    e.u8(1)
        .map_err(enc_err)?
        .u32(a.master_fingerprint)
        .map_err(enc_err)?;
    e.u8(2)
        .map_err(enc_err)?
        .array(a.keys.len() as u64)
        .map_err(enc_err)?;
    for k in &a.keys {
        write_hdkey(&mut e, k)?;
    }
    if let Some(d) = &a.device {
        e.u8(3).map_err(enc_err)?.str(d).map_err(enc_err)?;
    }
    Ok(out)
}

/// `eth-signature`, as a wallet answers: for the emulator and tests.
pub fn eth_signature(s: &EthSignature) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.map(1 + s.request_id.is_some() as u64).map_err(enc_err)?;
    if let Some(id) = &s.request_id {
        e.u8(1)
            .map_err(enc_err)?
            .tag(Tag::new(tag::UUID))
            .map_err(enc_err)?
            .bytes(id)
            .map_err(enc_err)?;
    }
    e.u8(2)
        .map_err(enc_err)?
        .bytes(&s.signature)
        .map_err(enc_err)?;
    Ok(out)
}

/// `eth-sign-request` read back, as a wallet reads it: for the emulator and tests.
pub fn read_eth_sign_request(cbor: &[u8]) -> Result<EthSignRequest> {
    let mut d = Decoder::new(cbor);
    let mut r = EthSignRequest {
        request_id: [0; 16],
        sign_data: Vec::new(),
        data_type: EthDataType::RawBytes,
        chain_id: None,
        path: Keypath::default(),
        address: None,
        origin: None,
    };
    map_entries(&mut d, |d, k| {
        match k {
            1 => {
                untag(d, tag::UUID)?;
                r.request_id = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| UrError::Missing("a 16-byte request id"))?;
            }
            2 => r.sign_data = d.bytes()?.to_vec(),
            3 => {
                r.data_type = match d.u8()? {
                    1 => EthDataType::Transaction,
                    2 => EthDataType::TypedData,
                    3 => EthDataType::RawBytes,
                    4 => EthDataType::TypedTransaction,
                    t => return Err(UrError::Unsupported(format!("data type {t}"))),
                }
            }
            4 => r.chain_id = Some(d.i64()?),
            5 => r.path = read_keypath(d)?,
            6 => r.address = d.bytes()?.try_into().ok(),
            7 => r.origin = Some(d.str()?.to_string()),
            _ => d.skip()?,
        }
        Ok(())
    })?;
    Ok(r)
}

// ── reading ─────────────────────────────────────────────────────────────

fn untag(d: &mut Decoder, want: u64) -> Result<()> {
    if d.datatype()? == Type::Tag {
        let t = d.tag()?;
        if t.as_u64() != want {
            return Err(UrError::Unsupported(format!(
                "tag {} where {want} was expected",
                t.as_u64()
            )));
        }
    }
    Ok(())
}

/// Each `(key, value)` of a map with small integer keys; `f` must consume the value.
fn map_entries(d: &mut Decoder, mut f: impl FnMut(&mut Decoder, u64) -> Result<()>) -> Result<()> {
    let n = d
        .map()?
        .ok_or(UrError::Unsupported("an indefinite map".into()))?;
    for _ in 0..n {
        let k = d.u64()?;
        f(d, k)?;
    }
    Ok(())
}

fn read_keypath(d: &mut Decoder) -> Result<Keypath> {
    untag(d, tag::KEYPATH)?;
    let mut p = Keypath::default();
    map_entries(d, |d, k| {
        match k {
            1 => {
                let n = d
                    .array()?
                    .ok_or(UrError::Unsupported("an indefinite path".into()))?;
                let mut i = 0;
                while i < n {
                    // A component is an index then its hardened flag; a wildcard is an empty array.
                    if d.datatype()? == Type::Array {
                        return Err(UrError::Unsupported("a wildcard path".into()));
                    }
                    let index = d.u32()?;
                    let hardened = d.bool()?;
                    p.components
                        .push(index | if hardened { HARDENED } else { 0 });
                    i += 2;
                }
            }
            2 => p.source_fingerprint = Some(d.u32()?),
            3 => p.depth = Some(d.u8()?),
            _ => d.skip()?,
        }
        Ok(())
    })?;
    Ok(p)
}

fn read_coininfo(d: &mut Decoder) -> Result<CoinInfo> {
    untag(d, tag::COININFO)?;
    let mut c = CoinInfo {
        coin_type: 0,
        network: 0,
    };
    map_entries(d, |d, k| {
        match k {
            1 => c.coin_type = d.u32()?,
            2 => c.network = d.i32()?,
            _ => d.skip()?,
        }
        Ok(())
    })?;
    Ok(c)
}

pub fn read_hdkey(d: &mut Decoder) -> Result<HdKey> {
    untag(d, tag::HDKEY)?;
    let mut h = HdKey::default();
    let mut private = false;
    map_entries(d, |d, k| {
        match k {
            2 => private = d.bool()?,
            3 => h.key = d.bytes()?.to_vec(),
            4 => h.chain_code = Some(d.bytes()?.to_vec()),
            5 => h.use_info = Some(read_coininfo(d)?),
            6 => h.origin = Some(read_keypath(d)?),
            7 => h.children = Some(read_keypath(d)?),
            8 => h.parent_fingerprint = Some(d.u32()?),
            9 => h.name = Some(d.str()?.to_string()),
            _ => d.skip()?,
        }
        Ok(())
    })?;
    if private {
        return Err(UrError::Unsupported("a private key".into()));
    }
    if h.key.len() != 33 {
        return Err(UrError::Missing("a 33-byte public key"));
    }
    Ok(h)
}

/// An output descriptor: script tags around a key.
fn read_output(d: &mut Decoder) -> Result<Output> {
    let mut tags = Vec::new();
    while d.datatype()? == Type::Tag {
        let t = d.tag()?.as_u64();
        if t == tag::HDKEY || t == tag::ECKEY {
            if t == tag::ECKEY {
                return Err(UrError::Unsupported("a bare key without derivation".into()));
            }
            let key = read_hdkey(d)?;
            let script = match tags.as_slice() {
                [tag::WPKH] => Script::Wpkh,
                [tag::TR] => Script::Tr,
                [tag::SH, tag::WPKH] => Script::ShWpkh,
                [tag::PKH] => Script::Pkh,
                _ => Script::Other,
            };
            return Ok(Output { script, key });
        }
        if t != tag::OUTPUT {
            tags.push(t);
        }
    }
    // Multisig and other expressions have no single key; skip them.
    d.skip()?;
    Ok(Output {
        script: Script::Other,
        key: HdKey::default(),
    })
}

fn read_account(d: &mut Decoder) -> Result<Accounts> {
    let mut a = Accounts {
        master_fingerprint: 0,
        outputs: Vec::new(),
        keys: Vec::new(),
        device: None,
    };
    let mut fp = None;
    map_entries(d, |d, k| {
        match k {
            1 => fp = Some(d.u32()?),
            2 => {
                let n = d
                    .array()?
                    .ok_or(UrError::Unsupported("an indefinite list".into()))?;
                for _ in 0..n {
                    let o = read_output(d)?;
                    if o.script != Script::Other {
                        a.outputs.push(o);
                    }
                }
            }
            _ => d.skip()?,
        }
        Ok(())
    })?;
    a.master_fingerprint = fp.ok_or(UrError::Missing("the master fingerprint"))?;
    Ok(a)
}

fn read_multi_accounts(d: &mut Decoder) -> Result<Accounts> {
    let mut a = Accounts {
        master_fingerprint: 0,
        outputs: Vec::new(),
        keys: Vec::new(),
        device: None,
    };
    let mut fp = None;
    map_entries(d, |d, k| {
        match k {
            1 => fp = Some(d.u32()?),
            2 => {
                let n = d
                    .array()?
                    .ok_or(UrError::Unsupported("an indefinite list".into()))?;
                for _ in 0..n {
                    a.keys.push(read_hdkey(d)?);
                }
            }
            3 => a.device = Some(d.str()?.to_string()),
            _ => d.skip()?,
        }
        Ok(())
    })?;
    a.master_fingerprint = fp.ok_or(UrError::Missing("the master fingerprint"))?;
    Ok(a)
}

/// Accounts from any of the types a wallet shows them as.
pub fn accounts(ur_type: &str, cbor: &[u8]) -> Result<Accounts> {
    let mut d = Decoder::new(cbor);
    match canonical(ur_type) {
        "crypto-account" => read_account(&mut d),
        "crypto-multi-accounts" => {
            untag(&mut d, tag::MULTI_ACCOUNTS)?;
            read_multi_accounts(&mut d)
        }
        "crypto-output" => {
            let o = read_output(&mut d)?;
            let fp = o
                .key
                .origin
                .as_ref()
                .and_then(|p| p.source_fingerprint)
                .ok_or(UrError::Missing("the key's origin"))?;
            Ok(Accounts {
                master_fingerprint: fp,
                outputs: vec![o],
                keys: Vec::new(),
                device: None,
            })
        }
        "crypto-hdkey" => {
            let k = read_hdkey(&mut d)?;
            let fp = k
                .origin
                .as_ref()
                .and_then(|p| p.source_fingerprint)
                .ok_or(UrError::Missing("the key's origin"))?;
            Ok(Accounts {
                master_fingerprint: fp,
                outputs: Vec::new(),
                keys: vec![k],
                device: None,
            })
        }
        other => Err(UrError::Unsupported(format!(
            "ur:{other} holds no accounts"
        ))),
    }
}

/// `crypto-psbt`'s PSBT.
pub fn read_psbt(cbor: &[u8]) -> Result<Vec<u8>> {
    Ok(Decoder::new(cbor).bytes()?.to_vec())
}

pub fn read_eth_signature(cbor: &[u8]) -> Result<EthSignature> {
    let mut d = Decoder::new(cbor);
    let mut s = EthSignature {
        request_id: None,
        signature: Vec::new(),
    };
    map_entries(&mut d, |d, k| {
        match k {
            1 => {
                untag(d, tag::UUID)?;
                s.request_id = d.bytes()?.try_into().ok();
            }
            2 => s.signature = d.bytes()?.to_vec(),
            _ => d.skip()?,
        }
        Ok(())
    })?;
    if s.signature.len() < 65 {
        return Err(UrError::Missing("a 65-byte signature"));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &[u32]) -> Keypath {
        Keypath {
            components: p.to_vec(),
            source_fingerprint: Some(0x73c5da0a),
            depth: None,
        }
    }

    #[test]
    fn eth_sign_request_is_written_in_key_order() {
        let r = EthSignRequest {
            request_id: [0x11; 16],
            sign_data: vec![0xde, 0xad],
            data_type: EthDataType::TypedTransaction,
            chain_id: Some(11155111),
            path: path(&[44 | HARDENED, 60 | HARDENED, HARDENED, 0, 0]),
            address: None,
            origin: Some("Logos".into()),
        };
        let cbor = eth_sign_request(&r).unwrap();
        let mut d = Decoder::new(&cbor);
        assert_eq!(d.map().unwrap(), Some(6));
        let mut keys = Vec::new();
        for _ in 0..6 {
            keys.push(d.u64().unwrap());
            d.skip().unwrap();
        }
        assert_eq!(keys, vec![1, 2, 3, 4, 5, 7]);
    }

    #[test]
    fn keypaths_round_trip() {
        let p = path(&[84 | HARDENED, 1 | HARDENED, HARDENED]);
        let mut out = Vec::new();
        write_keypath(&mut Encoder::new(&mut out), &p).unwrap();
        assert_eq!(read_keypath(&mut Decoder::new(&out)).unwrap(), p);
    }

    #[test]
    fn eth_signatures_are_read() {
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.map(2).unwrap();
        e.u8(1)
            .unwrap()
            .tag(Tag::new(tag::UUID))
            .unwrap()
            .bytes(&[7; 16])
            .unwrap();
        e.u8(2).unwrap().bytes(&[9; 65]).unwrap();
        let s = read_eth_signature(&out).unwrap();
        assert_eq!(s.request_id, Some([7; 16]));
        assert_eq!(s.signature.len(), 65);
    }

    #[test]
    fn requests_and_accounts_round_trip() {
        let r = EthSignRequest {
            request_id: [3; 16],
            sign_data: vec![1, 2, 3],
            data_type: EthDataType::RawBytes,
            chain_id: Some(1),
            path: path(&[44 | HARDENED, 60 | HARDENED, HARDENED, 0, 0]),
            address: Some([5; 20]),
            origin: None,
        };
        assert_eq!(
            read_eth_sign_request(&eth_sign_request(&r).unwrap()).unwrap(),
            r
        );
        let key = HdKey {
            key: vec![2; 33],
            chain_code: Some(vec![9; 32]),
            use_info: Some(CoinInfo {
                coin_type: 0,
                network: 1,
            }),
            origin: Some(path(&[84 | HARDENED, 1 | HARDENED, HARDENED])),
            children: None,
            parent_fingerprint: Some(7),
            name: Some("Shell".into()),
        };
        let a = Accounts {
            master_fingerprint: 0x73c5da0a,
            outputs: vec![],
            keys: vec![key],
            device: Some("Keycard Shell".into()),
        };
        let mut cbor = Vec::new();
        Encoder::new(&mut cbor)
            .tag(Tag::new(tag::MULTI_ACCOUNTS))
            .unwrap();
        cbor.extend(multi_accounts(&a).unwrap());
        assert_eq!(accounts("crypto-multi-accounts", &cbor).unwrap(), a);
    }

    #[test]
    fn psbt_is_a_byte_string() {
        assert_eq!(read_psbt(&psbt(b"psbt\xff")).unwrap(), b"psbt\xff");
    }

    #[test]
    fn new_names_read_as_old_ones() {
        assert_eq!(canonical("psbt"), "crypto-psbt");
        assert_eq!(canonical("account-descriptor"), "crypto-account");
        assert_eq!(canonical("crypto-psbt"), "crypto-psbt");
    }
}
