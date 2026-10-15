//! The QR signer behind `logos.signer/1`. A request is written as animated UR codes and shown
//! through the scanner; the wallet's answer is read back through the same session's camera. Only
//! the answer's type is taken, and the manager checks every signature, as for any device.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::ecdsa;
use bitcoin::Psbt;
use logos_signer_interface::jobs::JobTable;
use logos_signer_interface::{
    psbt as shared, Account, Collects, ErrorCode, Family, JobState, JobStatus, Payload,
    RequestKind, Result, SignRequest, Signature, Signer, SignerError, SignerInfo,
};
use serde::{Deserialize, Serialize};

use crate::accounts::{self, Offered};
use crate::parts::{self, Assembler, Progress};
use crate::profile::{self, Profile};
use crate::store::Store;
use crate::ur::{self, EthDataType, EthSignRequest, Keypath};

fn err(code: ErrorCode, m: impl Into<String>) -> SignerError {
    SignerError::new(code, m)
}

/// The scanner module, as the signer sees it.
pub trait Scanner: Send + Sync {
    /// Start a session: show `show`'s parts, read codes when `scan`. Answers its session and token.
    fn start(
        &self,
        title: &str,
        show: Option<Show<'_>>,
        scan: bool,
        hint: &str,
    ) -> std::result::Result<(String, String), String>;
    fn poll(&self, session: &str, token: &str) -> std::result::Result<ScanPoll, String>;
    fn progress(&self, session: &str, token: &str, received: usize, expected: usize);
    fn stop(&self, session: &str, token: &str);
}

#[derive(Debug, Clone, Copy)]
pub struct Show<'a> {
    pub parts: &'a [String],
    pub interval_ms: u64,
    pub max_version: u8,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ScanPoll {
    pub state: String,
    #[serde(default)]
    pub texts: Vec<String>,
    #[serde(default)]
    pub error: Option<ScanProblem>,
    /// The largest code a terminal showing them has room for.
    #[serde(default)]
    pub presenter_max_version: Option<u8>,
}

/// A message to show as UR parts, sized by the wallet's profile.
#[derive(Clone, Copy)]
struct Request<'a> {
    ur_type: &'a str,
    cbor: &'a [u8],
    profile: &'a Profile,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ScanProblem {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub message: String,
}

pub trait Events: Send + Sync {
    fn sign_progress(&self, job: &str, state: JobState);
    fn accounts_changed(&self, count: usize);
}

/// `scan_accounts`'s parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    pub families: Vec<Family>,
    #[serde(default)]
    pub label: Option<String>,
    /// Which wallet; read from the code where it says, else `generic`.
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Added {
    /// `scanning`, `done` or `failed`.
    pub state: &'static str,
    pub accounts: Vec<Account>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

enum Work {
    Psbt {
        psbt: Psbt,
        fingerprint: [u8; 4],
    },
    Evm {
        request: EthSignRequest,
        key: String,
    },
}

impl Work {
    fn of(o: &Offered, payload: &Payload, p: &Profile) -> Result<Work> {
        let path = o
            .account
            .path
            .as_deref()
            .and_then(accounts::parse_path)
            .ok_or_else(|| err(ErrorCode::Internal, "an account without its path"))?;
        match (o.account.family, payload) {
            (Family::Bitcoin | Family::BitcoinTaproot, Payload::BtcPsbt { psbt, .. }) => {
                let mut psbt: Psbt = psbt
                    .parse()
                    .map_err(|e| err(ErrorCode::Invalid, format!("the PSBT: {e}")))?;
                if psbt.inputs.len() > p.max_inputs || psbt.outputs.len() > p.max_outputs {
                    return Err(err(
                        ErrorCode::Unsupported,
                        format!(
                            "a {} signs at most {} inputs and {} outputs",
                            p.label, p.max_inputs, p.max_outputs
                        ),
                    ));
                }
                shared::check_inputs(&psbt, o.account.family, o.fingerprint, &path)?;
                shared::name_internal_keys(&mut psbt, o.fingerprint)?;
                Ok(Work::Psbt {
                    psbt,
                    fingerprint: o.fingerprint,
                })
            }
            (Family::Evm, Payload::EvmTransaction { chain_id, tx }) => {
                if *chain_id > p.max_chain_id {
                    return Err(err(
                        ErrorCode::Unsupported,
                        format!("a {} takes chain ids up to {}", p.label, p.max_chain_id),
                    ));
                }
                let bytes = hex::decode(tx.trim_start_matches("0x"))
                    .map_err(|e| err(ErrorCode::Invalid, format!("the transaction: {e}")))?;
                let data_type = match bytes.first() {
                    Some(b) if *b >= 0xc0 => EthDataType::Transaction,
                    Some(_) => EthDataType::TypedTransaction,
                    None => return Err(err(ErrorCode::Invalid, "an empty transaction")),
                };
                Ok(evm(o, data_type, bytes, Some(*chain_id as i64), path))
            }
            (Family::Evm, Payload::EvmMessage { message }) => {
                let bytes = hex::decode(message.trim_start_matches("0x"))
                    .map_err(|e| err(ErrorCode::Invalid, format!("the message: {e}")))?;
                Ok(evm(o, EthDataType::RawBytes, bytes, None, path))
            }
            (Family::Evm, Payload::EvmTypedData { typed_data }) => {
                let bytes = serde_json::to_vec(typed_data)
                    .map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
                Ok(evm(o, EthDataType::TypedData, bytes, None, path))
            }
            _ => Err(err(
                ErrorCode::Unsupported,
                "a request this account's wallet doesn't sign",
            )),
        }
    }
}

fn evm(
    o: &Offered,
    data_type: EthDataType,
    sign_data: Vec<u8>,
    chain_id: Option<i64>,
    path: Vec<u32>,
) -> Work {
    let mut request_id = [0u8; 16];
    getrandom::fill(&mut request_id).expect("the system's random source");
    // Version 4, as a UUID's bits say.
    request_id[6] = (request_id[6] & 0x0f) | 0x40;
    request_id[8] = (request_id[8] & 0x3f) | 0x80;
    let address = o
        .account
        .address
        .as_deref()
        .and_then(|a| hex::decode(a.trim_start_matches("0x")).ok())
        .and_then(|a| a.try_into().ok());
    Work::Evm {
        request: EthSignRequest {
            request_id,
            sign_data,
            data_type,
            chain_id,
            path: Keypath {
                components: path,
                source_fingerprint: Some(u32::from_be_bytes(o.fingerprint)),
                depth: None,
            },
            address,
            origin: Some("Logos".into()),
        },
        key: o.key.clone(),
    }
}

/// The recovery id an `eth-signature`'s v stands for, whichever way the wallet wrote it: 0 or 1,
/// 27 or 28, or EIP-155's chain id times two plus 35, whole or as its low byte. Then S made low.
fn evm_signature(sig: &[u8], key: &str) -> Result<Signature> {
    let bad = || err(ErrorCode::Invalid, "the wallet's signature is malformed");
    let (rs, v) = sig.split_at_checked(64).ok_or_else(bad)?;
    let last = *v.last().ok_or_else(bad)?;
    let mut id = if v.len() == 1 && last <= 1 {
        last
    } else {
        (last & 1) ^ 1
    };
    let mut s = ecdsa::Signature::from_compact(rs).map_err(|_| bad())?;
    let before = s;
    s.normalize_s();
    if s != before {
        id ^= 1;
    }
    Ok(Signature {
        item: 0,
        signature: hex::encode(s.serialize_compact()),
        recovery_id: Some(id),
        pubkey: key.to_string(),
    })
}

struct Shared {
    scanner: Arc<dyn Scanner>,
    store: Mutex<Store>,
    jobs: Mutex<JobTable>,
    adds: Mutex<HashMap<String, Added>>,
    events: Box<dyn Events>,
    seq: AtomicU64,
    busy: AtomicBool,
    patience: Duration,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a session can end with, besides an answer.
enum Ended {
    Answer(String, Vec<u8>),
    Cancelled,
}

#[derive(Clone)]
pub struct QrSigner {
    shared: Arc<Shared>,
}

/// How long a person may take to scan, confirm on the wallet and show its answer.
pub const PATIENCE: Duration = Duration::from_secs(600);

impl QrSigner {
    pub fn new(scanner: Arc<dyn Scanner>, store: Store, events: Box<dyn Events>) -> Self {
        Self::with_patience(scanner, store, events, PATIENCE)
    }

    pub fn with_patience(
        scanner: Arc<dyn Scanner>,
        store: Store,
        events: Box<dyn Events>,
        patience: Duration,
    ) -> Self {
        QrSigner {
            shared: Arc::new(Shared {
                scanner,
                store: Mutex::new(store),
                jobs: Mutex::new(JobTable::new()),
                adds: Mutex::new(HashMap::new()),
                events,
                seq: AtomicU64::new(0),
                busy: AtomicBool::new(false),
                patience,
            }),
        }
    }

    /// Silent: it runs while the module loads, before the host listens for its events, and callers
    /// read the accounts when they first ask.
    pub fn set_store(&self, store: Store) {
        *lock(&self.shared.store) = store;
    }

    pub fn offered(&self) -> Vec<Offered> {
        lock(&self.shared.store).list().to_vec()
    }

    /// Read a wallet's account code and offer the accounts of these families.
    pub fn scan_accounts(&self, req: ScanRequest) -> Result<String> {
        if req.families.is_empty() {
            return Err(err(ErrorCode::Invalid, "no families asked for"));
        }
        if self.shared.busy.swap(true, Ordering::SeqCst) {
            return Err(err(
                ErrorCode::Busy,
                "the QR signer is already reading a code",
            ));
        }
        let id = format!("add_{}", self.shared.seq.fetch_add(1, Ordering::SeqCst) + 1);
        lock(&self.shared.adds).insert(
            id.clone(),
            Added {
                state: "scanning",
                accounts: Vec::new(),
                error: None,
            },
        );
        let shared = self.shared.clone();
        let job = id.clone();
        std::thread::spawn(move || {
            let outcome = shared.add(&req);
            shared.busy.store(false, Ordering::SeqCst);
            let added = match outcome {
                Ok(accounts) => Added {
                    state: "done",
                    accounts,
                    error: None,
                },
                Err(e) => Added {
                    state: "failed",
                    accounts: Vec::new(),
                    error: Some(e.message),
                },
            };
            lock(&shared.adds).insert(job, added);
        });
        Ok(id)
    }

    pub fn add_status(&self, job: &str) -> Option<Added> {
        lock(&self.shared.adds).get(job).cloned()
    }

    pub fn remove_account(&self, id: &str) -> Result<bool> {
        let (removed, count) = {
            let mut store = lock(&self.shared.store);
            let removed = store
                .remove(id)
                .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
            (removed, store.list().len())
        };
        if removed {
            self.shared.events.accounts_changed(count);
        }
        Ok(removed)
    }

    /// Name an account for apps; a blank name clears it. Whether it changed.
    pub fn rename_account(&self, id: &str, label: &str) -> Result<bool> {
        let label = Some(label.trim()).filter(|l| !l.is_empty());
        if label.as_ref().is_some_and(|l| l.chars().count() > 80) {
            return Err(err(ErrorCode::Invalid, "a name is at most 80 characters"));
        }
        let (renamed, count) = {
            let mut store = lock(&self.shared.store);
            if store.find(id).is_none() {
                return Err(err(ErrorCode::UnknownAccount, format!("no account {id}")));
            }
            let renamed = store
                .rename(id, label.map(str::to_string))
                .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
            (renamed, store.list().len())
        };
        if renamed {
            self.shared.events.accounts_changed(count);
        }
        Ok(renamed)
    }
}

impl Shared {
    /// Run one scanner session until the wallet's answer is complete.
    fn session(
        &self,
        title: &str,
        show: Option<Request<'_>>,
        hint: &str,
        expect: &[&'static str],
        job: Option<&str>,
    ) -> Result<Ended> {
        let mut version = show.map_or(0, |r| r.profile.max_version);
        let mut parts = match show {
            Some(r) => parts::parts(r.ur_type, r.cbor, r.profile.fragment)
                .map_err(|e| err(ErrorCode::Internal, e))?,
            None => Vec::new(),
        };
        let begin = |parts: &[String], version: u8| {
            let show = show.map(|r| Show {
                parts,
                interval_ms: r.profile.interval_ms,
                max_version: version,
            });
            self.scanner
                .start(title, show, true, hint)
                .map_err(|e| err(ErrorCode::Unavailable, e))
        };
        let (mut session, mut token) = begin(&parts, version)?;
        let started = Instant::now();
        let mut assembler = Assembler::expecting(expect);
        let mut shown = Progress {
            received: 0,
            expected: 0,
        };
        let outcome = loop {
            if job.is_some_and(|j| {
                lock(&self.jobs)
                    .status(j)
                    .is_ok_and(|s| s.state == JobState::Cancelled)
            }) {
                break Ok(Ended::Cancelled);
            }
            if started.elapsed() > self.patience {
                break Err(err(
                    ErrorCode::Unavailable,
                    "no answer from the wallet in time",
                ));
            }
            let poll = match self.scanner.poll(&session, &token) {
                Ok(p) => p,
                Err(e) => break Err(err(ErrorCode::Unavailable, e)),
            };
            for text in &poll.texts {
                if let Some(p) = assembler.receive(text) {
                    if p != shown {
                        shown = p;
                        self.scanner
                            .progress(&session, &token, p.received, p.expected);
                    }
                }
            }
            if let Some((t, cbor)) = assembler.done() {
                break Ok(Ended::Answer(t, cbor));
            }
            // A terminal shows the codes and they don't fit it: smaller parts, in a new session.
            if let (Some(r), Some(v)) = (show, poll.presenter_max_version) {
                if v < version {
                    version = v;
                    if !parts::fit(&parts, v) {
                        if let Some(smaller) =
                            parts::parts_within(r.ur_type, r.cbor, r.profile.fragment, v)
                        {
                            self.scanner.stop(&session, &token);
                            parts = smaller;
                            match begin(&parts, v) {
                                Ok(s) => (session, token) = s,
                                Err(e) => break Err(e),
                            }
                            continue;
                        }
                    }
                }
            }
            match poll.state.as_str() {
                "cancelled" => {
                    break Err(err(ErrorCode::Refused, "cancelled in the Logos QR window"))
                }
                "failed" | "stopped" => {
                    let e = poll
                        .error
                        .map(|p| p.message)
                        .unwrap_or_else(|| "the QR scanner stopped".into());
                    break Err(err(ErrorCode::Unavailable, e));
                }
                _ => {}
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        self.scanner.stop(&session, &token);
        outcome
    }

    fn add(&self, req: &ScanRequest) -> Result<Vec<Account>> {
        let expect = [
            "crypto-account",
            "crypto-multi-accounts",
            "crypto-hdkey",
            "crypto-output",
        ];
        let hint = "Show your wallet's account code (on a Keycard Shell: Connect software wallet)";
        let Ended::Answer(t, cbor) = self.session("Add a QR wallet", None, hint, &expect, None)?
        else {
            return Err(err(ErrorCode::Refused, "cancelled"));
        };
        let found = ur::accounts(&t, &cbor).map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
        let profile = req
            .profile
            .clone()
            .or_else(|| profile::for_device(found.device.as_deref()).map(str::to_string))
            .unwrap_or_else(|| profile::GENERIC.name.to_string());
        let made = accounts::offered(&found, &req.families, &profile, req.label.as_deref())
            .map_err(|e| err(ErrorCode::Invalid, e))?;
        let count = {
            let mut store = lock(&self.store);
            store
                .put(made.clone())
                .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
            store.list().len()
        };
        self.events.accounts_changed(count);
        Ok(made.into_iter().map(|o| o.account).collect())
    }

    fn run(&self, job: &str, o: &Offered, work: Work) -> Result<Vec<Signature>> {
        let p = profile::get(&o.profile);
        let (ur_type, cbor, expect) = match &work {
            Work::Psbt { psbt, .. } => ("crypto-psbt", ur::psbt(&psbt.serialize()), "crypto-psbt"),
            Work::Evm { request, .. } => (
                "eth-sign-request",
                ur::eth_sign_request(request)
                    .map_err(|e| err(ErrorCode::Internal, e.to_string()))?,
                "eth-signature",
            ),
        };
        let show = Request {
            ur_type,
            cbor: &cbor,
            profile: &p,
        };
        // The scanner words each step itself: the request with the camera off, then the answer.
        let Ended::Answer(t, answer) = self.session(
            "Sign with your QR wallet",
            Some(show),
            "",
            &[expect],
            Some(job),
        )?
        else {
            return Err(err(ErrorCode::Refused, "cancelled"));
        };
        debug_assert_eq!(t, expect);
        match work {
            Work::Psbt { psbt, fingerprint } => {
                let bytes =
                    ur::read_psbt(&answer).map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
                let signed = Psbt::deserialize(&bytes)
                    .map_err(|e| err(ErrorCode::Invalid, format!("the PSBT it returned: {e}")))?;
                if signed.unsigned_tx.compute_txid() != psbt.unsigned_tx.compute_txid() {
                    return Err(err(
                        ErrorCode::Invalid,
                        "the wallet answered another transaction",
                    ));
                }
                Ok(shared::signatures(&signed, fingerprint))
            }
            Work::Evm { request, key } => {
                let s = ur::read_eth_signature(&answer)
                    .map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
                if s.request_id.is_some_and(|id| id != request.request_id) {
                    return Err(err(
                        ErrorCode::Invalid,
                        "the wallet answered another request",
                    ));
                }
                Ok(vec![evm_signature(&s.signature, &key)?])
            }
        }
    }
}

impl Signer for QrSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            interface: logos_signer_interface::INTERFACE.into(),
            kind: "qr".into(),
            model: "QR wallet".into(),
            families: vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
            request_kinds: vec![
                RequestKind::EvmTransaction,
                RequestKind::EvmMessage,
                RequestKind::EvmTypedData,
                RequestKind::BtcPsbt,
            ],
            shows_request: true,
            collects: Collects::Nothing,
        }
    }

    fn accounts(&mut self) -> Result<Vec<Account>> {
        Ok(lock(&self.shared.store)
            .list()
            .iter()
            .map(|o| o.account.clone())
            .collect())
    }

    fn sign(&mut self, request: SignRequest) -> Result<String> {
        let offered = lock(&self.shared.store)
            .find(&request.account)
            .cloned()
            .ok_or_else(|| {
                err(
                    ErrorCode::UnknownAccount,
                    format!("no account {}", request.account),
                )
            })?;
        let work = Work::of(&offered, &request.payload, &profile::get(&offered.profile))?;
        if self.shared.busy.swap(true, Ordering::SeqCst) {
            return Err(err(
                ErrorCode::Busy,
                "the QR signer is already reading a code",
            ));
        }
        let job = lock(&self.shared.jobs).start(JobState::ConfirmOnDevice);
        self.shared
            .events
            .sign_progress(&job, JobState::ConfirmOnDevice);
        let shared = self.shared.clone();
        let id = job.clone();
        std::thread::spawn(move || {
            let outcome = shared.run(&id, &offered, work);
            shared.busy.store(false, Ordering::SeqCst);
            let state = {
                let mut jobs = lock(&shared.jobs);
                let _ = jobs.finish(&id, outcome);
                jobs.status(&id)
                    .map(|s| s.state)
                    .unwrap_or(JobState::Failed)
            };
            shared.events.sign_progress(&id, state);
        });
        Ok(job)
    }

    fn status(&mut self, job: &str) -> Result<JobStatus> {
        lock(&self.shared.jobs).status(job)
    }

    fn result(&mut self, job: &str) -> Result<Vec<Signature>> {
        lock(&self.shared.jobs).result(job)
    }

    fn cancel(&mut self, job: &str) -> Result<()> {
        lock(&self.shared.jobs).cancel(job)?;
        self.shared.events.sign_progress(job, JobState::Cancelled);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v_in_every_form_gives_the_recovery_id() {
        let key = "02aa";
        let mut sig = vec![1u8; 64];
        sig[32] = 0x01; // a low S
        for (v, id) in [
            (0u8, 0u8),
            (1, 1),
            (27, 0),
            (28, 1),
            (37, 0),
            (38, 1),
            (0x45, 0),
        ] {
            let mut s = sig.clone();
            s.push(v);
            assert_eq!(
                evm_signature(&s, key).unwrap().recovery_id,
                Some(id),
                "v {v}"
            );
        }
        // EIP-155 on a chain id too big for one byte: 11155111 * 2 + 35 + 1.
        let mut s = sig.clone();
        s.extend_from_slice(&(11155111u32 * 2 + 36).to_be_bytes());
        assert_eq!(evm_signature(&s, key).unwrap().recovery_id, Some(1));
        assert!(evm_signature(&sig[..60], key).is_err());
    }
}
