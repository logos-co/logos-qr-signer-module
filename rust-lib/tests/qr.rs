//! The QR signer end to end against the emulated wallet, with the scanner in process: codes pass as
//! text, so this covers the signer and the UR types; the helper and its decoders have their own.

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::Psbt;
use logos_signer_interface::conformance::{self, Fixture};
use logos_signer_interface::mock::MockSigner;
use logos_signer_interface::{unlock, Account, ErrorCode, Family, JobState, Payload, SignRequest};
use logos_signer_interface::{Signer, SignerError, UnlockKey, UnlockKeyRequest};
use qr_signer_module::emulator::Emulator;
use qr_signer_module::parts;
use qr_signer_module::signer::{Events, QrSigner, ScanPoll, ScanRequest, Scanner, Show};
use qr_signer_module::store::Store;

/// Hands the emulator what the window would show, and the camera what the emulator holds up.
struct InProcess {
    emu: Emulator,
    sessions: Mutex<HashMap<String, Vec<String>>>,
    stopped: Mutex<u32>,
    /// A terminal presenting the codes, with room for codes up to this version; it can be resized.
    presenter: Mutex<Option<u8>>,
    /// Each start's largest version allowed.
    shown: Mutex<Vec<u8>>,
    /// The wallet's account code is out of the camera's sight.
    hidden: AtomicBool,
    /// The wallet reads requests and never answers, as a person who walks away.
    mute: AtomicBool,
}

impl Scanner for InProcess {
    fn start(
        &self,
        _: &str,
        show: Option<Show<'_>>,
        _: bool,
        _: &str,
    ) -> Result<(String, String), String> {
        let texts = match show {
            // Codes too large for the terminal never reach the wallet.
            Some(s)
                if self
                    .presenter
                    .lock()
                    .unwrap()
                    .is_some_and(|v| !parts::fit(s.parts, v)) =>
            {
                self.shown.lock().unwrap().push(s.max_version);
                Vec::new()
            }
            Some(s) => {
                self.shown.lock().unwrap().push(s.max_version);
                self.emu
                    .answer(s.parts)
                    .filter(|_| !self.emu.silent && !self.mute.load(Ordering::SeqCst))
                    .unwrap_or_default()
            }
            None if self.hidden.load(Ordering::SeqCst) => Vec::new(),
            None => self.emu.accounts_code(),
        };
        let mut sessions = self.sessions.lock().unwrap();
        let id = format!("s{}", sessions.len());
        sessions.insert(id.clone(), texts);
        Ok((id, "t".into()))
    }

    fn poll(&self, session: &str, _: &str) -> Result<ScanPoll, String> {
        let texts = self
            .sessions
            .lock()
            .unwrap()
            .get_mut(session)
            .map(std::mem::take)
            .unwrap_or_default();
        Ok(ScanPoll {
            state: "running".into(),
            texts,
            error: None,
            presenter_max_version: *self.presenter.lock().unwrap(),
        })
    }

    fn progress(&self, _: &str, _: &str, _: usize, _: usize) {}

    fn stop(&self, session: &str, _: &str) {
        self.sessions.lock().unwrap().remove(session);
        *self.stopped.lock().unwrap() += 1;
    }
}

/// A seed the signer registered with the manager: its name, its unlock key, the wallet's name.
type Enrolled = (String, Option<[u8; 33]>, String);

/// Hears the seeds the signer would register with the manager.
#[derive(Clone, Default)]
struct Heard(Arc<Mutex<Vec<Enrolled>>>);

impl Events for Heard {
    fn sign_progress(&self, _: &str, _: JobState) {}
    fn accounts_changed(&self, _: usize) {}
    fn seed_added(&self, seed: &str, unlock_key: Option<[u8; 33]>, name: &str) {
        self.0
            .lock()
            .unwrap()
            .push((seed.into(), unlock_key, name.into()));
    }
}

struct Rig {
    signer: QrSigner,
    scanner: Arc<InProcess>,
    heard: Heard,
}

fn rig(emu: Emulator, store: Store, patience: Duration) -> Rig {
    let scanner = Arc::new(InProcess {
        emu,
        sessions: Mutex::new(HashMap::new()),
        stopped: Mutex::new(0),
        presenter: Mutex::new(None),
        shown: Mutex::new(Vec::new()),
        hidden: AtomicBool::new(false),
        mute: AtomicBool::new(false),
    });
    let heard = Heard::default();
    let signer = QrSigner::with_patience(scanner.clone(), store, Box::new(heard.clone()), patience);
    Rig {
        signer,
        scanner,
        heard,
    }
}

fn signer(emu: Emulator) -> (QrSigner, Arc<InProcess>) {
    let r = rig(emu, Store::new(), Duration::from_secs(20));
    (r.signer, r.scanner)
}

/// A wallet whose code names no Keycard Shell: "Another QR wallet".
fn keystone() -> Emulator {
    Emulator {
        device: "Keystone 3 Pro (emulated)".into(),
        ..Emulator::default()
    }
}

/// A directory of its own for one test's accounts.json, emptied.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qr-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn all_families() -> ScanRequest {
    ScanRequest {
        families: vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
        label: None,
        profile: None,
    }
}

/// A scan's state once it is no longer scanning.
fn scanned(s: &QrSigner, job: &str) -> &'static str {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let state = s.add_status(job).unwrap().state;
        if state != "scanning" {
            return state;
        }
        assert!(Instant::now() < until, "still scanning");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn scan_all(s: &QrSigner) {
    let job = s.scan_accounts(all_families()).unwrap();
    let state = scanned(s, &job);
    let added = s.add_status(&job).unwrap();
    assert_eq!(state, "done", "{:?}", added.error);
    assert_eq!(added.accounts.len(), 3);
}

fn wait(s: &mut QrSigner, job: &str) -> JobState {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let st = s.status(job).unwrap().state;
        if st.is_final() || Instant::now() > until {
            return st;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The manager's `unlock_key`, to its end.
fn unlock_key(s: &mut QrSigner, seed: &str, index: u32) -> Result<UnlockKey, SignerError> {
    let job = s.unlock_key(UnlockKeyRequest {
        seed: seed.into(),
        index,
        secret: None,
    })?;
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let st = s.unlock_key_status(&job).unwrap();
        if st.state == JobState::Done {
            return s.unlock_key_result(&job);
        }
        if st.state.is_final() {
            return Err(st.error.unwrap());
        }
        assert!(Instant::now() < until, "the unlock never settled");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The mock signer's unlock key for the same phrase: what every holder of the seed gives.
fn mocks_unlock_key(index: u32) -> String {
    let mut mock = MockSigner::new(Default::default());
    let seed = mock.accounts().unwrap()[0].seed.clone().unwrap();
    let job = mock
        .unlock_key(UnlockKeyRequest {
            seed,
            index,
            secret: None,
        })
        .unwrap();
    mock.unlock_key_result(&job)
        .unwrap()
        .key
        .expose()
        .to_string()
}

fn account(s: &QrSigner, family: Family) -> Account {
    s.offered()
        .into_iter()
        .find(|o| o.account.family == family)
        .unwrap()
        .listed()
}

fn seed_of(s: &QrSigner) -> String {
    hex::encode(s.offered()[0].fingerprint)
}

#[test]
fn accounts_come_from_the_wallets_code() {
    let (mut s, _) = signer(Emulator::default());
    scan_all(&s);
    let offered = s.offered();
    assert!(
        offered.iter().all(|o| o.profile == "keycard_shell"),
        "the code names a Keycard Shell"
    );
    assert_eq!(
        offered[0].account.id,
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    );
    assert!(offered[1].account.id.ends_with("-84-1-0"));
    let listed = s.accounts().unwrap();
    let seed = seed_of(&s);
    assert!(listed.iter().all(|a| a.seed.as_deref() == Some(&*seed)));
    for a in listed.iter().filter(|a| a.family.is_bitcoin()) {
        let xpub = a.xpub.as_deref().unwrap();
        assert!(xpub.starts_with("tpub"));
        unlock::check_xpub(a.key.as_deref().unwrap(), a.family, a.chain, xpub).unwrap();
    }
}

#[test]
fn adding_a_shell_takes_its_seeds_unlock_key_and_registers_the_seed() {
    let r = rig(Emulator::default(), Store::new(), Duration::from_secs(20));
    let job = r.signer.scan_accounts(all_families()).unwrap();
    assert_eq!(scanned(&r.signer, &job), "done");
    assert_eq!(r.signer.add_status(&job).unwrap().unlock_key, Some(true));
    // The account code, then one request and answer for the whole seed.
    assert_eq!(r.scanner.shown.lock().unwrap().len(), 1);
    let heard = r.heard.0.lock().unwrap().clone();
    assert_eq!(heard.len(), 1);
    let (seed, key, name) = &heard[0];
    assert_eq!(seed, &seed_of(&r.signer));
    assert_eq!(
        key.map(hex::encode),
        Some(mocks_unlock_key(0)),
        "the key every holder of the seed gives"
    );
    assert_eq!(name, "Keycard Shell (emulated)");
}

#[test]
fn a_generic_wallet_registers_its_seed_without_a_key() {
    let r = rig(keystone(), Store::new(), Duration::from_secs(20));
    let job = r.signer.scan_accounts(all_families()).unwrap();
    assert_eq!(scanned(&r.signer, &job), "done");
    assert_eq!(r.signer.add_status(&job).unwrap().unlock_key, Some(false));
    assert!(
        r.scanner.shown.lock().unwrap().is_empty(),
        "no request: its wallet can't be relied on to answer one"
    );
    let heard = r.heard.0.lock().unwrap().clone();
    assert_eq!(
        heard,
        vec![(
            seed_of(&r.signer),
            None,
            "Keystone 3 Pro (emulated)".to_string()
        )]
    );
}

#[test]
fn a_wallet_that_doesnt_give_its_key_still_adds() {
    let r = rig(Emulator::default(), Store::new(), Duration::from_secs(1));
    r.scanner.mute.store(true, Ordering::SeqCst);
    let job = r.signer.scan_accounts(all_families()).unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    while r.signer.add_status(&job).unwrap().state == "scanning" {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(20));
    }
    let added = r.signer.add_status(&job).unwrap();
    assert_eq!(
        (added.state, added.unlock_key),
        ("done", Some(false)),
        "{:?}",
        added.error
    );
    assert_eq!(r.heard.0.lock().unwrap()[0].1, None);
}

#[test]
fn a_scan_stops_while_it_asks_for_the_unlock_key() {
    let r = rig(Emulator::default(), Store::new(), Duration::from_secs(20));
    r.scanner.mute.store(true, Ordering::SeqCst);
    let job = r.signer.scan_accounts(all_families()).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while r.signer.add_status(&job).unwrap().step != Some("unlock_key") {
        assert!(Instant::now() < until, "never asked for the key");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(r.signer.cancel_scan(&job));
    assert_eq!(scanned(&r.signer, &job), "cancelled");
    assert!(r.signer.offered().is_empty(), "nothing kept half added");
    assert!(r.heard.0.lock().unwrap().is_empty());
}

#[test]
fn a_seeds_unlock_key_is_the_same_each_time_and_another_at_the_next_index() {
    let (mut s, _) = signer(Emulator::default());
    scan_all(&s);
    let seed = seed_of(&s);
    let first = unlock_key(&mut s, &seed, 0).unwrap();
    unlock::check_unlock_key(first.key.expose()).unwrap();
    assert_eq!(first.key.expose(), mocks_unlock_key(0));
    assert_eq!(unlock_key(&mut s, &seed.to_uppercase(), 0).unwrap(), first);
    let next = unlock_key(&mut s, &seed, 1).unwrap();
    assert_eq!(next.key.expose(), mocks_unlock_key(1));
    assert_ne!(next, first);

    let job = s
        .unlock_key(UnlockKeyRequest {
            seed: seed.clone(),
            index: 0,
            secret: None,
        })
        .unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    while !s.unlock_key_status(&job).unwrap().state.is_final() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(s.unlock_key_result(&job).is_ok());
    assert!(s.unlock_key_result(&job).is_err(), "read once");
}

#[test]
fn only_a_seed_it_holds_unlocks() {
    let (mut s, scanner) = signer(Emulator::default());
    scan_all(&s);
    let shown = scanner.shown.lock().unwrap().len();
    let seed = seed_of(&s);
    assert_eq!(
        unlock_key(&mut s, "00000000", 0).unwrap_err().code,
        ErrorCode::WrongSeed
    );
    assert_eq!(
        unlock_key(&mut s, &seed, 0x8000_0000).unwrap_err().code,
        ErrorCode::Invalid
    );
    assert_eq!(scanner.shown.lock().unwrap().len(), shown, "nothing shown");
}

#[test]
fn an_unlock_is_cancelled_and_leaves_the_scanner_free() {
    let (mut s, scanner) = signer(Emulator::default());
    scan_all(&s);
    let seed = seed_of(&s);
    scanner.mute.store(true, Ordering::SeqCst);
    let before = *scanner.stopped.lock().unwrap();
    let job = s
        .unlock_key(UnlockKeyRequest {
            seed: seed.clone(),
            index: 0,
            secret: None,
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        unlock_key(&mut s, &seed, 0).unwrap_err().code,
        ErrorCode::Busy
    );
    s.cancel_unlock_key(&job).unwrap();
    assert_eq!(
        s.unlock_key_status(&job).unwrap().state,
        JobState::Cancelled
    );
    let until = Instant::now() + Duration::from_secs(5);
    while *scanner.stopped.lock().unwrap() == before {
        assert!(Instant::now() < until, "the session stays open");
        std::thread::sleep(Duration::from_millis(20));
    }
    scanner.mute.store(false, Ordering::SeqCst);
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match unlock_key(&mut s, &seed, 0) {
            Ok(_) => break,
            Err(e) if e.code == ErrorCode::Busy && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(e) => panic!("{e:?}"),
        }
    }
}

#[test]
fn conformance() {
    let (mut s, _) = signer(Emulator::default());
    scan_all(&s);
    // The emulated wallet answers by itself: driving it is only giving it time.
    conformance::run(
        &mut s,
        &Fixture {
            secret: None,
            wrong_secret: None,
        },
        &mut |_, _| std::thread::sleep(Duration::from_millis(100)),
    );
}

#[test]
fn conformance_of_a_generic_wallet() {
    let (mut s, _) = signer(keystone());
    scan_all(&s);
    conformance::run(
        &mut s,
        &Fixture {
            secret: None,
            wrong_secret: None,
        },
        &mut |_, _| std::thread::sleep(Duration::from_millis(100)),
    );
}

#[test]
fn a_request_bringing_another_accounts_xpub_is_refused() {
    let (mut s, scanner) = signer(Emulator::default());
    scan_all(&s);
    let segwit = account(&s, Family::Bitcoin);
    let taproot = account(&s, Family::BitcoinTaproot);
    let shown = scanner.shown.lock().unwrap().len();
    let e = s
        .sign(SignRequest {
            xpub: taproot.xpub.clone(),
            ..psbt_request(&segwit)
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid, "{}", e.message);
    assert!(e.message.contains("not this account's"), "{}", e.message);
    assert_eq!(scanner.shown.lock().unwrap().len(), shown);
    let job = s.sign(psbt_request(&segwit)).unwrap();
    assert_eq!(wait(&mut s, &job), JobState::Done);
}

#[test]
fn nothing_signs_under_the_unlock_keys_purpose() {
    let (mut s, scanner) = signer(Emulator::default());
    scan_all(&s);
    let segwit = account(&s, Family::Bitcoin);
    let shown = scanner.shown.lock().unwrap().len();

    // A PSBT naming a key under the reserved purpose, here a change output's.
    let mut r = psbt_request(&segwit);
    let Payload::BtcPsbt { psbt, .. } = &mut r.payload else {
        unreachable!()
    };
    let mut p = Psbt::from_str(psbt).unwrap();
    let key = *p.inputs[0].bip32_derivation.keys().next().unwrap();
    let fp = Fingerprint::from_str(segwit.fingerprint.as_deref().unwrap()).unwrap();
    p.outputs[0].bip32_derivation.insert(
        key,
        (fp, DerivationPath::from_str("m/1280263247'/0'").unwrap()),
    );
    *psbt = p.to_string();
    let e = s.sign(r).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid, "{}", e.message);
    assert!(e.message.contains("unlock keys' purpose"), "{}", e.message);

    // A row an edited accounts.json moved: under the reserved purpose, or an EVM one off 44'/60'.
    let mut moved = s.offered();
    moved[1].account.path = Some("m/1280263247'/1'/0'".into());
    moved[0].account.path = Some("m/44'/0'/0'/0/0".into());
    let mut store = Store::new();
    store.put(moved.clone()).unwrap();
    s.set_store(store);
    let e = s
        .sign(SignRequest {
            account: moved[0].account.id.clone(),
            payload: Payload::EvmMessage {
                message: hex::encode("hi"),
            },
            secret: None,
            xpub: None,
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid, "{}", e.message);
    assert!(e.message.contains("m/44'/60'"), "{}", e.message);
    let e = s.sign(psbt_request(&segwit)).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid, "{}", e.message);
    assert!(e.message.contains("unlock keys' purpose"), "{}", e.message);
    assert_eq!(scanner.shown.lock().unwrap().len(), shown);
}

#[test]
fn the_origin_names_the_device_model() {
    let (s, _) = signer(keystone());
    scan_all(&s);
    let id = s.offered()[0].account.id.clone();
    let device = &s.account_origins()[&id]["devices"][0];
    assert_eq!(device["name"], "Keystone 3 Pro (emulated)");
    assert_eq!(device["model"], "Keystone 3 Pro (emulated)");
    assert_eq!(device["profile"], "generic");
}

#[cfg(unix)]
#[test]
fn accounts_json_is_its_owners_alone() {
    use std::os::unix::fs::PermissionsExt;
    let d = dir("mode");
    std::fs::create_dir_all(&d).unwrap();
    // A file from before keeps nothing of its old mode.
    std::fs::write(d.join("accounts.json"), "{\"accounts\":[]}").unwrap();
    std::fs::set_permissions(
        d.join("accounts.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let (s, _) = signer(Emulator::default());
    s.set_store(Store::open(&d).unwrap());
    scan_all(&s);
    let mode = std::fs::metadata(d.join("accounts.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn a_cancelled_request_closes_the_session() {
    let (mut s, scanner) = signer(Emulator::default());
    scan_all(&s);
    scanner.mute.store(true, Ordering::SeqCst);
    let before = *scanner.stopped.lock().unwrap();
    let account = s.offered()[0].account.id.clone();
    let job = s
        .sign(SignRequest {
            account,
            payload: Payload::EvmMessage {
                message: hex::encode("hi"),
            },
            secret: None,
            xpub: None,
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        s.scan_accounts(all_families()).unwrap_err().code,
        ErrorCode::Busy,
        "a signature isn't stopped by a scan"
    );
    s.cancel(&job).unwrap();
    assert_eq!(wait(&mut s, &job), JobState::Cancelled);
    let until = Instant::now() + Duration::from_secs(5);
    while *scanner.stopped.lock().unwrap() < before + 1 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        *scanner.stopped.lock().unwrap(),
        before + 1,
        "the request closed its session"
    );
}

#[test]
fn a_scan_stops_when_asked() {
    let (s, scanner) = signer(Emulator::default());
    scanner.hidden.store(true, Ordering::SeqCst);
    let job = s.scan_accounts(all_families()).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(s.cancel_scan(&job));
    assert_eq!(scanned(&s, &job), "cancelled");
    assert!(!s.cancel_scan(&job), "it is over");
    assert_eq!(*scanner.stopped.lock().unwrap(), 1, "its session closed");
}

#[test]
fn a_new_scan_replaces_one_still_waiting() {
    let (s, scanner) = signer(Emulator::default());
    scanner.hidden.store(true, Ordering::SeqCst);
    let first = s.scan_accounts(all_families()).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    scanner.hidden.store(false, Ordering::SeqCst);
    let second = s.scan_accounts(all_families()).unwrap();
    assert_eq!(s.add_status(&first).unwrap().state, "cancelled");
    assert_eq!(scanned(&s, &second), "done");
    assert!(!s.cancel_scan(&first));
}

#[test]
fn accounts_are_named_and_unnamed() {
    let (s, _) = signer(Emulator::default());
    scan_all(&s);
    let id = s.offered()[1].account.id.clone();
    assert!(s.rename_account(&id, "  Savings ").unwrap());
    assert_eq!(s.offered()[1].account.label.as_deref(), Some("Savings"));
    assert!(
        !s.rename_account(&id, "Savings").unwrap(),
        "the same name changes nothing"
    );
    assert!(s.rename_account(&id, " ").unwrap());
    assert_eq!(s.offered()[1].account.label, None);
    assert_eq!(
        s.rename_account(&id, &"x".repeat(81)).unwrap_err().code,
        ErrorCode::Invalid
    );
    assert_eq!(
        s.rename_account("nope", "x").unwrap_err().code,
        ErrorCode::UnknownAccount
    );
}

#[test]
fn a_wallet_is_named_and_its_accounts_say_where_they_come_from() {
    let (s, _) = signer(Emulator::default());
    scan_all(&s);
    let fp = hex::encode(s.offered()[0].fingerprint);
    let first = s.offered()[0].account.id.clone();
    let origin = &s.account_origins()[&first];
    assert_eq!(
        origin["phrase"],
        serde_json::json!({ "id": format!("fp:{fp}"), "name": null })
    );
    assert_eq!(origin["devices"][0]["kind"], "qr");
    assert!(s.rename_wallet(&fp.to_uppercase(), " Cold ").unwrap());
    assert!(
        !s.rename_wallet(&fp, "Cold").unwrap(),
        "the same name changes nothing"
    );
    for o in s.offered() {
        assert_eq!(s.account_origins()[&o.account.id]["phrase"]["name"], "Cold");
    }
    assert_eq!(
        s.rename_wallet("00000000", "x").unwrap_err().code,
        ErrorCode::Invalid
    );
    assert_eq!(
        s.rename_wallet(&fp, &"x".repeat(81)).unwrap_err().code,
        ErrorCode::Invalid
    );
    for o in s.offered() {
        s.remove_account(&o.account.id).unwrap();
    }
    assert_eq!(
        s.wallet_name(&fp),
        None,
        "the name goes with the wallet's last account"
    );
}

#[test]
fn a_wallet_name_is_kept_with_the_accounts_and_registered() {
    let d = dir("store");
    let r = rig(
        Emulator::default(),
        Store::open(&d).unwrap(),
        Duration::from_secs(20),
    );
    scan_all(&r.signer);
    let fp = hex::encode(r.signer.offered()[0].fingerprint);
    r.signer.rename_wallet(&fp, "Cold").unwrap();
    let reopened = Store::open(&d).unwrap();
    assert_eq!(reopened.wallet_name(&fp), Some("Cold"));
    assert_eq!(reopened.list().len(), 3);
    // Added again, the seed is registered under the name it was given.
    scan_all(&r.signer);
    assert_eq!(r.heard.0.lock().unwrap().last().unwrap().2, "Cold");
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn codes_shrink_to_fit_the_terminal_showing_them() {
    let (mut s, scanner) = signer(Emulator::default());
    scan_all(&s);
    let segwit = account(&s, Family::Bitcoin);
    *scanner.presenter.lock().unwrap() = Some(6);
    scanner.shown.lock().unwrap().clear();
    let job = s.sign(psbt_request(&segwit)).unwrap();
    assert_eq!(wait(&mut s, &job), JobState::Done);
    // The profile's codes first, then, once the terminal said how much room it has, ones that fit.
    assert_eq!(*scanner.shown.lock().unwrap(), vec![25, 6]);
}

#[test]
fn a_terminal_too_small_for_any_code_is_tried_again_once_resized() {
    let (mut s, scanner) = signer(Emulator::default());
    scan_all(&s);
    let segwit = account(&s, Family::Bitcoin);
    // Room for version 1 only, which no part cycle fits in, as a 120 by 30 console.
    *scanner.presenter.lock().unwrap() = Some(1);
    scanner.shown.lock().unwrap().clear();
    let job = s.sign(psbt_request(&segwit)).unwrap();
    std::thread::sleep(Duration::from_millis(600));
    *scanner.presenter.lock().unwrap() = Some(6);
    assert_eq!(wait(&mut s, &job), JobState::Done);
    assert_eq!(*scanner.shown.lock().unwrap(), vec![25, 6]);
}

/// A PSBT spending two coins of a Bitcoin account, asked for with the account's xpub.
fn psbt_request(account: &Account) -> SignRequest {
    let base = account.path.clone().unwrap();
    let inputs: Vec<(String, String)> = ["0/0", "1/3"]
        .iter()
        .map(|t| (format!("{base}/{t}"), format!("{base}/{t}")))
        .collect();
    let (psbt, _) = conformance::psbt_for(account, &inputs);
    SignRequest {
        account: account.id.clone(),
        payload: Payload::BtcPsbt {
            network: "testnet".into(),
            psbt,
        },
        secret: None,
        xpub: account.xpub.clone(),
    }
}

#[test]
fn what_the_wallet_cant_take_is_refused_before_it_is_shown() {
    let (mut s, scanner) = signer(Emulator::default());
    scan_all(&s);
    let account = s.offered()[0].account.id.clone();
    let e = s
        .sign(SignRequest {
            account,
            payload: Payload::EvmTransaction {
                chain_id: 1 << 40,
                tx: "02c0".into(),
            },
            secret: None,
            xpub: None,
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("Keycard Shell"), "{}", e.message);
    assert!(scanner.sessions.lock().unwrap().is_empty());
}
