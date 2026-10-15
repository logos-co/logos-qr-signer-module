//! The QR signer end to end against the emulated wallet, with the scanner in process: codes pass as
//! text, so this covers the signer and the UR types; the helper and its decoders have their own.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use logos_signer_interface::conformance::{self, Fixture};
use logos_signer_interface::{ErrorCode, Family, JobState, Payload, SignRequest, Signer};
use qr_signer_module::emulator::Emulator;
use qr_signer_module::parts;
use qr_signer_module::signer::{Events, QrSigner, ScanPoll, ScanRequest, Scanner, Show};
use qr_signer_module::store::Store;

/// Hands the emulator what the window would show, and the camera what the emulator holds up.
struct InProcess {
    emu: Emulator,
    sessions: Mutex<HashMap<String, Vec<String>>>,
    stopped: Mutex<u32>,
    /// A terminal presenting the codes, with room for codes up to this version.
    presenter: Option<u8>,
    /// Each start's largest version allowed.
    shown: Mutex<Vec<u8>>,
    /// The wallet's account code is out of the camera's sight.
    hidden: AtomicBool,
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
            Some(s) if self.presenter.is_some_and(|v| !parts::fit(s.parts, v)) => {
                self.shown.lock().unwrap().push(s.max_version);
                Vec::new()
            }
            Some(s) => {
                self.shown.lock().unwrap().push(s.max_version);
                self.emu
                    .answer(s.parts)
                    .filter(|_| !self.emu.silent)
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
            presenter_max_version: self.presenter,
        })
    }

    fn progress(&self, _: &str, _: &str, _: usize, _: usize) {}

    fn stop(&self, session: &str, _: &str) {
        self.sessions.lock().unwrap().remove(session);
        *self.stopped.lock().unwrap() += 1;
    }
}

struct Quiet;

impl Events for Quiet {
    fn sign_progress(&self, _: &str, _: JobState) {}
    fn accounts_changed(&self, _: usize) {}
}

fn signer(emu: Emulator) -> (QrSigner, Arc<InProcess>) {
    signer_presented(emu, None)
}

fn signer_presented(emu: Emulator, presenter: Option<u8>) -> (QrSigner, Arc<InProcess>) {
    let scanner = Arc::new(InProcess {
        emu,
        sessions: Mutex::new(HashMap::new()),
        stopped: Mutex::new(0),
        presenter,
        shown: Mutex::new(Vec::new()),
        hidden: AtomicBool::new(false),
    });
    (
        QrSigner::with_patience(
            scanner.clone(),
            Store::new(),
            Box::new(Quiet),
            Duration::from_secs(20),
        ),
        scanner,
    )
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

#[test]
fn accounts_come_from_the_wallets_code() {
    let (s, _) = signer(Emulator::default());
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
    assert!(offered[2]
        .account
        .xpub
        .as_deref()
        .unwrap()
        .starts_with("tpub"));
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
fn a_cancelled_request_closes_the_session() {
    let (mut s, scanner) = signer(Emulator {
        silent: true,
        ..Emulator::default()
    });
    scan_all(&s);
    let account = s.offered()[0].account.id.clone();
    let job = s
        .sign(SignRequest {
            account,
            payload: Payload::EvmMessage {
                message: hex::encode("hi"),
            },
            secret: None,
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
    while *scanner.stopped.lock().unwrap() < 2 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        *scanner.stopped.lock().unwrap(),
        2,
        "the scan and the request each closed their session"
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
fn codes_shrink_to_fit_the_terminal_showing_them() {
    let (mut s, scanner) = signer_presented(Emulator::default(), Some(6));
    scan_all(&s);
    let account = s
        .offered()
        .into_iter()
        .find(|o| o.account.family == Family::Bitcoin)
        .unwrap()
        .account;
    let base = account.path.clone().unwrap();
    let inputs: Vec<(String, String)> = ["0/0", "1/3"]
        .iter()
        .map(|t| (format!("{base}/{t}"), format!("{base}/{t}")))
        .collect();
    let (psbt, _) = conformance::psbt_for(&account, &inputs);
    let job = s
        .sign(SignRequest {
            account: account.id.clone(),
            payload: Payload::BtcPsbt {
                network: "testnet".into(),
                psbt,
            },
            secret: None,
        })
        .unwrap();
    assert_eq!(wait(&mut s, &job), JobState::Done);
    // The profile's codes first, then, once the terminal said how much room it has, ones that fit.
    assert_eq!(*scanner.shown.lock().unwrap(), vec![25, 6]);
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
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("Keycard Shell"), "{}", e.message);
    assert!(scanner.sessions.lock().unwrap().is_empty());
}
