//! Logos module glue for `qr_signer_module`. The builder derives the `.lidl` from the
//! `QrSignerModule` trait and injects the generated scaffold at the `include!` point.
//!
//! Every reply is a JSON string: `{ "ok": true, ... }` or `{ "ok": false, "error": "...", "code"? }`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use logos_signer_interface::json as signer_json;
use logos_signer_interface::wallets::{read_data_key, DataKey, DataKeyRequest};
use logos_signer_interface::JobState;
use serde_json::{json, Value};

use crate::profile;
use crate::signer::{Events, QrSigner, ScanPoll, ScanRequest, Scanner, Show};
use crate::store::Store;

pub trait QrSignerModule: Send + Sync + 'static {
    // ── logos.signer/1 ──────────────────────────────────────────────────
    fn signer_info(&self) -> String;
    fn signer_accounts(&self) -> String;
    fn sign(&self, request_json: String) -> String;
    fn sign_status(&self, job: String) -> String;
    fn sign_result(&self, job: String) -> String;
    fn cancel_sign(&self, job: String) -> String;
    /// A seed's unlock key, for the signer manager alone: `{ seed, index }` → `{ ok, job }`; the
    /// job waits in `confirm_on_device` while the request shows and its answer is read.
    fn unlock_key(&self, request_json: String) -> String;
    fn unlock_key_status(&self, job: String) -> String;
    /// `{ ok, job, key }`, once: the job forgets it.
    fn unlock_key_result(&self, job: String) -> String;
    fn cancel_unlock_key(&self, job: String) -> String;

    // ── the QR signer's app ─────────────────────────────────────────────
    /// The wallets it knows by name: `{ ok, profiles: [{ name, label }] }`.
    fn profiles(&self) -> String;
    /// Read a wallet's account code and offer accounts of these families:
    /// `{ families, label?, profile? }` → `{ ok, job }`.
    fn scan_accounts(&self, params_json: String) -> String;
    /// A scan's progress: `{ ok, job, state, accounts, error? }`.
    fn add_status(&self, job: String) -> String;
    /// Stop a scan: `{ ok, cancelled }`, whether it was still running.
    fn cancel_scan(&self, job: String) -> String;
    /// Stop offering an account: `{ ok, removed }`. Nothing on the wallet changes.
    fn remove_account(&self, id: String) -> String;
    /// Name an account for apps; a blank name clears it: `{ ok, renamed }`.
    fn rename_account(&self, id: String, label: String) -> String;
    /// The wallets accounts came from, by master fingerprint, with the profile each follows and
    /// the name given to it: `{ ok, wallets: [{ fingerprint, profile, label, name }] }`.
    fn wallets(&self) -> String;
    /// Name a wallet by its master fingerprint; a blank name clears it: `{ ok, renamed }`.
    fn rename_wallet(&self, fingerprint: String, name: String) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

pub trait QrSignerModuleEvents {
    fn signer_accounts_changed(&self, count: i64);
    fn sign_progress(&self, job: String, state: String);
}

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/generated/provider_gen.rs"
));

static UNLOADING: AtomicBool = AtomicBool::new(false);

/// How long one call to the scanner may take; a session itself lasts as long as the person needs.
const BUDGET: Duration = Duration::from_secs(20);

/// The module behind `logos.wallets/1`: the signer manager, bound at runtime, since it depends on
/// this module and this module can't depend on it.
const WALLETS: &str = "signer_manager_module";

fn from_manager() -> bool {
    matches!(logos_rust_sdk::current_caller(), logos_rust_sdk::LogosCaller::Module { name, .. } if name == WALLETS)
}

struct Emit;

impl Events for Emit {
    /// The seed goes to the signer manager while its unlock key is at hand, so the person never
    /// unlocks it a second time. Asked without waiting: without a manager the add stands.
    fn seed_added(&self, seed: &str, unlock_key: Option<[u8; 33]>, name: &str) {
        if UNLOADING.load(Ordering::SeqCst) {
            return;
        }
        let body = zeroize::Zeroizing::new(
            json!({ "seed": seed, "kind": "qr", "unlockKey": unlock_key.map(hex::encode), "name": name })
                .to_string(),
        );
        wallets::WalletsClient::bind(WALLETS).enroll_seed_async(&body, |_| {});
    }
    fn sign_progress(&self, job: &str, state: JobState) {
        if !UNLOADING.load(Ordering::SeqCst) {
            emit_sign_progress(job, state.as_str());
        }
    }
    fn accounts_changed(&self, count: usize) {
        if !UNLOADING.load(Ordering::SeqCst) {
            emit_signer_accounts_changed(count as i64);
        }
    }
}

/// A seed's accounts open with this module's key for it, which the signer manager gives once the
/// person unlocks the wallet in the Signer app, and close when it locks. Asked from threads of their
/// own, never while answering the manager, which would wait on itself.
fn watch_wallets(qr: QrSigner) {
    let mut client = wallets::WalletsClient::bind(WALLETS);
    let changed = client.on_wallets_changed();
    let locked = client.on_wallets_locked();
    let q = qr.clone();
    std::thread::spawn(move || {
        open_wallets(&q);
        if let Ok(sub) = changed {
            for _ in sub {
                open_wallets(&q);
            }
        }
    });
    if let Ok(sub) = locked {
        std::thread::spawn(move || {
            for _ in sub {
                qr.lock_seeds();
                // Only some may have locked.
                open_wallets(&qr);
            }
        });
    }
}

/// Every closed seed's key; a locked one answers `locked` and stays closed.
fn open_wallets(qr: &QrSigner) {
    for (seed, sealed_under) in qr.closed_seeds() {
        if UNLOADING.load(Ordering::SeqCst) {
            return;
        }
        let Some(current) = data_key(&seed, None) else {
            continue;
        };
        let box_key = match sealed_under {
            Some(g) if g != current.generation => match data_key(&seed, Some(g)) {
                Some(k) => k,
                None => continue,
            },
            _ => current.clone(),
        };
        if let Err(e) = qr.open_seed(&seed, &box_key, &current) {
            eprintln!("qr_signer_module: a wallet's accounts didn't open: {e}");
        }
    }
}

/// The key for a seed's document, the seed named as this module names it: its master fingerprint.
fn data_key(seed: &str, generation: Option<u32>) -> Option<DataKey> {
    let body = serde_json::to_string(&DataKeyRequest {
        seed: seed.to_string(),
        scope: "accounts".into(),
        generation,
    })
    .ok()?;
    let (tx, rx) = sync_channel(1);
    wallets::WalletsClient::bind(WALLETS).data_key_async_with_timeout(&body, BUDGET, move |r| {
        let _ = tx.send(r);
    });
    read_data_key(&wait(rx).ok()?).ok()
}

fn wait<T>(rx: Receiver<Result<T, logos_rust_sdk::LogosError>>) -> Result<T, String> {
    let start = Instant::now();
    loop {
        if UNLOADING.load(Ordering::SeqCst) {
            return Err("unloading".into());
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(r) => return r.map_err(|e| e.to_string()),
            Err(RecvTimeoutError::Timeout) if start.elapsed() < BUDGET + Duration::from_secs(5) => {
                continue
            }
            Err(_) => return Err("the QR scanner didn't answer".into()),
        }
    }
}

/// The scanner module, called from job threads without blocking its main thread: one client,
/// asynchronous calls, each answer waited for on a channel.
#[derive(Default)]
struct ScannerIpc(OnceLock<qr_scanner_module::QrScannerModuleClient>);

impl ScannerIpc {
    fn c(&self) -> &qr_scanner_module::QrScannerModuleClient {
        self.0
            .get_or_init(qr_scanner_module::QrScannerModuleClient::new)
    }
}

macro_rules! ipc {
    ($self:ident, $method:ident, $($arg:expr),*) => {{
        let (tx, rx) = sync_channel(1);
        $self.c().$method($($arg,)* BUDGET, move |r| {
            let _ = tx.send(r);
        });
        wait(rx)
    }};
}

/// A reply's fields when `ok`, its error otherwise.
fn reply(raw: String) -> Result<Value, String> {
    let v: Value =
        serde_json::from_str(&raw).map_err(|e| format!("the QR scanner's reply: {e}"))?;
    if v["ok"] == true {
        Ok(v)
    } else {
        Err(v["error"]
            .as_str()
            .unwrap_or("the QR scanner refused")
            .to_string())
    }
}

impl Scanner for ScannerIpc {
    fn start(
        &self,
        title: &str,
        show: Option<Show<'_>>,
        scan: bool,
        hint: &str,
    ) -> Result<(String, String), String> {
        let mut p = json!({ "title": title, "scan": scan, "hint": hint });
        if let Some(s) = show {
            p["show"] = json!({ "parts": s.parts, "interval_ms": s.interval_ms, "max_version": s.max_version });
        }
        let v = reply(ipc!(self, start_async_with_timeout, &p.to_string())?)?;
        match (v["session"].as_str(), v["token"].as_str()) {
            (Some(s), Some(t)) => Ok((s.to_string(), t.to_string())),
            _ => Err("the QR scanner gave no session".into()),
        }
    }

    fn poll(&self, session: &str, token: &str) -> Result<ScanPoll, String> {
        let v = reply(ipc!(self, poll_async_with_timeout, session, token)?)?;
        serde_json::from_value(v).map_err(|e| format!("the QR scanner's poll: {e}"))
    }

    fn progress(&self, session: &str, token: &str, received: usize, expected: usize) {
        let p = json!({ "received": received, "expected": expected }).to_string();
        let _ = ipc!(self, progress_async_with_timeout, session, token, &p);
    }

    fn stop(&self, session: &str, token: &str) {
        let _ = ipc!(self, stop_async_with_timeout, session, token);
    }
}

struct QrSignerModuleImpl {
    qr: QrSigner,
}

impl Default for QrSignerModuleImpl {
    fn default() -> Self {
        QrSignerModuleImpl {
            qr: QrSigner::new(
                Arc::new(ScannerIpc::default()),
                Store::new(),
                Box::new(Emit),
            ),
        }
    }
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

fn signer_err(e: logos_signer_interface::SignerError) -> String {
    json!({ "ok": false, "code": e.code, "error": e.message }).to_string()
}

impl QrSignerModule for QrSignerModuleImpl {
    fn signer_info(&self) -> String {
        signer_json::signer_info(&self.qr)
    }

    fn signer_accounts(&self) -> String {
        let raw = signer_json::signer_accounts(&mut self.qr.clone());
        let Ok(mut reply) = serde_json::from_str::<Value>(&raw) else {
            return raw;
        };
        let origins = self.qr.account_origins();
        if let Some(rows) = reply["accounts"].as_array_mut() {
            for row in rows {
                if let Some(origin) = row["id"].as_str().and_then(|id| origins.get(id)) {
                    row["origin"] = origin.clone();
                }
            }
        }
        reply.to_string()
    }

    fn sign(&self, request_json: String) -> String {
        signer_json::sign(&mut self.qr.clone(), &request_json)
    }

    fn sign_status(&self, job: String) -> String {
        signer_json::sign_status(&mut self.qr.clone(), &job)
    }

    fn sign_result(&self, job: String) -> String {
        signer_json::sign_result(&mut self.qr.clone(), &job)
    }

    fn cancel_sign(&self, job: String) -> String {
        signer_json::cancel_sign(&mut self.qr.clone(), &job)
    }

    fn unlock_key(&self, request_json: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::unlock_key(&mut self.qr.clone(), &request_json)
    }

    fn unlock_key_status(&self, job: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::unlock_key_status(&mut self.qr.clone(), &job)
    }

    fn unlock_key_result(&self, job: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::unlock_key_result(&mut self.qr.clone(), &job)
    }

    fn cancel_unlock_key(&self, job: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::cancel_unlock_key(&mut self.qr.clone(), &job)
    }

    fn profiles(&self) -> String {
        let profiles: Vec<Value> = profile::ALL
            .iter()
            .map(|p| json!({ "name": p.name, "label": p.label }))
            .collect();
        json!({ "ok": true, "profiles": profiles }).to_string()
    }

    fn scan_accounts(&self, params_json: String) -> String {
        let req: ScanRequest = match serde_json::from_str(&params_json) {
            Ok(r) => r,
            Err(e) => return err(format!("params: {e}")),
        };
        match self.qr.scan_accounts(req) {
            Ok(job) => json!({ "ok": true, "job": job }).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn add_status(&self, job: String) -> String {
        match self.qr.add_status(&job) {
            Some(added) => {
                let mut v = json!({ "ok": true, "job": job });
                if let (Some(out), Ok(Value::Object(fields))) =
                    (v.as_object_mut(), serde_json::to_value(added))
                {
                    out.extend(fields);
                }
                v.to_string()
            }
            None => err(format!("no scan {job}")),
        }
    }

    fn cancel_scan(&self, job: String) -> String {
        json!({ "ok": true, "cancelled": self.qr.cancel_scan(&job) }).to_string()
    }

    fn remove_account(&self, id: String) -> String {
        match self.qr.remove_account(&id) {
            Ok(removed) => json!({ "ok": true, "removed": removed }).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn rename_account(&self, id: String, label: String) -> String {
        match self.qr.rename_account(&id, &label) {
            Ok(renamed) => json!({ "ok": true, "renamed": renamed }).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn wallets(&self) -> String {
        let mut wallets: Vec<Value> = Vec::new();
        for o in self.qr.offered() {
            let fingerprint = hex::encode(o.fingerprint);
            if wallets
                .iter()
                .any(|w| w["fingerprint"] == fingerprint.as_str())
            {
                continue;
            }
            let p = profile::get(&o.profile);
            let name = self.qr.wallet_name(&fingerprint);
            wallets.push(json!({
                "fingerprint": fingerprint, "profile": p.name, "label": p.label, "name": name
            }));
        }
        json!({ "ok": true, "wallets": wallets }).to_string()
    }

    fn rename_wallet(&self, fingerprint: String, name: String) -> String {
        match self.qr.rename_wallet(&fingerprint, &name) {
            Ok(renamed) => json!({ "ok": true, "renamed": renamed }).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn on_context_ready(&self, ctx: &RustModuleContext) {
        // The accounts offered live in the module's own directory, each seed's sealed until the
        // signer manager gives its key.
        match Store::open(&ctx.instance_persistence_path) {
            Ok(store) => {
                self.qr.set_store(store);
                // Off this callback: subscribing waits for the manager's connection in a nested
                // event loop, which would dispatch other calls inside it.
                let qr = self.qr.clone();
                std::thread::spawn(move || watch_wallets(qr));
            }
            Err(e) => eprintln!("qr_signer_module: {}: {e}", ctx.instance_persistence_path),
        }
    }
}

impl logos_rust_sdk::AboutToUnload for QrSignerModuleImpl {
    /// Calls waiting on the scanner are answered first: their replies would need this thread.
    fn about_to_unload(&self) -> logos_rust_sdk::Shutdown {
        UNLOADING.store(true, Ordering::SeqCst);
        logos_rust_sdk::Shutdown::Synchronous
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    logos_install!(QrSignerModuleImpl);
}
