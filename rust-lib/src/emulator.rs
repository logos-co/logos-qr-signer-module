//! A QR wallet in software, for tests and doctests: the other end of the QR helper's fake mode. It
//! reads the codes the helper would show, signs with the signer interface's mock keys, and holds its
//! answer up to the "camera" as pictures of QR codes. Asked to scan with nothing shown, it shows its
//! accounts, as a wallet's connect screen does.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::time::Duration;

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::secp256k1::{ecdsa, schnorr, Secp256k1};
use bitcoin::{NetworkKind, Psbt};
use logos_signer_interface::mock::{MockOptions, MockSigner, PHRASE};
use logos_signer_interface::{Family, Payload, RequestKind, SignRequest, Signer};
use qrcodegen::{QrCode, QrCodeEcc};
use serde::Deserialize;

use crate::parts::{self, Assembler};
use crate::ur::{self, Accounts, EthDataType, EthSignature, HdKey, Keypath};

#[derive(Clone)]
pub struct Emulator {
    pub phrase: String,
    /// Read requests but never answer, as a person who walks away.
    pub silent: bool,
    /// What its account code says it is.
    pub device: String,
}

impl Default for Emulator {
    fn default() -> Self {
        Emulator {
            phrase: PHRASE.into(),
            silent: false,
            device: "Keycard Shell (emulated)".into(),
        }
    }
}

#[derive(Deserialize)]
struct Frame {
    size: usize,
    bits: String,
}

#[derive(Deserialize)]
struct Shown {
    frames: Vec<Frame>,
}

#[derive(Deserialize)]
struct Line {
    show: Option<Shown>,
    #[serde(default)]
    scan: bool,
}

/// A frame as a camera would see it: 4 pixels a module, with the quiet zone.
fn frame_raster(f: &Frame) -> (usize, usize, Vec<u8>) {
    let scale = 4;
    let side = (f.size + 8) * scale;
    let bits = f.bits.as_bytes();
    let mut px = vec![255u8; side * side];
    for y in 0..side {
        for x in 0..side {
            let (mx, my) = ((x / scale).wrapping_sub(4), (y / scale).wrapping_sub(4));
            if mx < f.size && my < f.size && bits[my * f.size + mx] == b'1' {
                px[y * side + x] = 0;
            }
        }
    }
    (side, side, px)
}

/// What the wallet reads in each frame.
fn read_frames(frames: &[Frame]) -> Vec<String> {
    frames
        .iter()
        .filter_map(|f| {
            let (w, h, px) = frame_raster(f);
            let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| px[y * w + x]);
            img.detect_grids()
                .into_iter()
                .find_map(|g| g.decode().ok().map(|(_, t)| t))
        })
        .collect()
}

/// A code held up to the camera: on a mid-gray background, 4 pixels a module.
fn text_raster(text: &str) -> (usize, usize, Vec<u8>) {
    let qr = QrCode::encode_text(text, QrCodeEcc::Low).expect("a part fits a QR code");
    let n = qr.size() as usize;
    let scale = 4;
    let side = (n + 8) * scale;
    let (w, h) = (side + 40, side + 40);
    let mut px = vec![120u8; w * h];
    for y in 0..side {
        for x in 0..side {
            let (mx, my) = (x / scale, y / scale);
            let dark = (4..n + 4).contains(&mx)
                && (4..n + 4).contains(&my)
                && qr.get_module(mx as i32 - 4, my as i32 - 4);
            px[(20 + y) * w + 20 + x] = if dark { 15 } else { 240 };
        }
    }
    (w, h, px)
}

impl Emulator {
    fn seed(&self) -> [u8; 64] {
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(self.phrase.as_bytes(), b"mnemonic", 2048, &mut seed);
        seed
    }

    fn mock(&self) -> MockSigner {
        MockSigner::new(MockOptions {
            phrase: self.phrase.clone(),
            request_kinds: vec![
                RequestKind::EvmTransaction,
                RequestKind::EvmMessage,
                RequestKind::BtcPsbt,
            ],
            ..MockOptions::default()
        })
    }

    /// Its accounts, as Keystone's `crypto-multi-accounts`: native segwit and taproot on the test
    /// networks, and EVM.
    pub fn accounts_code(&self) -> Vec<String> {
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(NetworkKind::Test, &self.seed()).expect("a master key");
        let fp = u32::from_be_bytes(root.fingerprint(&secp).to_bytes());
        let key = |p: &str| {
            let path = DerivationPath::from_str(p).expect("a path");
            let x = root.derive_priv(&secp, &path).expect("derive");
            let steps: Vec<ChildNumber> = path.into_iter().copied().collect();
            let parent = root
                .derive_priv(&secp, &steps[..steps.len() - 1].to_vec())
                .expect("derive");
            HdKey {
                key: x.private_key.public_key(&secp).serialize().to_vec(),
                chain_code: Some(x.chain_code.to_bytes().to_vec()),
                use_info: None,
                origin: Some(Keypath {
                    components: steps.iter().map(|c| u32::from(*c)).collect(),
                    source_fingerprint: Some(fp),
                    depth: Some(steps.len() as u8),
                }),
                children: None,
                parent_fingerprint: Some(u32::from_be_bytes(parent.fingerprint(&secp).to_bytes())),
                name: None,
            }
        };
        let accounts = Accounts {
            master_fingerprint: fp,
            outputs: Vec::new(),
            keys: vec![key("m/84'/1'/0'"), key("m/86'/1'/0'"), key("m/44'/60'/0'")],
            device: Some(self.device.clone()),
        };
        let cbor = ur::multi_accounts(&accounts).expect("encode");
        parts::parts("crypto-multi-accounts", &cbor, 200).expect("parts")
    }

    /// The answer to the request in these codes, or none.
    pub fn answer(&self, texts: &[String]) -> Option<Vec<String>> {
        let mut a = Assembler::expecting(&["crypto-psbt", "eth-sign-request"]);
        for t in texts {
            a.receive(t);
        }
        let (t, cbor) = a.done()?;
        let mut mock = self.mock();
        let accounts = mock.accounts().ok()?;
        let id_of = |f: Family| {
            accounts
                .iter()
                .find(|a| a.family == f)
                .map(|a| a.id.clone())
        };
        if t == "eth-sign-request" {
            let r = ur::read_eth_sign_request(&cbor).ok()?;
            let payload = match r.data_type {
                EthDataType::Transaction | EthDataType::TypedTransaction => {
                    Payload::EvmTransaction {
                        chain_id: r.chain_id.unwrap_or(1) as u64,
                        tx: hex::encode(&r.sign_data),
                    }
                }
                EthDataType::RawBytes => Payload::EvmMessage {
                    message: hex::encode(&r.sign_data),
                },
                EthDataType::TypedData => return None,
            };
            let job = mock
                .sign(SignRequest {
                    account: id_of(Family::Evm)?,
                    payload,
                    secret: None,
                })
                .ok()?;
            let sig = mock.result(&job).ok()?.into_iter().next()?;
            let id = sig.recovery_id? as u64;
            // v as each kind of request writes it: 27 or 28, EIP-155, or the bare recovery id.
            let v = match r.data_type {
                EthDataType::RawBytes => 27 + id,
                EthDataType::Transaction => r.chain_id.unwrap_or(1) as u64 * 2 + 35 + id,
                _ => id,
            };
            let mut signature = hex::decode(&sig.signature).ok()?;
            let vb = v.to_be_bytes();
            let first = vb.iter().position(|b| *b != 0).unwrap_or(7);
            signature.extend_from_slice(&vb[first..]);
            let cbor = ur::eth_signature(&EthSignature {
                request_id: Some(r.request_id),
                signature,
            })
            .ok()?;
            return parts::parts("eth-signature", &cbor, 200).ok();
        }
        let mut psbt = Psbt::deserialize(&ur::read_psbt(&cbor).ok()?).ok()?;
        let taproot = psbt
            .inputs
            .first()
            .is_some_and(|i| !i.tap_key_origins.is_empty());
        let family = if taproot {
            Family::BitcoinTaproot
        } else {
            Family::Bitcoin
        };
        let b64 = psbt.to_string();
        let job = mock
            .sign(SignRequest {
                account: id_of(family)?,
                payload: Payload::BtcPsbt {
                    network: "regtest".into(),
                    psbt: b64,
                },
                secret: None,
            })
            .ok()?;
        for sig in mock.result(&job).ok()? {
            let bytes = hex::decode(&sig.signature).ok()?;
            let input = psbt.inputs.get_mut(sig.item)?;
            if taproot {
                let signature = schnorr::Signature::from_slice(&bytes).ok()?;
                input.tap_key_sig = Some(bitcoin::taproot::Signature {
                    signature,
                    sighash_type: bitcoin::TapSighashType::Default,
                });
            } else {
                let key = *input.bip32_derivation.keys().next()?;
                let s = ecdsa::Signature::from_compact(&bytes).ok()?;
                input.partial_sigs.insert(
                    bitcoin::PublicKey::new(key),
                    bitcoin::ecdsa::Signature::sighash_all(s),
                );
            }
        }
        parts::parts("crypto-psbt", &ur::psbt(&psbt.serialize()), 200).ok()
    }

    /// One helper's session: what it shows is read, and once it scans, the answer is held up over
    /// and over until it hangs up.
    fn session(&self, stream: TcpStream) {
        let Ok(mut writer) = stream.try_clone() else {
            return;
        };
        let mut shown = Vec::new();
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { return };
            let Ok(l) = serde_json::from_str::<Line>(&line) else {
                continue;
            };
            if let Some(s) = l.show {
                shown = read_frames(&s.frames);
            }
            if !l.scan {
                continue;
            }
            let codes = if shown.is_empty() {
                Some(self.accounts_code())
            } else {
                self.answer(&shown)
            };
            let (Some(codes), false) = (codes, self.silent) else {
                continue;
            };
            let Ok(mut w) = writer.try_clone() else {
                return;
            };
            std::thread::spawn(move || loop {
                for text in &codes {
                    let (cw, ch, px) = text_raster(text);
                    if writeln!(w, "raster {cw} {ch}").is_err() || w.write_all(&px).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
        }
        let _ = writer.flush();
    }

    /// Listen for helpers in fake mode, one session per connection.
    pub fn listen(self, addr: &str) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let at = listener.local_addr()?;
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let me = self.clone();
                std::thread::spawn(move || me.session(conn));
            }
        });
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_read_back_as_their_text() {
        let text = "UR:CRYPTO-PSBT/1-2/LPADAOCFADCYBZFTLTENHDCXAEAEAEAE";
        let qr = QrCode::encode_text(text, QrCodeEcc::Low).unwrap();
        let n = qr.size() as usize;
        let bits = (0..n * n)
            .map(|i| {
                if qr.get_module((i % n) as i32, (i / n) as i32) {
                    '1'
                } else {
                    '0'
                }
            })
            .collect();
        assert_eq!(
            read_frames(&[Frame { size: n, bits }]),
            vec![text.to_string()]
        );
    }

    #[test]
    fn the_account_code_holds_the_mock_accounts() {
        let codes = Emulator::default().accounts_code();
        let mut a = Assembler::default();
        for c in &codes {
            a.receive(c);
        }
        let (t, cbor) = a.done().unwrap();
        let found = ur::accounts(&t, &cbor).unwrap();
        let mock = Emulator::default().mock().accounts().unwrap();
        assert_eq!(
            format!("{:08x}", found.master_fingerprint),
            mock[0].fingerprint.clone().unwrap()
        );
        assert_eq!(found.keys.len(), 3);
        assert_eq!(
            found.keys[0].origin.as_ref().unwrap().components[0],
            crate::accounts::HARDENED | 84
        );
    }
}
