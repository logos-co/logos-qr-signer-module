//! Animated QR codes: a message split into UR parts to show, and parts read back into a message.
//! Parts are uppercase, so each QR code uses alphanumeric mode.

use crate::ur::canonical;

/// The parts to show, in a cycle: every plain part, then as many fountain parts again, so a
/// reader that missed one doesn't wait a whole cycle.
pub fn parts(ur_type: &str, cbor: &[u8], fragment: usize) -> Result<Vec<String>, String> {
    if cbor.len() <= fragment {
        return Ok(vec![
            ur::encode(cbor, &ur::Type::Custom(ur_type)).to_uppercase()
        ]);
    }
    let mut e = ur::Encoder::new(cbor, fragment, ur_type).map_err(|e| e.to_string())?;
    let n = e.fragment_count();
    (0..2 * n)
        .map(|_| {
            e.next_part()
                .map(|p| p.to_uppercase())
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// Parts read back into one message of one UR type.
#[derive(Default)]
pub struct Assembler {
    multi: ur::Decoder,
    single: Option<(String, Vec<u8>)>,
    /// The types to take, by old name; any when empty.
    expect: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub received: usize,
    pub expected: usize,
}

impl Assembler {
    /// Takes only these UR types, by their old names.
    pub fn expecting(types: &[&'static str]) -> Assembler {
        Assembler {
            expect: types.to_vec(),
            ..Assembler::default()
        }
    }

    /// Takes one code's text. Codes that are no UR, of a type not expected, or of another type than
    /// the first, are ignored: a person may hold up something else first.
    pub fn receive(&mut self, text: &str) -> Option<Progress> {
        let lower = text.trim().to_ascii_lowercase();
        let body = lower.strip_prefix("ur:")?;
        let (ur_type, rest) = body.split_once('/')?;
        if !self.expect.is_empty() && !self.expect.contains(&canonical(ur_type)) {
            return None;
        }
        if rest.contains('/') {
            if let Some(t) = self.multi.ur_type() {
                if canonical(t) != canonical(ur_type) {
                    return None;
                }
            }
            self.multi.receive(&lower).ok()?;
        } else {
            let (_, cbor) = ur::ur::decode(&lower).ok()?;
            self.single = Some((ur_type.to_string(), cbor));
        }
        Some(self.progress())
    }

    pub fn progress(&self) -> Progress {
        if self.single.is_some() {
            return Progress {
                received: 1,
                expected: 1,
            };
        }
        Progress {
            received: self.multi.resolved_fragment_count().unwrap_or(0),
            expected: self.multi.fragment_count(),
        }
    }

    /// The UR type, under its old name, and its CBOR, once complete.
    pub fn done(&self) -> Option<(String, Vec<u8>)> {
        if let Some((t, cbor)) = &self.single {
            return Some((canonical(t).to_string(), cbor.clone()));
        }
        if !self.multi.complete() {
            return None;
        }
        let cbor = self.multi.message().ok()??;
        Some((canonical(self.multi.ur_type()?).to_string(), cbor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_message_comes_back_from_its_parts() {
        let msg: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
        let parts = parts("crypto-psbt", &msg, 200).unwrap();
        assert_eq!(parts.len(), 2 * 5);
        assert!(parts
            .iter()
            .all(|p| p.starts_with("UR:CRYPTO-PSBT/") && p == &p.to_uppercase()));
        let mut a = Assembler::default();
        // Every other part: the fountain parts make up for the plain ones missed.
        for p in parts.iter().step_by(2) {
            a.receive(p);
        }
        for p in parts.iter().skip(1).step_by(2) {
            if a.done().is_some() {
                break;
            }
            a.receive(p);
        }
        assert_eq!(a.done(), Some(("crypto-psbt".to_string(), msg)));
    }

    #[test]
    fn a_short_message_is_one_code() {
        let parts = parts("eth-signature", b"short", 200).unwrap();
        assert_eq!(parts.len(), 1);
        let mut a = Assembler::default();
        assert_eq!(
            a.receive(&parts[0]),
            Some(Progress {
                received: 1,
                expected: 1
            })
        );
        assert_eq!(
            a.done(),
            Some(("eth-signature".to_string(), b"short".to_vec()))
        );
    }

    #[test]
    fn other_codes_are_ignored() {
        let mut a = Assembler::default();
        assert_eq!(a.receive("https://example.com"), None);
        assert_eq!(a.receive("UR:"), None);
        let first = parts("crypto-psbt", &[1; 500], 100).unwrap();
        a.receive(&first[0]);
        let other = parts("crypto-account", &[2; 500], 100).unwrap();
        assert_eq!(a.receive(&other[0]), None);
    }
}
