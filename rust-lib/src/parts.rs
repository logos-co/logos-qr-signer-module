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

/// Characters an alphanumeric code holds at error correction L, by version, 1 to 25.
const ALPHANUMERIC_L: [usize; 25] = [
    25, 47, 77, 114, 154, 195, 224, 279, 335, 395, 468, 535, 619, 667, 758, 854, 938, 1046, 1153,
    1249, 1352, 1460, 1588, 1704, 1853,
];

/// Whether every part fits a code of at most `version`.
pub fn fit(parts: &[String], version: u8) -> bool {
    usize::from(version)
        .checked_sub(1)
        .and_then(|i| ALPHANUMERIC_L.get(i))
        .is_some_and(|cap| parts.iter().all(|p| p.len() <= *cap))
}

/// The parts to show when no code may be larger than `version`, such as a terminal's: the largest
/// fragment up to `fragment` whose every part fits. None when not even one byte does.
pub fn parts_within(
    ur_type: &str,
    cbor: &[u8],
    fragment: usize,
    version: u8,
) -> Option<Vec<String>> {
    let (mut lo, mut hi, mut best) = (1, fragment, None);
    while lo <= hi {
        let mid = (lo + hi) / 2;
        let p = parts(ur_type, cbor, mid).ok()?;
        if fit(&p, version) {
            best = Some(p);
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    best
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
    fn parts_shrink_to_fit_a_small_code_and_still_add_up() {
        let msg: Vec<u8> = (0..600u32).map(|i| (i * 13 % 251) as u8).collect();
        let big = parts("crypto-psbt", &msg, 300).unwrap();
        let small = parts_within("crypto-psbt", &msg, 300, 6).unwrap();
        assert!(small.iter().all(|p| p.len() <= ALPHANUMERIC_L[5]));
        assert!(small.len() > big.len());
        let mut a = Assembler::default();
        for p in &small {
            a.receive(p);
        }
        assert_eq!(a.done(), Some(("crypto-psbt".to_string(), msg.clone())));
        // Room enough already: the fragment asked for is kept.
        assert_eq!(parts_within("crypto-psbt", &msg, 300, 25).unwrap(), big);
        assert_eq!(parts_within("crypto-psbt", &msg, 300, 1), None);
    }

    /// The table against the encoder the scanner draws with.
    #[cfg(feature = "emulator")]
    #[test]
    fn the_capacities_are_qrcodegens() {
        use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};
        for (i, cap) in ALPHANUMERIC_L.iter().enumerate() {
            let v = Version::new(i as u8 + 1);
            let fits = |n: usize| {
                let text = "A".repeat(n);
                let segs = QrSegment::make_segments(&text);
                QrCode::encode_segments_advanced(&segs, QrCodeEcc::Low, Version::MIN, v, None, true)
                    .is_ok()
            };
            assert!(fits(*cap) && !fits(cap + 1), "version {}", i + 1);
        }
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
