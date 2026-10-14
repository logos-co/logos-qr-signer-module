//! What a QR wallet's codes can hold, by wallet. A request one can't take is refused before
//! anything is shown.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub name: &'static str,
    /// What the person picks in the app.
    pub label: &'static str,
    /// Bytes of CBOR per animated part.
    pub fragment: usize,
    pub interval_ms: u64,
    /// The densest code the wallet's camera reads.
    pub max_version: u8,
    pub max_inputs: usize,
    pub max_outputs: usize,
    /// The largest EVM chain id its decoder takes.
    pub max_chain_id: u64,
}

/// The Keycard Shell, firmware 1.4.0: codes up to version 25, PSBTs of at most 40 inputs and 40
/// outputs, chain ids that fit an int32.
pub const KEYCARD_SHELL: Profile = Profile {
    name: "keycard_shell",
    label: "Keycard Shell",
    fragment: 300,
    interval_ms: 200,
    max_version: 25,
    max_inputs: 40,
    max_outputs: 40,
    max_chain_id: i32::MAX as u64,
};

/// Any other BC-UR wallet: smaller, slower codes most cameras read.
pub const GENERIC: Profile = Profile {
    name: "generic",
    label: "Another QR wallet",
    fragment: 200,
    interval_ms: 250,
    max_version: 20,
    max_inputs: usize::MAX,
    max_outputs: usize::MAX,
    max_chain_id: u64::MAX,
};

pub const ALL: [Profile; 2] = [KEYCARD_SHELL, GENERIC];

pub fn get(name: &str) -> Profile {
    ALL.into_iter().find(|p| p.name == name).unwrap_or(GENERIC)
}

/// The profile for the device a code names, as Keystone's `crypto-multi-accounts` does.
pub fn for_device(device: Option<&str>) -> Option<&'static str> {
    let d = device?.to_ascii_lowercase();
    d.contains("shell").then_some(KEYCARD_SHELL.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_by_name_and_device() {
        assert_eq!(get("keycard_shell").max_inputs, 40);
        assert_eq!(get("nope"), GENERIC);
        assert_eq!(for_device(Some("Keycard Shell")), Some("keycard_shell"));
        assert_eq!(for_device(Some("Keystone 3 Pro")), None);
    }
}
