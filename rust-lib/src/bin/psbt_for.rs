//! qr-psbt-for: a PSBT spending two coins of a Bitcoin account (its first receive key and a change
//! key), for doctests and checks by hand. The coins are made up: the PSBT can be signed, never
//! broadcast. Reads the account as JSON on standard input, as `signer_accounts` lists it, and
//! prints the PSBT in base64.

use std::io::Read;

use logos_signer_interface::conformance::psbt_for;
use logos_signer_interface::Account;

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("an account on standard input");
    let account: Account = serde_json::from_str(&input).expect("an account as JSON");
    let base = account.path.clone().expect("the account's path");
    let inputs: Vec<(String, String)> = ["0/0", "1/3"]
        .iter()
        .map(|tail| (format!("{base}/{tail}"), format!("{base}/{tail}")))
        .collect();
    let (psbt, _) = psbt_for(&account, &inputs);
    println!("{psbt}");
}
