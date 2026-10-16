//! qr-device-emulator: a QR wallet in software, for the QR helper's fake mode. Prints the address it
//! listens on; point the helper at it with LOGOS_QR_HELPER_FAKE.
//!
//!   qr-device-emulator [--listen 127.0.0.1:0] [--phrase WORDS] [--silent]

use qr_signer_module::emulator::Emulator;

fn main() {
    let mut emu = Emulator::default();
    let mut listen = "127.0.0.1:0".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next().expect("--listen ADDR"),
            "--phrase" => emu.phrase = args.next().expect("--phrase WORDS"),
            "--silent" => emu.silent = true,
            other => panic!("unknown argument {other}"),
        }
    }
    let at = emu.listen(&listen).expect("listen");
    println!("{at}");
    loop {
        std::thread::park();
    }
}
