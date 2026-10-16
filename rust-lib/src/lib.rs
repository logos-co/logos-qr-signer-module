//! qr_signer_module: air-gapped wallets that sign over QR codes, behind `logos.signer/1`. It writes
//! each request as animated BC-UR codes and reads the wallet's answer through `qr_scanner_module`,
//! which alone holds the camera. It holds no secret: the keys stay on the wallet.
//!
//! The core is plain Rust, tested with `cargo test --no-default-features --features emulator`. The
//! Logos glue is behind `logos_module`.

pub mod accounts;
pub mod parts;
pub mod profile;
pub mod signer;
pub mod store;
pub mod ur;

#[cfg(feature = "emulator")]
pub mod emulator;

#[cfg(feature = "logos_module")]
mod glue;
