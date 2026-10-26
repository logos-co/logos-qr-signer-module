# logos-qr-signer-module

`qr_signer_module` signs with air-gapped wallets over animated QR codes (BC-UR and ERC-4527): the Keycard
Shell, Keystone, Passport, Jade, SeedSigner and others. It is a signer behind `logos.signer/1`, so the
signer manager lists its accounts and hands it requests like any device. The camera belongs to
`qr_scanner_module`; this module holds no secret. See [docs/specs.md](docs/specs.md).

```sh
logosctl call qr_signer_module scan_accounts '{"families":["evm","bitcoin","bitcoin_taproot"]}'
logosctl call qr_signer_module add_status <job>          # done, once the wallet's code is read
logosctl call qr_signer_module signer_accounts
```

## Build and test

```sh
nix build .#lgx                       # the module
nix build .#emulator                  # a QR wallet in software, and qr-psbt-for
cargo test --manifest-path rust-lib/Cargo.toml --no-default-features --features emulator
```

`cargo test` resolves the Rust SDK's manifest, so check out
[logos-rust-sdk](https://github.com/logos-co/logos-rust-sdk) as `logos-rust-sdk-src` beside `rust-lib`.

## Licence

MIT or Apache-2.0, at your option.
