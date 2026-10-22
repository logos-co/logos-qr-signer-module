# qr_signer_module

`qr_signer_module` is a signer behind `logos.signer/1` for air-gapped wallets that sign over animated QR
codes: the Keycard Shell, Keystone, Foundation Passport, Blockstream Jade in QR mode, SeedSigner and
others. It writes each request as BC-UR codes and reads the wallet's answer back, through
`qr_scanner_module`, which alone holds the camera. It holds no secret: the keys stay on the wallet, and the
signer manager checks every signature, as for any device.

## What it speaks

| Exchange | It shows | The wallet answers |
|---|---|---|
| Bitcoin PSBT | `ur:crypto-psbt` | `ur:crypto-psbt`: the same transaction with its signatures |
| EVM transaction, `personal_sign`, EIP-712 | `ur:eth-sign-request` (ERC-4527) | `ur:eth-signature` |
| Adding accounts | | `ur:crypto-account`, `ur:crypto-output`, `ur:crypto-hdkey` or Keystone's `ur:crypto-multi-accounts` |
| A seed's unlock key | `ur:eth-sign-request`, `personal_sign` at `m/1280263247'/n'` with no address | `ur:eth-signature`, which the key recovers from |

- **Written** under the registry's old names, which every wallet reads (the Keycard Shell rejects `ur:psbt`),
  in the CDDL's key order, which the Shell's decoder requires. **Read** under old or new names, in any order.
- Only the answer's type is taken: a code of any other type, or no UR at all, is ignored while waiting.
- A PSBT answer must be the same unsigned transaction; an `eth-signature` must carry the request's id.
- An `eth-signature`'s v may be 0 or 1, 27 or 28, or EIP-155's, whole or as its low byte; S is made low.
- No Bitcoin message signing: `btc-sign-request` is Keystone's, and the signer interface has no such kind.

## Wallets

Each account remembers which wallet it came from, its **profile**. A request the wallet can't take is refused
before anything is shown.

| Profile | Codes | Limits | At add |
|---|---|---|---|
| `keycard_shell` | 300 bytes a part, every 200 ms, at most version 25 | 40 inputs and 40 outputs; EVM chain ids that fit an int32 | the seed's unlock key, one more request and answer |
| `generic` | 200 bytes a part, every 250 ms, at most version 20 | none | no unlock key: its wallet unlocks by a password |

The profile is the one `scan_accounts` names, else the one the code names (`crypto-multi-accounts` says
which device), else `generic`.

When a terminal shows the codes (`qr_scanner_module`'s presenter), its size can allow only smaller ones: the
scanner's `poll` says the largest version that fits (`presenter_max_version`). If the parts don't fit it,
the signer splits the request again into smaller parts, more of them, and restarts the session with them.

## The seed's unlock key

Every account names its `seed`: its wallet's master fingerprint, in hex, as QR Wallets keys a wallet. The
signer manager unlocks that seed's data, in every app, with the public key at `m/1280263247'/n'` (the
signer interface's [`unlock`](https://github.com/logos-co/logos-signer-interface/blob/main/src/unlock.rs)),
which every holder of the seed gives. A QR wallet can't export a key on request, but it signs: the signer
shows an `eth-sign-request` of "Logos: unlock this wallet's data on this computer. Signing this moves no
funds." at that path, with the wallet's master fingerprint and no address, and recovers the key from the
`eth-signature` the wallet shows back (`verify::recover_key`). A Keycard Shell, firmware 1.4.0, gives the
same key this way as over USB and as the phrase derives (measured). EIP-1581 paths fail over QR: the
Shell's card refuses them.

- **At add**, a `keycard_shell` wallet shows one more request after its account code: the key at index 0.
  The module then registers the seed with the manager, `enroll_seed({ seed, kind: "qr", unlockKey, name
  })` through `logos.wallets/1` (`wallets.lidl`), bound to `signer_manager_module` at runtime and asked
  without waiting. `add_status` says `step: unlock_key` meanwhile, and `unlockKey: true` once done. A
  wallet that doesn't answer still adds (`unlockKey: false`), and so does a `generic` one, which is never
  asked: the seed is registered without a key, and its wallet unlocks by a password set in the Signer app.
  Cancelling the scan during that request cancels the add.
- **`unlock_key`** (`{ seed, index }`, the signer manager alone) returns a job in `confirm_on_device`
  while the request shows and its answer is read, in a scanner session titled "Unlock with your QR
  wallet", so whichever app draws signing sessions draws it too. `unlock_key_result` gives the key once.
  A seed no account comes from is `wrong_seed`. A QR wallet can't be asked which seed it holds: another
  wallet's answer gives another key, which the manager finds unwraps nothing.
- Anyone who photographs the wallet's answer can recover that seed's key at that index; the manager then
  moves the seed to its next index.

## Guards

- A Bitcoin request may bring its wallet's `xpub`; one that isn't the account's is refused (`invalid`).
- Nothing signs under the reserved purpose `m/1280263247'`: an account whose path sits there, or a PSBT
  naming a key there in any input, output or global xpub, is refused before anything is shown.
- An EVM account's path must sit under `m/44'/60'`, as an edited `accounts.json` could put it elsewhere.
- `qr_scanner_module` shows an `eth-sign-request` under the reserved purpose only for this module.

## Methods

The signer interface's, as every signer implements them: `signer_info`, `signer_accounts`, `sign`,
`sign_status`, `sign_result`, `cancel_sign`, and, for the signer manager alone, `unlock_key`,
`unlock_key_status`, `unlock_key_result` and `cancel_unlock_key`. `signer_info` says kind `qr`, request
kinds `evm_transaction`, `evm_message`, `evm_typed_data` and `btc_psbt`, `showsRequest: true`,
`unlockKey: true`, and that it collects nothing.

A job stays `confirm_on_device` while the person scans the codes, confirms on the wallet and holds its answer
up to the camera, for at most 10 minutes. Cancelling it, or pressing Cancel in the Logos QR window, closes
the scanner's session.

An account scan waits at most 3 minutes for the wallet's code. A new `scan_accounts` stops one still
running, since it is the same person trying again; a signature in progress answers `busy` instead.

For the app:

| Method | Parameters | Answer |
|---|---|---|
| `profiles` | | `{ ok, profiles: [{ name, label }] }` |
| `scan_accounts` | `{ families, label?, profile? }` | `{ ok, job }`. Reads the wallet's account code and offers an account of each family it holds: `evm`, `bitcoin` (native segwit, BIP84) and `bitcoin_taproot` (BIP86) |
| `add_status` | `job` | `{ ok, job, state, step?, accounts, unlockKey?, error? }`, `state` being `scanning`, `done`, `failed` or `cancelled`. While scanning, `step` is `account_code`, then `unlock_key` while the seed's unlock key is asked for; once done, `unlockKey` says whether the wallet gave it |
| `cancel_scan` | `job` | `{ ok, cancelled }`, whether the scan was still running |
| `remove_account` | `id` | `{ ok, removed }`. Nothing on the wallet changes |
| `rename_account` | `id, label` | `{ ok, renamed }`. The name apps see, up to 80 characters; blank clears it |
| `wallets` | | `{ ok, wallets: [{ fingerprint, profile, label, name }] }`: each wallet accounts came from, by master fingerprint, the profile it follows and the name given to it |
| `rename_wallet` | `fingerprint, name` | `{ ok, renamed }`. Names a wallet some account came from, up to 80 characters; blank clears it. The name goes with the wallet's last account |

Accounts are kept in `accounts.json` in the module's own directory, readable by its owner alone (0600):
public material, the wallet's master fingerprint, the profile and the device its code names, and the
wallets' names. Each `signer_accounts` row names its `seed`, a Bitcoin one its roster `key` too, and carries
the signer interface's `origin`: the wallet as the device (`kind: "qr"`, named by the model its code names,
else its profile, as `name` and `model`, with its `profile`), and `phrase` as `{ id: "fp:<fingerprint>",
name }`. Ids are as the Keycard Shell's USB module names them: the address for EVM,
`qr-<fingerprint>-<purpose>-<coin>-<account>` for Bitcoin. When the same account is offered by two signers,
the manager gives it to the one it consults first.

### Events

| Event | Arguments |
|---|---|
| `signer_accounts_changed` | `count` |
| `sign_progress` | `job, state` |

## The scanner

Calls to `qr_scanner_module` run on job threads, through its generated client's `_async_with_timeout`
methods, each answer waited for on a channel: a blocking call from a worker would run as a nested event
loop on the module's main thread. Before the module unloads, waiting calls are answered first.

## Tests

- `cargo test --no-default-features --features emulator`: the UR types, the fountain codes, accounts against
  BIP84's and BIP86's xpubs, the v forms, and end to end against `qr-device-emulator` with the scanner in
  process: the unlock key equal to the mock signer's for the same seed at index 0 and 1, the seed
  registered at add with it or without it, the guards, a 0600 `accounts.json`, and the signer interface's
  conformance suite for both profiles.
- **The emulator** (`nix build .#emulator`) is a QR wallet in software behind the QR helper's fake mode: it
  reads the frames the helper would show, signs with the signer interface's mock keys, and holds up its
  answer as pictures of QR codes. Asked to scan with nothing shown, it shows its accounts; a message at the
  reserved purpose it signs with the key at that path, as the Shell does.
  `qr-psbt-for` makes a PSBT spending two made-up coins of an account, for the doctest and by hand.
- **The doctest** runs the signer, the scanner, the helper in fake mode, the emulator and the signer
  manager through `logoscore`.

## By hand

With a Keycard Shell and a camera:

1. Load `qr_scanner_module`, `qr_signer_module` and the signer manager in a `logoscore` daemon.
2. `scan_accounts` with the families wanted; on the Shell, Connect software wallet. The Logos QR window
   reads its code, then shows a message to sign for the seed's unlock key, which the Shell scans and
   confirms.
3. Sign a message, an EVM transaction and a PSBT from `qr-psbt-for` through the manager: each request shows
   in the window, the Shell scans it and asks to confirm, then shows its answer for the camera.
