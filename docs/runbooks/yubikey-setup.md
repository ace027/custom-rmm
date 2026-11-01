# Runbook: provisioning YubiKeys for rmm-sign

Purpose: prepare a daily and a backup YubiKey 5 that hold an Ed25519 signing key in the OpenPGP signature slot. `rmm-sign` signs with them (PIN plus touch); the root key stays offline (see `root-ceremony.md`).

Requirements: YubiKey 5 with firmware 5.2.3 or later (Ed25519 in OpenPGP), `ykman` (yubikey-manager), `gpg` 2.2+ with `scdaemon` for the on-card key generation, `pcscd` running, and a checkout with `rmm-sign` built.

Do this on a trusted machine. Never script the PINs into shell history: type them at the prompts.

## 1. Reset and set PINs

Do this for each key. Skip the reset only if the key is brand new.

```sh
ykman openpgp reset                 # destroys all OpenPGP data on the key
ykman openpgp access change-pin             # user PIN, default 123456 -> your PIN (6-8 digits)
ykman openpgp access change-admin-pin       # admin PIN, default 12345678 -> long random value
ykman openpgp access set-retries 5 5 5      # PIN, reset code, admin PIN retries
```

Store the admin PIN with the root key copies (safe and offsite). The user PIN is known to its holder only.

## 2. Generate the Ed25519 key on the card

The private key is generated on the card and cannot be exported.

```sh
gpg --card-edit
gpg/card> admin
gpg/card> key-attr          # signature key: choose ECC, then Curve 25519 (Ed25519)
gpg/card> generate          # answer "n" when asked to make an off-card backup of the key
```

Only the signature slot is used by rmm-sign. The encryption and authentication slots may stay empty. `gpg --card-status` must show a signature key with `Key attributes: ed25519`.

## 3. Require touch for every signature

```sh
ykman openpgp keys set-touch sig fixed
```

`fixed` means a physical touch is required for every signature and the policy cannot be changed later without a reset. Check with `ykman openpgp info` (Signature key touch policy: Fixed).

## 4. Record the key id

```sh
cargo build -p rmm-sign --locked
target/debug/rmm-sign pubkey --backend card
```

Output: `public_key` and `key_id` (hex). With several keys plugged in, list the card idents with `gpg --card-status` (field "Serial number" gives `MMMM:SSSSSSSS` as `Application ID`) and select one: `--backend card:<ident>`.

Record, in the key register: holder, daily or backup, card ident, `key_id`, `public_key`, date. These are the values that the root-signed manifest certifies (`cert.key_id`, `cert.pubkey`).

Repeat steps 1-4 for the backup key and keep it in a different location from the daily key.

## 5. Hardware check

Run the recorded hardware check for every key after provisioning, and again after any firmware update:

```sh
scripts/yubikey-smoke.sh [card-ident]
```

It reads the card public key, creates a throwaway root, signs a manifest certifying the card key for `techlist`, signs a techlist with the card (the key blinks: touch it), and verifies the chain with `rmm-trust`. It prints `PASS key_id=<hex>` on success. Paste that line into the key register. Set `RMM_CARD_PIN` to avoid the PIN prompt.

## Using the key

```sh
rmm-sign sign --type techlist --in techlist.json --backend card --expect-key-id <key_id> --out techlist.env
```

`rmm-sign` prints `Touch your security key to sign...` and waits for the touch. `--expect-key-id` makes it refuse to sign if another card is present. Only an Ed25519 signature key is accepted.

## Troubleshooting

- `no OpenPGP card found`: check `pcscd` is running (`systemctl status pcscd`) and no other program (gpg-agent `scdaemon`) holds the card exclusively; `gpgconf --kill scdaemon` releases it.
- `several cards present`: pass `--backend card:<ident>`.
- `card signing key is not Ed25519`: redo step 2 with Curve 25519.
- Wrong PIN: the error comes from the card; three failures block the user PIN, unblock with the admin PIN (`ykman openpgp access unblock-pin`).
