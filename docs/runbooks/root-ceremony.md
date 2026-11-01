# Runbook: root key ceremony

Purpose: create the offline root signing key, produce two encrypted copies, record the public key that is compiled into the agent, and sign the first trust manifest. The root key signs trust manifests only; day to day signing uses YubiKeys (`yubikey-setup.md`).

Roles: the **operator** performs the steps, the **witness** watches and signs off. They must be two different people. The root key is a single Ed25519 key, so a ceremony with `root_threshold` 1 needs one root key; for a higher threshold run keygen once per root key and sign with `--add-to` (below).

## Before the ceremony

- Provision the daily and backup YubiKeys first (`yubikey-setup.md`), so their `key_id` and `public_key` values are known.
- Prepare the command key (the server's command-signing key) public key and `key_id`.
- Prepare the manifest draft `manifest.json` (see "Manifest draft") on a separate USB stick. Review it with the witness before the ceremony; it contains no secrets.
- Two USB sticks for the encrypted key copies, one for offsite storage, one for the safe.
- A build of `rmm-sign` for the live system (built from a reviewed commit, `cargo build --release -p rmm-sign --locked`, with the hash of the binary recorded).

## Air-gapped laptop

1. Boot a trusted laptop from a live USB image. Disable Wi-Fi and Bluetooth in firmware if possible, remove network cables, and check with `ip link` that no interface is up.
2. Insert the USB stick holding the `rmm-sign` binary and `manifest.json`. Verify the binary hash against the recorded value.
3. Work in a RAM disk: `mkdir -p /dev/shm/ceremony && cd /dev/shm/ceremony`. Nothing is written to the laptop's disk.

## Generate the root key

```sh
rmm-sign keygen-root --out root.age
```

Enter a strong passphrase twice (at least six random words). The command prints `public_key` and `key_id`. The key file is an age passphrase-encrypted Ed25519 seed and refuses to overwrite an existing file. Do not set `RMM_SIGN_PASSPHRASE` in the shell: the passphrase would end up in history.

Write `public_key` and `key_id` on the sign-off sheet. The witness reads them back from the screen and compares.

## Two encrypted copies

Copy `root.age` to both USB sticks. Check each copy by decrypting its public key:

```sh
rmm-sign pubkey --backend file:/media/copy-1/root.age   # must print the same key_id
rmm-sign pubkey --backend file:/media/copy-2/root.age
```

Store one stick in the safe and one offsite. The passphrase is stored separately from the sticks (sealed envelope with the admin PINs of the YubiKeys, in the safe). Only the encrypted file ever leaves the RAM disk.

## Record the root public key

The `public_key` hex value is compiled into the agent as its trust anchor. Hand it to the build: commit it (public value, no secret) as agreed with the release owner, and rebuild the agent with it. Record the `key_id` in the key register. Without this step no agent trusts anything the ceremony signs.

## Manifest draft

`manifest.json` is a `TrustManifest` document. It lists the root key(s) and threshold and certifies the daily YubiKey, the backup YubiKey and the command key:

- `root_keys`: the root `public_key` value(s); `root_threshold`: 1 for a single root.
- `certs`: one entry per certified key with `key_id`, `pubkey`, `alg` "ed25519", `roles`, `not_before`, `not_after`, `label`. The daily and backup YubiKeys carry the roles they sign for (`techlist`, `catalog`, `release`, `artifact-revoke`, `policy` as needed); the command key carries `command`.
- `thresholds`: signatures required per role.
- `seq` strictly increasing, `issued_at`, `expires_at` (at most 400 days after `issued_at`), `console_rp_id`, `console_origins`.

Unknown fields are rejected, so typos fail early.

## Sign the first manifest

```sh
rmm-sign sign --type manifest --in manifest.json --backend file:root.age --out manifest.env
```

`rmm-sign` validates the draft, shows the full document as a diff, and asks you to type `yes`. The operator and witness read the diff aloud against the prepared values (keys, roles, expiry). Typing `yes` signs.

For `root_threshold` above 1, each root holder signs the same draft in turn, passing the previous result:

```sh
rmm-sign sign --type manifest --in manifest.json --backend file:root-2.age --add-to manifest.env --out manifest-2.env
```

`--add-to` refuses an envelope with a different payload.

## Verify it

```sh
rmm-sign verify --roots <root public_key hex> --root-threshold 1 manifest.env
rmm-sign inspect manifest.env
```

`verify` must print `OK` and the root `signer:` key id(s), followed by the document. Check the certified key ids against the key register. Copy `manifest.env` to the transfer stick, power off the laptop (the RAM disk disappears).

## Yearly re-sign

The manifest expires (at most 400 days). Re-sign at least 30 days before expiry:

1. Fetch the current envelope as the reference. Edit `manifest.json`: increase `seq`, set new `issued_at` and `expires_at`, and apply changes (new or revoked keys).
2. Repeat "Sign the first manifest" with `--prev manifest-current.env` so the diff shows only what changed.
3. Verify, then publish through the trust-update path.
4. Run a mini dry run of this runbook's checklist beforehand; check that both root copies still decrypt.

## Dry run checklist

Hold a dry run before the real ceremony and repeat it before each yearly re-sign. Use a throwaway key and a dummy manifest; never the real passphrase.

- [ ] Live USB boots; network is disabled (`ip link` shows no active interface).
- [ ] `rmm-sign` hash matches the recorded value.
- [ ] `keygen-root` succeeds; `key_id` read back by the witness.
- [ ] A second `keygen-root` to the same path refuses to overwrite.
- [ ] A wrong passphrase fails (exit status 2) and writes no output.
- [ ] Both USB copies decrypt to the same `key_id`.
- [ ] Manifest signed; the diff was read aloud; `verify` prints OK with the expected signer.
- [ ] A tampered copy of `manifest.env` fails `verify`.
- [ ] Time taken and problems recorded; runbook updated for any deviation.

## Sign-off

| Step | Date | Operator | Witness | Result / notes |
| --- | --- | --- | --- | --- |
| Dry run completed |  |  |  |  |
| Air-gapped laptop prepared |  |  |  |  |
| Root key generated, `key_id` read back |  |  |  |  |
| Copy 1 (safe) verified and stored |  |  |  |  |
| Copy 2 (offsite) verified and stored |  |  |  |  |
| Root public key handed to the build |  |  |  |  |
| First manifest signed and verified |  |  |  |  |
| Laptop powered off, RAM disk gone |  |  |  |  |
| Yearly re-sign (repeat per year) |  |  |  |  |
