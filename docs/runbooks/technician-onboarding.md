# Runbook: technician onboarding and offboarding (co-signed shell)

Purpose: let a technician open remote shells on client machines, and remove them again. A shell opens only when three things agree: the API grants it, the technician's hardware key co-signs it (touch plus PIN), and the agent finds the technician and that key in the techlist signed offline. Removing someone from the signed techlist locks them out at the agent, whatever the server says.

Requirements: the technician has a YubiKey 5 (or another key whose AAGUID you allowlisted, see `deploy/.env.example`), a browser with WebAuthn, and an Entra account; the signer holds the techlist YubiKey (see `yubikey-setup.md`) and a checkout with `rmm-sign`.

The dev stack replaces the YubiKey with `cargo run -p xtask -- fake-authn`. It is for development and CI only: production lists only the vendor's attestation roots and your keys' AAGUIDs (`RMM_WEBAUTHN_ATTESTATION_ROOTS`, `RMM_WEBAUTHN_AAGUIDS`), neither of which contains the dev root or the dev AAGUID `726d6d2d6465762d66616b652d6b6579`. Never put the dev values in a production environment, and never pass `--allow-aaguid` for the dev AAGUID when signing a production techlist.

## 1. Register the technician's key

The technician signs in to the console and starts "Register security key". The console calls `POST /api/v1/technicians/me/credentials/register/begin`, runs `navigator.credentials.create` (attestation `direct`, user verification required) and posts the result to `.../register/finish`. The API accepts only a `packed` attestation whose certificate chain ends at a configured root and whose AAGUID is allowlisted; anything else (software keys, passkeys that sync, `none` attestation) is refused with 422 and audited as `webauthn.register_rejected`.

Give each technician two keys (daily and backup) so a lost key does not lock them out.

## 2. Assign clients

A technician may act only on the clients assigned in `msp.technician_client`. Until a client is assigned, the draft lists the technician with an empty scope and every grant for that client answers 403.

```sql
insert into msp.technician_client (tech_id, client_id) values ('<entra sub>', '<client uuid>');
```

## 3. Export, review and sign the techlist

An admin exports the draft:

```sh
curl -H "Authorization: Bearer $ADMIN" https://<api>/api/v1/admin/techlist-draft > techlist.json
```

`seq` is the stored techlist's plus one, `issued_at` is now and `expires_at` is 30 days later. Review the technicians, client scopes and credentials (AAGUIDs) in the diff `rmm-sign` shows. Then sign with the techlist YubiKey (PIN, then touch):

```sh
rmm-sign sign --type techlist --in techlist.json --backend card --expect-key-id <key_id> --out techlist.env
```

`rmm-sign` refuses an entry whose credential AAGUID is not a YubiKey 5 AAGUID (or one given with `--allow-aaguid`, dev only).

## 4. Publish

```sh
curl -X PUT -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/octet-stream' \
  --data-binary @techlist.env https://<api>/api/v1/trust/techlist     # 204
```

The server verifies the signature and stores it; enrolling agents get it in their bundle. Re-sign and publish before `expires_at`: an agent refuses shells once its techlist is stale. Running agents pick up a new techlist on their own: each agent asks the server for the latest trust documents when it connects and every 15 minutes after that, verifies them like any other trust update, and closes open sessions of technicians who are no longer listed.

## 5. Open a shell

The technician picks an agent in the console: `POST /api/v1/agents/{agent_id}/shell {"shell":"sh"}` returns a challenge (valid 60 s); the browser runs `navigator.credentials.get` with the key (touch, PIN) and posts the result to `POST /api/v1/shell-sessions/{grant_id}/open`; the response carries a one-time `ws_ticket` for the WebSocket relay. Every session is recorded (asciicast v2, including keystrokes) and kept for 365 days (`RMM_RECORDING_RETENTION_DAYS`); an admin downloads one from `GET /api/v1/shell-sessions/{session_id}/recording`. The logged-in user sees "IT is connected" while a session is open.

## 6. Offboard a technician

1. Revoke their credentials (`update msp.webauthn_credential set revoked_at = now() where tech_id = '<id>'`) so the API stops granting and the draft omits them.
2. Export a new draft, check the technician is gone, sign it with the techlist key and publish it (steps 3 and 4). Open sessions of that technician end with `tech_removed` once the agent applies the new list; new grants are refused with `unknown_tech`.
3. Disable the Entra account.

Do steps 1 and 2 first when the person is dismissed: the signed techlist, not the account, is what the agents trust.

## Known gaps

- `deploy/nginx/nginx.conf` does not forward WebSocket upgrades on `/api/`; add `proxy_http_version 1.1`, `Upgrade` and `Connection` headers and a long `proxy_read_timeout` for `/api/v1/shell-sessions/` before the browser console can use the relay through nginx.
- Recordings fill the disk without a quota; monitor the recording volume.
