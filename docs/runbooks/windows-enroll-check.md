# Runbook: Windows VM enrollment check (manual)

CI has no Windows VM that can reach the dev stack, so the Windows path of
phase 3 (DPAPI key in the SYSTEM scope, protected key file ACL, WSS on 443) is
checked by hand before a release. Record the date, agent commit and result of
each step in the release notes.

## Prerequisites

- A Windows 10/11 or Server 2022+ x64 VM that can reach the dev or staging
  server on TCP 443, with a local administrator account.
- The server stack running with the auth callout (`scripts/dev-up.sh`) on a
  host name the VM can resolve, with a certificate the VM trusts. For the dev
  CA, import `deploy/dev/certs/ca.pem` into *Local Computer > Trusted Root
  Certification Authorities* (dev builds also honour `RMM_AGENT_EXTRA_CA`).
- A client and site in the database, and an RMM.Admin token
  (`docs/dev-environment.md`, "Technician tokens in dev").

## 1. Build the agent (MSVC)

On a Windows build machine with the Rust toolchain from `rust-toolchain.toml`:

```
cargo build --locked -p rmm-agent
```

or take the `rmm-agent-windows-x64` artifact from the CI `windows-cross` job.
A release build needs `RMM_ROOT_PUBKEYS` (and optionally
`RMM_ROOT_THRESHOLD`) set at build time. Copy `rmm-agent.exe` to
`C:\Program Files\RMM\rmm-agent.exe` on the VM.

## 2. Create a single-use enrollment token

```
curl --cacert ca.pem -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST -d '{"client_id":"<client>","site_id":"<site>","expires_in_hours":1,"max_uses":1,"allow_reattach":false}' \
  https://<server>/api/v1/enrollment-tokens
```

Keep the `token` value (`rmmenr_...`); it is shown only once.

## 3. Enroll and run as SYSTEM

The key must be created by SYSTEM so that DPAPI binds it to the SYSTEM user
scope. In an elevated PowerShell:

```
$exe = 'C:\Program Files\RMM\rmm-agent.exe'
$argline = 'enroll --server https://<server> --token rmmenr_...'
$a = New-ScheduledTaskAction -Execute $exe -Argument $argline
Register-ScheduledTask -TaskName 'rmm-enroll' -Action $a -User 'SYSTEM' -RunLevel Highest
Start-ScheduledTask -TaskName 'rmm-enroll'
Start-Sleep 15
(Get-ScheduledTaskInfo -TaskName 'rmm-enroll').LastTaskResult   # expect 0
Unregister-ScheduledTask -TaskName 'rmm-enroll' -Confirm:$false
```

Exit codes: 0 enrolled, 2 already enrolled, 3 token rejected, 4 server
unreachable, 1 other error. Then start the connection the same way:

```
$a = New-ScheduledTaskAction -Execute $exe -Argument 'run'
Register-ScheduledTask -TaskName 'rmm-run' -Action $a -User 'SYSTEM' -RunLevel Highest
Start-ScheduledTask -TaskName 'rmm-run'
```

## 4. Check the key file and its ACL

```
Get-ChildItem C:\ProgramData\RMM
icacls C:\ProgramData\RMM\agent.key
```

Pass when `agent.key`, `identity.json` and `trust\` exist and icacls lists
exactly one entry, `NT AUTHORITY\SYSTEM:(F)`, with no inherited (`(I)`)
entries, so Administrators, Users and the installing account have no access.
As a local administrator `Get-Content C:\ProgramData\RMM\agent.key` must fail
with access denied. The file content is a DPAPI blob, not a 32-byte raw key.

## 5. Check the connection on 443

- On the VM: `Get-NetTCPConnection -State Established -RemotePort 443` shows
  a connection owned by the `rmm-agent.exe` process, and nothing to port
  4222.
- On the server: `docker compose -f deploy/compose.yaml logs authd` shows
  `nats auth allow` with the agent id, and
  `curl -s 'http://127.0.0.1:8222/connz?subs=1' | python3 -m json.tool` lists a
  connection whose `name` starts with `rmm-agent/` and whose
  `authorized_user` / `user` is the agent nkey.
- In the database, `msp.audit_event` has `agent.enroll` and
  `nats.auth.allow` rows for the agent, and `tenant.agent.last_seen` is
  recent.

## 6. Revoke (optional)

`POST /api/v1/agents/<agent_id>/revoke` with the admin token. Within 5 s the
connection on the VM disappears, authd logs `revoked agent connections
kicked`, and later reconnects are logged as `nats auth deny`.

## Cleanup

```
Unregister-ScheduledTask -TaskName 'rmm-run' -Confirm:$false
Stop-Process -Name rmm-agent -ErrorAction SilentlyContinue
```

To repeat with a fresh identity, delete `C:\ProgramData\RMM` as SYSTEM or
run `rmm-agent enroll --force`.
