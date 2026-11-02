# MSI validation matrix

CI (`msi` job, windows-2022 and windows-2025) runs `scripts/msi-check.ps1`: failed
enrollment rolls back cleanly and the log holds no token, install, repair keeps
`slots` and `state.json`, uninstall wipes everything. CI cannot enroll against a
real server, so enrollment is validated by hand on real machines:

- Windows 10 22H2
- Windows 11 24H2
- Windows Server 2019
- Windows Server 2022

Use a fresh, disposable VM (snapshot it) for each OS. Do not use a machine that
already runs the RMM agent.

## 1. Build the MSI

On a Windows build machine (see `docs/runbooks/msi-install.md`), with
`RMM_ROOT_PUBKEYS` set to the root keys of the dev stack (`RMM_ROOT_PUBKEYS` in
`deploy/.env`):

```
cargo run -p xtask -- msi --out dist
```

Copy `dist\rmm-agent-<v>-x64.msi` to the VM.

## 2. Expose the dev stack to the VM over TLS

1. On the Docker host run `RMM_HTTPS_PORT=443 scripts/dev-up.sh`. nginx listens
   on all interfaces. Allow the port through the host firewall.
2. The dev server certificate is issued for `localhost`, `rmm.local` and 127.0.0.1 (see `scripts/dev-certs.sh`); use `rmm.local`.
   Make the VM resolve one of them to the host, for example add
   `<host-ip> rmm.local` to `C:\Windows\System32\drivers\etc\hosts`, and use
   that name in `SERVER_URL`. If the host name is not in the certificate,
   regenerate it with `scripts/dev-certs.sh --force` after adding the name.
3. Import the dev CA into the VM machine store (elevated PowerShell):
   `Import-Certificate -FilePath .\ca.pem -CertStoreLocation Cert:\LocalMachine\Root`
   (copy `deploy/dev/certs/ca.pem` to the VM; rename to `ca.crt` if the cmdlet
   rejects the extension).
4. Check from the VM: `curl.exe https://rmm.local/healthz` returns `ok`.

Remove the CA from the VM store when done. Never import the dev CA on a
production or shared machine.

## 3. Create an enrollment token

Mint a technician token and create a token (see "Technician tokens in dev" in
`docs/dev-environment.md`), with `max_uses` 1 and `expires_in_hours` 1. Use a
new token per VM. Note the client and site ids.

## 4. Silent install

Elevated prompt on the VM:

```
msiexec /i rmm-agent-<v>-x64.msi /qn SERVER_URL=https://rmm.local ENROLL_TOKEN=rmmenr_... /l*v C:\install.log
echo %ERRORLEVEL%
```

Expected: exit code 0 (or 3010). Then confirm:

- `Get-Service RMMWatchdog` shows Running, start type Automatic, `sc.exe qc RMMWatchdog` shows LocalSystem.
- `C:\ProgramData\RMM\bootstrap\rmm-agent.exe` exists and the watchdog started it
  (`Get-Process rmm-agent`).
- `C:\install.log` does not contain the token: `Select-String -Path C:\install.log -Pattern rmmenr_ -SimpleMatch` returns nothing.
- Enrollment: the device appears in the API/console under the client and site
  with agent status `active`; `last_seen` advances at the heartbeat interval
  (30 s default). For a database check run on the Docker host:
  `docker compose -f deploy/compose.yaml exec -T timescale psql -U rmm -d rmm -c "select status, last_seen from tenant.agent order by created_at desc limit 1"`.
- Reusing the same token on a second install fails with exit code 1603 and rolls
  back (no service left).

## 5. Repair keeps slots

1. `Stop-Service RMMWatchdog`, then create a marker:
   `New-Item C:\ProgramData\RMM\slots\a -ItemType Directory -Force; Set-Content C:\ProgramData\RMM\slots\a\marker.txt keep`
   and record `Get-FileHash C:\ProgramData\RMM\state.json` if the file exists.
2. Delete `C:\Program Files\RMM\rmm-session.exe`.
3. `msiexec /fa rmm-agent-<v>-x64.msi /qn /l*v C:\repair.log`
4. Expected: `rmm-session.exe` is back, the service is Running, `marker.txt`
   and the `state.json` hash are unchanged, the device is still active and no
   second device record was created.

## 6. Uninstall is clean

```
msiexec /x rmm-agent-<v>-x64.msi /qn /l*v C:\uninstall.log
```

Expected: no `RMMWatchdog` service (`sc.exe query RMMWatchdog` reports 1060),
`C:\Program Files\RMM` and `C:\ProgramData\RMM` gone (including `slots` and
`state.json`), no `RMMSession` value under
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`. The server-side device
stays; revoke it in the console afterwards.

## Results

One row per run. Leave empty until tested; use pass, fail (with a note below the
table) or n/a.

| OS | Build | Date | Tester | Install | Enroll | Repair | Uninstall |
|----|-------|------|--------|---------|--------|--------|-----------|
| Windows 10 22H2 | | | | | | | |
| Windows 11 24H2 | | | | | | | |
| Windows Server 2019 | | | | | | | |
| Windows Server 2022 | | | | | | | |

Notes on failures:
