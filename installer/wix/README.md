# RMM Agent MSI (WiX v5)

`Package.wxs` builds a per-machine, x64, unsigned MSI. Build it with
`cargo run -p xtask -- msi` (see `docs/runbooks/msi-install.md`).

## Contents

- `%ProgramFiles%\RMM\rmm-watchdog.exe`: service `RMMWatchdog` (LocalSystem, auto start, restart on failure)
- `%ProgramFiles%\RMM\rmm-session.exe`: started at logon via an HKLM Run value
- `%ProgramData%\RMM\bootstrap\rmm-agent.exe`: the MSI-owned bootstrap copy of the agent

Updater-owned directories and state files under `%ProgramData%\RMM` are never
MSI components, so repair and upgrade cannot overwrite them.

## Properties

| Property | Meaning |
|---|---|
| `SERVER_URL` | Server base URL. Required when `ENROLL_TOKEN` is set. |
| `ENROLL_TOKEN` | One-time enrollment token (`rmmenr_...`). Hidden: kept out of the log, disk and registry. Optional: without it the service is installed but the machine is not enrolled. |

Enrollment runs only on first install (`NOT Installed AND ENROLL_TOKEN`) as a
deferred, non-impersonated action before the service starts, using
`enroll --if-not-enrolled`. A failed enrollment fails and rolls back the install.

## Commands

```
msiexec /i rmm-agent-<v>-x64.msi /qn SERVER_URL=https://rmm.example.com ENROLL_TOKEN=rmmenr_... /l*v install.log
msiexec /fa rmm-agent-<v>-x64.msi /qn /l*v repair.log
msiexec /x rmm-agent-<v>-x64.msi /qn /l*v uninstall.log
```

Uninstall removes the service and program files and, only on a full uninstall
(`REMOVE=ALL` and not a major upgrade), the whole `%ProgramData%\RMM` tree.

## Build inputs

`wix build Package.wxs -arch x64 -ext WixToolset.Util.wixext -d Version=<v> -d BinDir=<dir>`
with WiX 5.0.2 (`dotnet tool install --global wix --version 5.0.2`, then
`wix extension add --global WixToolset.Util.wixext/5.0.2`).
