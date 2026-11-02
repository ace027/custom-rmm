# MSI install, repair and uninstall

The installer is a per-machine, x64, unsigned MSI built from `installer/wix/Package.wxs`.

## Prerequisites (build machine, Windows)

- Rust toolchain and the repo checkout
- WiX 5 as a dotnet tool:
  `dotnet tool install --global wix --version 5.0.2`
  `wix extension add --global WixToolset.Util.wixext/5.0.2`
- `RMM_ROOT_PUBKEYS` set to the root public keys compiled into the release binaries

## Build

```
cargo run -p xtask -- msi [--out DIR] [--no-build]
```

This builds release `rmm-agent`, `rmm-watchdog` and `rmm-session`, stages them and
writes `<out>/rmm-agent-<version>-x64.msi` (default `target/msi`). `--no-build`
reuses `target/release`. On other platforms `--dry-run` prints the commands.

## Silent install and enrollment

```
msiexec /i rmm-agent-<v>-x64.msi /qn SERVER_URL=https://rmm.example.com ENROLL_TOKEN=rmmenr_... /l*v install.log
```

`ENROLL_TOKEN` is a hidden property: it is masked in `install.log` and never stored.
Enrollment runs once, before the service starts, via
`rmm-agent enroll --if-not-enrolled`. If it fails (bad token, server unreachable) the
install fails and rolls back, so deployment tooling sees a non-zero exit code
(1603). `SERVER_URL` is required whenever `ENROLL_TOKEN` is set.

Without `ENROLL_TOKEN` the service is installed but the machine is not enrolled;
enroll later with `rmm-agent enroll` from `%ProgramData%\RMM\bootstrap`.

## Repair

```
msiexec /fa rmm-agent-<v>-x64.msi /qn /l*v repair.log
```

Restores the MSI-owned files only. Updater-owned directories, state and the agent
identity under `%ProgramData%\RMM` are not touched, and enrollment is not repeated.

## Upgrade

Installing a newer MSI performs a major upgrade. The `%ProgramData%\RMM` tree is kept.

## Uninstall

```
msiexec /x rmm-agent-<v>-x64.msi /qn /l*v uninstall.log
```

| Item | Result |
|---|---|
| Service `RMMWatchdog` | stopped and removed |
| `%ProgramFiles%\RMM` (watchdog, session helper), logon Run value | removed |
| `%ProgramData%\RMM\bootstrap` | removed |
| Rest of `%ProgramData%\RMM` (updater files, state, identity) | removed on full uninstall only; kept on upgrade |

The server-side device record is not deleted; revoke it in the console.
