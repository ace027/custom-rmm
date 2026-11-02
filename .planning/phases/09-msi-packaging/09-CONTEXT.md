# Phase 9: MSI packaging -- Context

## Phase Goal
A silent MSI install enrolls an internal Windows machine end to end; uninstall is clean and repair never touches updater-owned A/B slots.

## Requirements Covered
- REQ-22

## What Already Exists (from prior phases)
- rmm-watchdog (phase 8): Windows service entry `rmm-watchdog service`, root %ProgramData%\RMM with bootstrap/, slots/a|b, pending/, state.json; root DACL SYSTEM+Administrators
- rmm-agent: `enroll --server URL --token TOKEN [--state-dir] [--force]` with exit codes 2 already enrolled, 3 token rejected, 4 unreachable; `run`
- rmm-session: indicator helper (tray icon on Windows)
- CI: windows-cross (cargo-xwin on ubuntu), test-windows on windows-2025 (native tests, aarch64 check)
- No installer or WiX files exist yet

## Key Design Decisions
- WiX Toolset v5 as a pinned dotnet tool (`dotnet tool install --global wix --version 5.0.2` plus the WixToolset.Util.wixext extension at the same version) on the Windows runner; per-machine, x64, unsigned (Authenticode later)
- Layout: [ProgramFiles64Folder]RMM\rmm-watchdog.exe and rmm-session.exe; [CommonAppDataFolder]RMM\bootstrap\rmm-agent.exe (the MSI-owned bootstrap slot). slots/, pending/, state.json and the agent state are never MSI components, so repair and upgrade cannot overwrite them
- Service: ServiceInstall RMMWatchdog (display 'RMM Watchdog'), LocalSystem, auto start, arguments 'service', failure actions restart; ServiceControl start on install, stop+remove on uninstall
- rmm-session starts at user logon via an HKLM Run value
- Properties: SERVER_URL and ENROLL_TOKEN (Hidden, MsiHiddenProperties, never written to disk or the registry); a deferred, no-impersonate custom action runs `bootstrap\rmm-agent.exe enroll --server [SERVER_URL] --token [ENROLL_TOKEN] --if-not-enrolled` via WixQuietExec64 with HideTarget, scheduled before StartServices and only on first install when ENROLL_TOKEN is set; a failed enrollment fails and rolls back the install so deployment tooling sees it
- Agent change: `enroll --if-not-enrolled` returns 0 when the machine is already enrolled (instead of 2) and the token may also come from RMM_ENROLL_TOKEN when --token is absent
- Uninstall: removes the service, the program files, the bootstrap slot and, only on full uninstall (REMOVE=ALL and not UPGRADINGPRODUCTCODE), the whole %ProgramData%\RMM tree via util:RemoveFolderEx
- MajorUpgrade with a stable UpgradeCode; version from the workspace version
- Real enrollment across Win10, Win11, Server 2019 and Server 2022 is a manual validation run against the dev stack, recorded in a runbook table; CI covers install, repair and uninstall on windows-2022 and windows-2025 without a server (enrollment-failure rollback is exercised with an unreachable SERVER_URL)

## Plan Structure
- **Plan 09-01 (Wave 1)**: WiX package, xtask msi and agent enrollment flag -- Create the WiX v5 package for the watchdog service, bootstrap agent and session helper with ENROLL_TOKEN enrollment, an xtask msi builder, and the agent's --if-not-enrolled flag.
- **Plan 09-02 (Wave 2)**: MSI CI checks and Windows validation matrix -- Build the MSI in CI on windows-2022 and windows-2025 and check install, repair and uninstall behavior, and document the manual enrollment validation across Win10, Win11, Server 2019 and Server 2022.
