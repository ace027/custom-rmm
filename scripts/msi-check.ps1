<#
.SYNOPSIS
  Checks MSI install rollback, install, repair and uninstall on a Windows machine.

.DESCRIPTION
  Run as administrator on a disposable machine (CI runner or throwaway VM). It
  exits non-zero on the first failed check and prints one PASS or FAIL line per
  check. Verbose msiexec logs are written to -LogDir.

  Exit codes 0 and 3010 (reboot required) from msiexec count as success.
#>
param(
    [Parameter(Mandatory = $true)][string]$Msi,
    [string]$LogDir = (Join-Path (Get-Location) 'msi-logs')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'RMMWatchdog'
$TestToken = 'rmmenr_test'
$ProgFiles = Join-Path $env:ProgramFiles 'RMM'
$DataRoot = Join-Path $env:ProgramData 'RMM'
$Bootstrap = Join-Path $DataRoot 'bootstrap'
$BootstrapExe = Join-Path $Bootstrap 'rmm-agent.exe'
$RunKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'

function Pass([string]$Name) { Write-Host "PASS: $Name" }

function Fail([string]$Name, [string]$Detail) {
    Write-Host "FAIL: $Name - $Detail"
    throw "check failed: $Name"
}

function Check([string]$Name, [bool]$Condition, [string]$Detail) {
    if ($Condition) { Pass $Name } else { Fail $Name $Detail }
}

function Get-Svc { Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue }

function Invoke-Msi([string]$Verb, [string]$Log, [string]$Extra) {
    $argLine = "$Verb `"$Msi`" /qn /l*v `"$Log`" $Extra"
    $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $argLine -Wait -PassThru -NoNewWindow
    return [int]$p.ExitCode
}

function Test-MsiOk([int]$Code) { return ($Code -eq 0 -or $Code -eq 3010) }

function Wait-ServiceRunning([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $s = Get-Svc
        if ($s -and $s.State -eq 'Running') { return $true }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Get-Hash([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash }

function Test-RunValue {
    $item = Get-ItemProperty -Path $RunKey -Name 'RMMSession' -ErrorAction SilentlyContinue
    return [bool]$item
}

if (-not (Test-Path -LiteralPath $Msi)) { throw "MSI not found: $Msi" }
$Msi = (Resolve-Path -LiteralPath $Msi).Path
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run as administrator'
}
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogDir = (Resolve-Path -LiteralPath $LogDir).Path

# Fail fast on a dirty machine: results would be meaningless.
if (Get-Svc) { Fail 'clean machine' "service $ServiceName already exists" }
if (Test-Path -LiteralPath $ProgFiles) { Fail 'clean machine' "$ProgFiles already exists" }
if (Test-Path -LiteralPath $DataRoot) { Fail 'clean machine' "$DataRoot already exists" }
Pass 'clean machine (no RMMWatchdog, Program Files\RMM or ProgramData\RMM)'

$installed = $false
try {
    # 1. Enrollment against an unreachable server must fail and roll back cleanly.
    $log1 = Join-Path $LogDir 'install-rollback.log'
    $code = Invoke-Msi '/i' $log1 "SERVER_URL=https://127.0.0.1:9 ENROLL_TOKEN=$TestToken"
    Check 'enroll failure fails the install' (-not (Test-MsiOk $code)) "msiexec exit $code, expected non-zero"
    Pass "msiexec exit code $code"
    Check 'rollback: no RMMWatchdog service' ($null -eq (Get-Svc)) 'service still present'
    Check 'rollback: no Program Files\RMM' (-not (Test-Path -LiteralPath $ProgFiles)) "$ProgFiles still present"
    Check 'rollback: no ProgramData\RMM\bootstrap' (-not (Test-Path -LiteralPath $Bootstrap)) "$Bootstrap still present"
    Check 'rollback: no Run value' (-not (Test-RunValue)) 'RMMSession Run value still present'
    $leak = Select-String -LiteralPath $log1 -Pattern $TestToken -SimpleMatch -Quiet
    Check 'log does not contain the token' (-not $leak) "$log1 contains the enrollment token"
    # The failure must come from the agent actually running, not from an empty command.
    $ran = Select-String -LiteralPath $log1 -Pattern 'server unreachable' -SimpleMatch -Quiet
    Check 'rollback: failure came from the agent (server unreachable in log)' $ran "$log1 has no agent error text"

    # 1b. Successful enrollment against a local stub server (loopback http is accepted).
    $port = 18943
    $stubBody = Join-Path $LogDir 'stub-request.json'
    Remove-Item -LiteralPath $stubBody -Force -ErrorAction SilentlyContinue
    $stub = Start-Job -ArgumentList $port, $stubBody -ScriptBlock {
        param($Port, $BodyFile)
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add("http://127.0.0.1:$Port/")
        $l.Start()
        try {
            $ctx = $l.GetContext()
            $reader = New-Object System.IO.StreamReader($ctx.Request.InputStream)
            [System.IO.File]::WriteAllText($BodyFile, $reader.ReadToEnd())
            $resp = @{
                agent_id = '00000000-0000-0000-0000-0000000000a1'
                device_id = '00000000-0000-0000-0000-0000000000d1'
                client_id = '00000000-0000-0000-0000-0000000000c1'
                nats_url = 'nats://127.0.0.1:4222'
                trust = @{ manifest = $null; revocations = $null; techlist = $null }
                status = 'active'
            } | ConvertTo-Json -Depth 4
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($resp)
            $ctx.Response.ContentType = 'application/json'
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $ctx.Response.Close()
        } finally { $l.Stop() }
    }
    try {
        Start-Sleep -Seconds 2
        $logE = Join-Path $LogDir 'install-enroll.log'
        $code = Invoke-Msi '/i' $logE "SERVER_URL=http://127.0.0.1:$port ENROLL_TOKEN=$TestToken"
        $installed = $true
        Check 'enroll install succeeds' (Test-MsiOk $code) "msiexec exit $code"
        Check 'stub server received the enrollment request' (Test-Path -LiteralPath $stubBody) 'no request reached the stub'
        Check 'stub request carried the token' ((Get-Content -LiteralPath $stubBody -Raw) -match [regex]::Escape($TestToken)) 'token missing from request'
        $identityFile = Join-Path $DataRoot 'identity.json'
        Check 'enrolled: identity.json exists' (Test-Path -LiteralPath $identityFile) "$identityFile missing"
        Check 'enrolled: identity has the stub agent id' ((Get-Content -LiteralPath $identityFile -Raw) -match '0000000000a1') 'agent_id not in identity.json'
        $leak = Select-String -LiteralPath $logE -Pattern $TestToken -SimpleMatch -Quiet
        Check 'enroll success log does not contain the token' (-not $leak) "$logE contains the enrollment token"
        $p = Start-Process -FilePath $BootstrapExe -NoNewWindow -Wait -PassThru -ArgumentList @('enroll', '--server', "http://127.0.0.1:$port", '--token', $TestToken, '--if-not-enrolled')
        Check '--if-not-enrolled exits 0 when enrolled' ($p.ExitCode -eq 0) "exit $($p.ExitCode)"
    }
    finally {
        Stop-Job -Job $stub -ErrorAction SilentlyContinue
        Remove-Job -Job $stub -Force -ErrorAction SilentlyContinue
    }
    $code = Invoke-Msi '/x' (Join-Path $LogDir 'uninstall-enroll.log') ''
    Check 'enroll install: uninstall succeeds' (Test-MsiOk $code) "msiexec exit $code"
    $installed = $false
    Check 'enroll install: ProgramData\RMM gone' (-not (Test-Path -LiteralPath $DataRoot)) "$DataRoot still present"

    # 2. Plain install without a token.
    $log2 = Join-Path $LogDir 'install.log'
    $code = Invoke-Msi '/i' $log2 ''
    $installed = $true
    Check 'install succeeds' (Test-MsiOk $code) "msiexec exit $code"
    $svc = Get-Svc
    Check 'service exists' ($null -ne $svc) "$ServiceName missing"
    Check 'service runs as LocalSystem' ($svc.StartName -eq 'LocalSystem') "StartName is $($svc.StartName)"
    Check 'service start mode is Auto' ($svc.StartMode -eq 'Auto') "StartMode is $($svc.StartMode)"
    Check 'service Running within 30 s' (Wait-ServiceRunning 30) 'service not Running after 30 s'
    Check 'bootstrap agent exists' (Test-Path -LiteralPath $BootstrapExe) "$BootstrapExe missing"
    Check 'HKLM Run value RMMSession exists' (Test-RunValue) 'Run value missing'

    # 3. Repair must not touch updater-owned slots or state. Stop the service first
    # so the watchdog cannot rewrite them while the hashes are being taken.
    Stop-Service -Name $ServiceName -Force
    $slotDir = Join-Path $DataRoot 'slots\a'
    New-Item -ItemType Directory -Force -Path $slotDir | Out-Null
    $slotExe = Join-Path $slotDir 'rmm-agent.exe'
    $stateJson = Join-Path $DataRoot 'state.json'
    Copy-Item -LiteralPath $BootstrapExe -Destination $slotExe
    $fs = [System.IO.File]::Open($slotExe, 'Append')
    try { $fs.WriteByte(0x5A) } finally { $fs.Dispose() }
    [System.IO.File]::WriteAllText($stateJson, '{"active":"a","marker":"msi-check"}')
    $slotBefore = Get-Hash $slotExe
    $stateBefore = Get-Hash $stateJson
    $log3 = Join-Path $LogDir 'repair.log'
    $code = Invoke-Msi '/fa' $log3 ''
    Check 'repair succeeds' (Test-MsiOk $code) "msiexec exit $code"
    Check 'repair keeps slot binary' ((Get-Hash $slotExe) -eq $slotBefore) 'slots\a\rmm-agent.exe hash changed'
    Check 'repair keeps state.json' ((Get-Hash $stateJson) -eq $stateBefore) 'state.json hash changed'
    Check 'service Running after repair' (Wait-ServiceRunning 30) 'service not Running 30 s after repair'

    # 4. Uninstall removes everything.
    $log4 = Join-Path $LogDir 'uninstall.log'
    $code = Invoke-Msi '/x' $log4 ''
    Check 'uninstall succeeds' (Test-MsiOk $code) "msiexec exit $code"
    $installed = $false
    Check 'uninstall: service gone' ($null -eq (Get-Svc)) 'service still present'
    Check 'uninstall: Program Files\RMM gone' (-not (Test-Path -LiteralPath $ProgFiles)) "$ProgFiles still present"
    Check 'uninstall: ProgramData\RMM gone (slots and state included)' (-not (Test-Path -LiteralPath $DataRoot)) "$DataRoot still present"
    Check 'uninstall: Run value gone' (-not (Test-RunValue)) 'RMMSession Run value still present'
    Write-Host 'ALL CHECKS PASSED'
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    if ($installed) {
        # Best-effort cleanup so a failed run does not leave the machine dirty.
        try { Invoke-Msi '/x' (Join-Path $LogDir 'cleanup.log') '' | Out-Null } catch { }
    }
    exit 1
}
