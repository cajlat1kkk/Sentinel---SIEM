param(
    [Parameter(Mandatory=$true)][ValidateSet('agent','server')][string]$Role,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$BinaryDirectory = "$env:ProgramFiles\Sentinel SIEM\bin"
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated PowerShell after installing the machine-wide EXE package.' }
$binary = Join-Path $BinaryDirectory "siem-$Role.exe"
if (-not (Test-Path $binary)) { throw "Missing installed binary: $binary" }
$resolved = (Resolve-Path $binary).Path
if (-not $resolved.StartsWith($env:ProgramFiles + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Service binaries must be installed under Program Files, never in a user-writable directory.' }
$serviceName = if ($Role -eq 'agent') { 'SentinelAgent' } else { 'SentinelServer' }
$directory = Join-Path $env:ProgramData "Sentinel\$Role"
New-Item -ItemType Directory -Force $directory | Out-Null
& icacls.exe $directory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict configuration directory ACL' }
$config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
$identity = if ($Role -eq 'agent') { $config.server } else { $config }
$identityDir = Join-Path $directory ([guid]::NewGuid().ToString())
New-Item -ItemType Directory $identityDir | Out-Null
foreach ($field in @('ca','certificate','private_key')) {
    $destination = Join-Path $identityDir "$field.pem"
    Copy-Item -LiteralPath $identity.$field -Destination $destination
    $identity.$field = $destination
}
if ($Role -eq 'agent') {
    $config.state_dir = Join-Path $directory 'state'
    $token = Join-Path $identityDir 'enrollment.token'
    Copy-Item -LiteralPath $config.enrollment_token_file -Destination $token
    $config.enrollment_token_file = $token
} elseif ($config.database.password_file) {
    $passwordFile = Join-Path $identityDir 'postgres-password'
    Copy-Item -LiteralPath $config.database.password_file -Destination $passwordFile
    $config.database.password_file = $passwordFile
}
$candidate = Join-Path $identityDir "$Role.json"
$config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $candidate -Encoding utf8
& $binary --config $candidate --check-config
if ($LASTEXITCODE -ne 0) { throw 'Configuration validation failed; existing service was not changed' }
$command = '"{0}" --service --config "{1}"' -f $resolved,$candidate
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $serviceName
    & sc.exe config $serviceName binPath= $command start= auto
    if ($LASTEXITCODE -ne 0) { throw 'Cannot update Windows service' }
} else {
    New-Service -Name $serviceName -DisplayName "Sentinel $Role" -BinaryPathName $command -StartupType Automatic | Out-Null
}
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/60000
if ($LASTEXITCODE -ne 0) { throw 'Cannot configure service recovery' }
Start-Service -Name $serviceName
Get-Service -Name $serviceName
