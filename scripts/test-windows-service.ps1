$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This disposable-machine test may only run inside GitHub Actions.' }
if (Get-Service SentinelAgent -ErrorAction SilentlyContinue) { throw 'Refusing to replace an existing endpoint agent' }
$project = Split-Path $PSScriptRoot -Parent
$work = Join-Path $env:RUNNER_TEMP ('sentinel-service-' + [guid]::NewGuid().ToString())
$runtime = Join-Path $env:ProgramFiles 'Sentinel SIEM Service Test'
$openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
if (-not (Test-Path $openssl)) { throw 'OpenSSL from Git for Windows is required for ephemeral test certificates' }
New-Item -ItemType Directory -Force $work | Out-Null
try {
    cmake --install "$project\build-windows" --prefix $runtime
    if ($LASTEXITCODE -ne 0) { throw 'Runtime deployment failed' }
    $key = Join-Path $work 'agent.key'
    $cert = Join-Path $work 'agent.crt'
    & $openssl req -x509 -newkey rsa:2048 -nodes -keyout $key -out $cert -subj '/CN=Sentinel service test' -days 1
    if ($LASTEXITCODE -ne 0) { throw 'Test certificate generation failed' }
    $token = Join-Path $work 'enrollment.token'
    (([guid]::NewGuid().ToString('N')) + ([guid]::NewGuid().ToString('N'))) | Set-Content $token -NoNewline
    $config = Join-Path $work 'agent.json'
    @{
        server = @{ host='localhost'; port=65534; ca=$cert; certificate=$cert; private_key=$key }
        state_dir = (Join-Path $work 'state'); enrollment_token_file=$token
        collect_system=$false; manage_firewall=$false; syslog_port=0; scan_roots=@()
    } | ConvertTo-Json -Depth 10 | Set-Content $config -Encoding utf8
    & "$project\packaging\windows\install-service.ps1" -Role agent -ConfigPath $config -BinaryDirectory (Join-Path $runtime 'bin')
    Start-Sleep -Seconds 2
    if ((Get-Service SentinelAgent).Status -ne 'Running') { throw 'Agent did not remain running without a GUI/server' }
    Restart-Service SentinelAgent
    Start-Sleep -Seconds 2
    if ((Get-Service SentinelAgent).Status -ne 'Running') { throw 'Agent did not restart' }
    Stop-Service SentinelAgent
    if ((Get-Service SentinelAgent).Status -ne 'Stopped') { throw 'Agent did not stop cleanly' }
    Write-Output 'PASS: actual Windows SCM installation, background operation, restart and stop'
} finally {
    $service = Get-Service SentinelAgent -ErrorAction SilentlyContinue
    if ($service) { Stop-Service SentinelAgent -ErrorAction SilentlyContinue; & sc.exe delete SentinelAgent | Out-Null }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $runtime -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'Sentinel\agent') -ErrorAction SilentlyContinue
}
