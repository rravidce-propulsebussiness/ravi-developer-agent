param(
  [switch]$InstallIfNeeded = $true
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".env")) {
  Write-Host "runner/.env is missing; running setup first..."
  & "$PSScriptRoot\setup-windows.ps1"
}

$toolsDir = Join-Path $PSScriptRoot ".tools"
$cloudflared = Join-Path $toolsDir "cloudflared.exe"
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

if (-not (Test-Path $cloudflared)) {
  if (-not $InstallIfNeeded) { throw "cloudflared.exe is missing." }
  Write-Host "Downloading cloudflared..."
  Invoke-WebRequest -Uri "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" -OutFile $cloudflared
}

$logOut = Join-Path $toolsDir "quick-tunnel.out.log"
$logErr = Join-Path $toolsDir "quick-tunnel.err.log"
Remove-Item $logOut,$logErr -Force -ErrorAction SilentlyContinue

Write-Host "Starting secure Quick Tunnel..."
$tunnel = Start-Process -FilePath $cloudflared -ArgumentList @("tunnel","--url","http://127.0.0.1:8788","--no-autoupdate") -RedirectStandardOutput $logOut -RedirectStandardError $logErr -PassThru -WindowStyle Hidden

$publicUrl = $null
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  $raw = ""
  if (Test-Path $logOut) { $raw += Get-Content $logOut -Raw -ErrorAction SilentlyContinue }
  if (Test-Path $logErr) { $raw += Get-Content $logErr -Raw -ErrorAction SilentlyContinue }
  $match = [regex]::Match($raw, 'https://[a-z0-9-]+\.trycloudflare\.com')
  if ($match.Success) { $publicUrl = $match.Value; break }
  if ($tunnel.HasExited) { throw "cloudflared exited before producing a Quick Tunnel URL." }
}

if (-not $publicUrl) {
  Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue
  throw "Timed out waiting for a Quick Tunnel URL."
}

$envPath = Join-Path $PSScriptRoot ".env"
$lines = Get-Content $envPath
$found = $false
$updated = foreach ($line in $lines) {
  if ($line -match '^PUBLIC_BASE_URL=') {
    $found = $true
    "PUBLIC_BASE_URL=$publicUrl"
  } else {
    $line
  }
}
if (-not $found) { $updated += "PUBLIC_BASE_URL=$publicUrl" }
$updated | Set-Content -Encoding UTF8 $envPath

Write-Host ""
Write-Host "Quick Tunnel ready:"
Write-Host "  $publicUrl"
Write-Host ""
Write-Host "Starting Chromium runner..."

Get-Content $envPath | ForEach-Object {
  $line = $_.Trim()
  if (-not $line -or $line.StartsWith("#")) { return }
  $parts = $line.Split("=", 2)
  if ($parts.Count -eq 2) { [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1], "Process") }
}

$runner = Start-Process -FilePath "npm.cmd" -ArgumentList @("start") -WorkingDirectory $PSScriptRoot -PassThru

@{
  publicUrl = $publicUrl
  tunnelPid = $tunnel.Id
  runnerPid = $runner.Id
  startedAt = (Get-Date).ToString("o")
} | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $toolsDir "active-session.json")

Write-Host ""
Write-Host "Runner PID: $($runner.Id)"
Write-Host "Tunnel PID: $($tunnel.Id)"
Write-Host "The browser runner is now reachable over HTTPS."
Write-Host ""
Write-Host "Next, in a second PowerShell window run:"
Write-Host "  .\connect-worker-windows.ps1"
