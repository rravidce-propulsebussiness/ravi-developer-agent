$ErrorActionPreference = "SilentlyContinue"
Set-Location $PSScriptRoot
$statePath = Join-Path $PSScriptRoot ".tools\active-session.json"

if (Test-Path $statePath) {
  $state = Get-Content $statePath -Raw | ConvertFrom-Json
  foreach ($pidValue in @($state.runnerPid, $state.tunnelPid)) {
    if ($pidValue) { Stop-Process -Id ([int]$pidValue) -Force -ErrorAction SilentlyContinue }
  }
  Remove-Item $statePath -Force -ErrorAction SilentlyContinue
}
Write-Host "Browser runner and Quick Tunnel stopped."
