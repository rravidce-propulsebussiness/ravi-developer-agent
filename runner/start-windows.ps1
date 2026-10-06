$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".env")) {
  throw "runner/.env is missing. Run .\setup-windows.ps1 first."
}

Get-Content ".env" | ForEach-Object {
  $rawLine = [string]$_
  $line = $rawLine.Trim()
  if (-not $line -or $line.StartsWith("#")) { return }
  $parts = $rawLine.Split("=", 2)
  if ($parts.Count -eq 2) {
    [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1], "Process")
  }
}

if (-not $env:BROWSER_PROFILE_DIR) {
  $env:BROWSER_PROFILE_DIR = Join-Path $PSScriptRoot ".browser-profiles"
}

npm start
