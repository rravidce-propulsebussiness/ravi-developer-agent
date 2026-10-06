$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".env")) {
  throw "runner/.env is missing. Run .\setup-windows.ps1 first."
}

Get-Content ".env" | ForEach-Object {
  $line = $_.Trim()
  if (-not $line -or $line.StartsWith("#")) { return }
  $parts = $line.Split("=", 2)
  if ($parts.Count -eq 2) {
    [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1], "Process")
  }
}

npm start
