param(
  [Parameter(Mandatory=$false)]
  [string]$PublicBaseUrl = "https://browser.example.com"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js 24+ is required. Install Node.js, then run this script again."
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  throw "npm is required."
}

if (-not (Test-Path ".env")) {
  $bytes = New-Object byte[] 48
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($bytes)
  } finally {
    $rng.Dispose()
  }
  $token = [Convert]::ToBase64String($bytes).Replace("+","-").Replace("/","_").TrimEnd("=")
  @"
RUNNER_TOKEN=$token
RUNNER_HOST=127.0.0.1
RUNNER_PORT=8788
PUBLIC_BASE_URL=$PublicBaseUrl
CHROME_PATH=
HEADLESS=false
MAX_SESSIONS=8
SESSION_IDLE_MS=1800000
BROWSER_PROFILE_DIR=.browser-profiles
"@ | Set-Content -Encoding UTF8 ".env"
  Write-Host "Created runner/.env with a random RUNNER_TOKEN."
} else {
  Write-Host "runner/.env already exists; leaving it unchanged."
}

& npm.cmd install
& npx.cmd playwright install chromium

Write-Host ""
Write-Host "Self-hosted browser runner is installed."
Write-Host "Edit PUBLIC_BASE_URL in runner/.env if needed, then run:"
Write-Host "  .\start-windows.ps1"
Write-Host ""
Write-Host "Optional secure browser secret alias:"
Write-Host "  .\set-browser-secret-windows.ps1 -Name HOSTINGER_PASSWORD"
