$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$envPath = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envPath)) { throw "runner/.env is missing." }

$values = @{}
Get-Content $envPath | ForEach-Object {
  $line = $_.Trim()
  if (-not $line -or $line.StartsWith("#")) { return }
  $parts = $line.Split("=", 2)
  if ($parts.Count -eq 2) { $values[$parts[0].Trim()] = $parts[1] }
}

$url = [string]$values["PUBLIC_BASE_URL"]
$token = [string]$values["RUNNER_TOKEN"]
if (-not $url.StartsWith("https://")) { throw "PUBLIC_BASE_URL must be an HTTPS URL." }
if ($token.Length -lt 32) { throw "RUNNER_TOKEN is invalid." }

$repoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repoRoot
try {
  Write-Host "Checking Cloudflare CLI login..."
  & npx.cmd wrangler whoami *> $null
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Cloudflare authorization is required. A browser window will open."
    & npx.cmd wrangler login
    if ($LASTEXITCODE -ne 0) { throw "Cloudflare login failed." }
  }

  Write-Host "Updating Worker runner URL..."
  $url | & npx.cmd wrangler secret put SELF_HOSTED_BROWSER_URL --name ravi-developer-agent
  if ($LASTEXITCODE -ne 0) { throw "Failed to set SELF_HOSTED_BROWSER_URL." }

  Write-Host "Updating Worker runner token securely..."
  $token | & npx.cmd wrangler secret put SELF_HOSTED_BROWSER_TOKEN --name ravi-developer-agent
  if ($LASTEXITCODE -ne 0) { throw "Failed to set SELF_HOSTED_BROWSER_TOKEN." }

  Write-Host ""
  Write-Host "Worker connection settings updated."
  Write-Host "Runner URL: $url"
  Write-Host "The runner token was not printed."
} finally {
  Pop-Location
}
